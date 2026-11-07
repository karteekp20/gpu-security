package scan

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

// classifyTLSError turns a crypto/x509 verification error into one of five
// strings that reach the report, RG-TLS-001's detail line, and the Rego
// sentinel. Two things make that mapping worth pinning with a test rather
// than reading off the code:
//
//   - Which error type x509 returns for a given certificate is not stable
//     across Go releases. Go has tightened verification repeatedly - the
//     CommonName fallback was dropped, SHA-1 signatures were rejected, name
//     constraints were enforced - and each change can move a certificate from
//     one of our classes to another without a line of our code changing.
//   - This repository builds locally on a toolchain older than the one that
//     ships (decision row 2026-11-07: go1.20.5 here, go1.27.3 in the release).
//     So "the TLS tests pass" has meant "they pass against whichever standard
//     library is installed on this laptop". These tests are what make the
//     claim about the stdlib that ships, because CI runs them on that one.
//
// Before this file, `not-yet-valid` and `hostname-mismatch` had no test at
// all - two of the five strings the classifier can emit were never asserted
// anywhere, in a product whose output is the artifact a buyer acts on.

// leafValidFor returns a certificate whose validity window is the one the
// caller asks for. Only NotBefore/NotAfter matter to the classifier's first
// two cases, which is why this is deliberately not a full chain.
func leafValidFor(t *testing.T, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()
	return &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ray.example.invalid"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
}

// TestClassifyTLSErrorCoversEveryIssueClass pins the whole mapping. The table
// is exhaustive on purpose: the five strings here are the five values
// `tls.issue` is documented to take (internal/domain/types.go, and the
// policies/README input contract), so a sixth string appearing in a report
// would be a contract break that nothing else catches.
func TestClassifyTLSErrorCoversEveryIssueClass(t *testing.T) {
	now := time.Now()
	inWindow := leafValidFor(t, now.Add(-24*time.Hour), now.Add(24*time.Hour))
	expiredLeaf := leafValidFor(t, now.Add(-48*time.Hour), now.Add(-time.Hour))

	for _, tc := range []struct {
		name string
		leaf *x509.Certificate
		err  error
		want string
		why  string
	}{
		{
			name: "expired leaf wins over whatever x509 said",
			leaf: expiredLeaf,
			err:  x509.UnknownAuthorityError{},
			want: "expired",
			why: "an operator can fix an expired certificate without us; " +
				"telling them it is untrusted sends them to the wrong place",
		},
		{
			name: "not yet valid",
			leaf: leafValidFor(t, now.Add(time.Hour), now.Add(48*time.Hour)),
			err:  x509.UnknownAuthorityError{},
			want: "not-yet-valid",
			why:  "a clock-skew or staged-rotation case, not a trust problem",
		},
		{
			// This case exists because of a mutation that got through. The
			// table looked exhaustive while every row carried only one
			// defect, so moving the hostname check above the validity
			// switch changed nothing and no test failed. Order is a
			// decision here, not an accident: an expired certificate with
			// the wrong name is both things at once, and the classifier
			// deliberately reports the one the operator can fix without us.
			name: "expired and wrong name both apply; expiry is reported",
			leaf: expiredLeaf,
			err:  x509.HostnameError{Certificate: expiredLeaf, Host: "10.0.0.5"},
			want: "expired",
			why: "this row is what pins the ordering; without it the two " +
				"branches can be swapped with the suite still green",
		},
		{
			name: "hostname mismatch",
			leaf: inWindow,
			err:  x509.HostnameError{Certificate: inWindow, Host: "10.0.0.5"},
			want: "hostname-mismatch",
			why: "a valid certificate for the wrong name: real, common, and " +
				"had no test before this file",
		},
		{
			name: "unknown authority reads as self-signed",
			leaf: inWindow,
			err:  x509.UnknownAuthorityError{Cert: inWindow},
			want: "self-signed",
			why: "the overwhelmingly common cause in a GPU cluster, and the " +
				"word an operator recognises",
		},
		{
			name: "chain expired above the leaf",
			leaf: inWindow,
			err:  x509.CertificateInvalidError{Cert: inWindow, Reason: x509.Expired},
			want: "expired",
			why: "the leaf is in window but something above it is not; still " +
				"an expiry for the person who has to fix it",
		},
		{
			name: "anything else is untrusted, never empty",
			leaf: inWindow,
			err: x509.CertificateInvalidError{Cert: inWindow,
				Reason: x509.NameConstraintsWithoutSANs},
			want: "untrusted",
			why: "the fallback must still be a non-empty issue, because the " +
				"rules test issue != \"\" - an empty string would close the finding",
		},
		{
			name: "an opaque error is still untrusted",
			leaf: inWindow,
			err:  errors.New("some future verification failure"),
			want: "untrusted",
			why: "a Go release that introduces a new error type must not " +
				"silently produce a clean certificate",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyTLSError(tc.err, tc.leaf)
			if got != tc.want {
				t.Errorf("classifyTLSError = %q, want %q (%s)", got, tc.want, tc.why)
			}
			if got == "" {
				t.Error("an empty issue would read as a valid certificate and " +
					"would satisfy the Rego closure for RG-TLS-001")
			}
		})
	}
}

// TestClassifyTLSErrorNeverReturnsEmpty is the property behind the table. The
// hazard is specific: policies/cloud rules test `tls.issue != ""`, so an
// empty string does not merely lose information - it closes the finding and
// would let a verification sentinel attest a certificate we could not verify.
func TestClassifyTLSErrorNeverReturnsEmpty(t *testing.T) {
	now := time.Now()
	leaves := []*x509.Certificate{
		leafValidFor(t, now.Add(-time.Hour), now.Add(time.Hour)),
		leafValidFor(t, now.Add(-48*time.Hour), now.Add(-time.Hour)),
		leafValidFor(t, now.Add(time.Hour), now.Add(48*time.Hour)),
	}
	errs := []error{
		errors.New(""),
		x509.UnknownAuthorityError{},
		x509.HostnameError{},
		x509.CertificateInvalidError{},
		x509.SystemRootsError{},
	}
	for _, leaf := range leaves {
		for _, err := range errs {
			if got := classifyTLSError(err, leaf); got == "" {
				t.Errorf("empty issue for leaf %v / err %T", leaf.NotAfter, err)
			}
		}
	}
}

// serveTLSWithCert starts a TLS listener presenting exactly the certificate
// described by the given validity window, self-signed, with the loopback
// address in its SANs so the only defect is the one under test.
func serveTLSWithCert(t *testing.T, notBefore, notAfter time.Time) (string, int) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	srv.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	host, portStr, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)
	return host, port
}

// TestTLSProbeClassifiesRealExpiredAndNotYetValidCerts runs the table's two
// clock cases through the actual handshake and the actual x509.Verify, rather
// than through a synthesized error. That is the half a unit test cannot
// cover: it proves the installed standard library really does hand us a
// verification failure for these certificates, and that the date we print
// comes from the certificate we were served.
func TestTLSProbeClassifiesRealExpiredAndNotYetValidCerts(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		name                string
		notBefore, notAfter time.Time
		want                string
	}{
		{"expired", now.Add(-72 * time.Hour), now.Add(-24 * time.Hour), "expired"},
		{"not yet valid", now.Add(24 * time.Hour), now.Add(72 * time.Hour), "not-yet-valid"},
		{"in window but self-signed", now.Add(-time.Hour), now.Add(72 * time.Hour), "self-signed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host, port := serveTLSWithCert(t, tc.notBefore, tc.notAfter)
			s := NewWithChecks(3*time.Second, nil)
			state, failed := s.tlsProbe(context.Background(), target{host, host}, port)
			if failed {
				t.Fatal("the probe reported a local resource failure, not a posture")
			}
			if !state.Enabled {
				t.Fatal("TLS was not detected on a TLS listener")
			}
			if state.Issue != tc.want {
				t.Errorf("issue = %q, want %q", state.Issue, tc.want)
			}
			if want := tc.notAfter.UTC().Format("2006-01-02"); state.NotAfter != want {
				t.Errorf("NotAfter = %q, want %q (the served certificate's own date)",
					state.NotAfter, want)
			}
		})
	}
}
