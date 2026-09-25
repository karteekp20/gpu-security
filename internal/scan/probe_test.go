package scan

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"gpusecurity/internal/domain"
)

// serve starts a local HTTP server and returns its host and port.
func serve(t *testing.T, h http.HandlerFunc) (string, int) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	host, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("splitting test server address: %v", err)
	}
	port, _ := strconv.Atoi(portStr)
	return host, port
}

func probeOne(t *testing.T, host string, checks []Check) []domain.Observation {
	t.Helper()
	s := NewWithChecks(2*time.Second, checks)
	return s.ProbeHost(context.Background(), host).Observations
}

func TestProbeIdentifiesUnauthenticatedService(t *testing.T) {
	host, port := serve(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	obs := probeOne(t, host, []Check{{"ray-dashboard", port, "http", "/"}})
	if len(obs) != 1 {
		t.Fatalf("expected 1 observation, got %+v", obs)
	}
	if !obs[0].Unauth || obs[0].Service != "ray-dashboard" || obs[0].State != domain.PortOpen {
		t.Errorf("expected an open, unauthenticated ray-dashboard, got %+v", obs[0])
	}
}

func TestProbeRecordsAuthRequired(t *testing.T) {
	host, port := serve(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	obs := probeOne(t, host, []Check{{"vllm", port, "http", "/v1/models"}})
	if len(obs) != 1 {
		t.Fatalf("expected 1 observation, got %+v", obs)
	}
	if obs[0].Unauth {
		t.Errorf("a 401 must not be reported as unauthenticated exposure: %+v", obs[0])
	}
	if obs[0].Note == "" {
		t.Errorf("expected an auth-required note, got %+v", obs[0])
	}
}

// Both vLLM and Triton default to port 8000. Only the service that actually
// answers 2xx on its own health path should be attributed.
func TestProbeDisambiguatesSharedPort(t *testing.T) {
	host, port := serve(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/models" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	obs := probeOne(t, host, []Check{
		{"vllm", port, "http", "/v1/models"},
		{"triton", port, "http", "/v2/health/ready"},
	})
	if len(obs) != 1 {
		t.Fatalf("expected exactly one attributed service, got %+v", obs)
	}
	if obs[0].Service != "vllm" {
		t.Errorf("expected vllm to be attributed, got %q", obs[0].Service)
	}
}

func TestProbeReportsUnidentifiedOpenPort(t *testing.T) {
	host, port := serve(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	obs := probeOne(t, host, []Check{{"triton", port, "http", "/v2/health/ready"}})
	if len(obs) != 1 || obs[0].Service != ServiceUnknown {
		t.Fatalf("expected an unidentified-service observation, got %+v", obs)
	}
}

func TestProbeClosedPortYieldsNoObservation(t *testing.T) {
	// Bind and immediately release a port so we know nothing is listening.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, portStr, _ := net.SplitHostPort(l.Addr().String())
	port, _ := strconv.Atoi(portStr)
	l.Close()

	obs := probeOne(t, "127.0.0.1", []Check{{"ray-dashboard", port, "http", "/"}})
	if len(obs) != 0 {
		t.Fatalf("a closed port must produce no observation, got %+v", obs)
	}
}

func TestProbeTCPOnlyCheck(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	_, portStr, _ := net.SplitHostPort(l.Addr().String())
	port, _ := strconv.Atoi(portStr)

	obs := probeOne(t, "127.0.0.1", []Check{{"slurmctld", port, "tcp", ""}})
	if len(obs) != 1 || obs[0].Service != "slurmctld" || obs[0].HTTPStatus != 0 {
		t.Fatalf("expected a reachability-only slurmctld observation, got %+v", obs)
	}
}

// httptest's TLS server presents a certificate from an untrusted CA, which
// is exactly the "self-signed" case operators hit in real clusters.
func TestTLSProbeClassifiesUntrustedCertificate(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	host, portStr, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	s := NewWithChecks(3*time.Second, nil)
	state := s.tlsProbe(context.Background(), host, port)
	if !state.Enabled {
		t.Fatal("expected TLS to be detected")
	}
	if state.Issue == "" {
		t.Error("an untrusted certificate should be reported as an issue, not silently accepted")
	}
	if state.NotAfter == "" || len(state.NotAfter) != len("2006-01-02") {
		t.Errorf("expected a date-only expiry, got %q", state.NotAfter)
	}
}

// The TLS state carries no certificate identity - only posture facts (P3).
func TestTLSProbeRecordsNoCertificateIdentity(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	host, portStr, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	state := NewWithChecks(3*time.Second, nil).tlsProbe(context.Background(), host, port)
	for _, leaked := range []string{"CN=", "O=", "Acme"} {
		if strings.Contains(state.Issue+state.NotAfter, leaked) {
			t.Errorf("TLS state leaked certificate identity (%q)", leaked)
		}
	}
}

// Regression: a server that accepts the connection and then waits silently
// for a complete HTTP request - real Jupyter and MLflow both do this - used
// to burn the entire probe timeout before we concluded "not TLS". Every such
// port on a cluster paid that cost. The handshake must be bounded separately.
func TestTLSProbeGivesUpQuicklyOnAcceptAndHang(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			// Hold the connection open, say nothing - the pathological case.
			go func() { <-done; c.Close() }()
		}
	}()
	_, portStr, _ := net.SplitHostPort(l.Addr().String())
	port, _ := strconv.Atoi(portStr)

	const probeTimeout = 8 * time.Second
	s := NewWithChecks(probeTimeout, nil)

	start := time.Now()
	state := s.tlsProbe(context.Background(), "127.0.0.1", port)
	elapsed := time.Since(start)

	if state.Enabled {
		t.Errorf("a silent TCP listener is not a TLS service: %+v", state)
	}
	if elapsed >= probeTimeout {
		t.Errorf("the TLS handshake consumed the whole probe timeout (%v); it must be bounded separately", elapsed)
	}
	if max := s.handshakeTimeout() * 2; elapsed > max {
		t.Errorf("handshake took %v, expected it bounded near %v", elapsed, s.handshakeTimeout())
	}
}

func TestHandshakeTimeoutIsClamped(t *testing.T) {
	cases := []struct {
		probe time.Duration
		want  time.Duration
	}{
		{500 * time.Millisecond, 500 * time.Millisecond}, // never exceed the caller's timeout
		{2 * time.Second, time.Second},                   // floor
		{4 * time.Second, 2 * time.Second},               // default: half
		{30 * time.Second, 3 * time.Second},              // ceiling
	}
	for _, tc := range cases {
		if got := NewWithChecks(tc.probe, nil).handshakeTimeout(); got != tc.want {
			t.Errorf("probe timeout %v: want handshake %v, got %v", tc.probe, tc.want, got)
		}
	}
}

func TestTLSProbeOnPlaintextPort(t *testing.T) {
	host, port := serve(t, func(w http.ResponseWriter, r *http.Request) {})
	state := NewWithChecks(2*time.Second, nil).tlsProbe(context.Background(), host, port)
	if state.Enabled {
		t.Errorf("a plaintext HTTP port must not be reported as TLS-enabled: %+v", state)
	}
}

// A TLS service still gets probed: an unauthenticated API behind a bad
// certificate is exposed twice over, and must not be skipped.
func TestProbeReachesServiceBehindUntrustedTLS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	host, portStr, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	obs := probeOne(t, host, []Check{{"ray-dashboard", port, "http", "/"}})

	var sawService, sawTLSIssue bool
	for _, o := range obs {
		if o.Service == "ray-dashboard" && o.Unauth {
			sawService = true
		}
		if o.Service == ServiceTLS && o.TLS.Issue != "" {
			sawTLSIssue = true
		}
	}
	if !sawService {
		t.Error("the unauthenticated service behind TLS was missed")
	}
	if !sawTLSIssue {
		t.Error("the certificate problem was not reported")
	}
}

func TestProbeBucketDetectsPublicListing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	o, err := New(3*time.Second).ProbeBucket(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !o.Unauth || o.Service != ServiceBucket {
		t.Errorf("expected a public bucket observation, got %+v", o)
	}
}

func TestProbeBucketPrivateAndUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	s := New(1 * time.Second)
	o, err := s.ProbeBucket(context.Background(), srv.URL)
	if err != nil || o.Unauth {
		t.Errorf("a 403 bucket is not public: %+v (err %v)", o, err)
	}

	// An unreachable endpoint is reported, not treated as an error.
	o, err = s.ProbeBucket(context.Background(), "http://127.0.0.1:1/bucket")
	if err != nil {
		t.Errorf("an unreachable bucket should not fail the scan: %v", err)
	}
	if o.Unauth || o.Note == "" {
		t.Errorf("expected an unreachable note, got %+v", o)
	}
}

func TestProbeBucketAddsSchemeAndRejectsGarbage(t *testing.T) {
	s := New(1 * time.Second)
	if _, err := s.ProbeBucket(context.Background(), "://nonsense"); err == nil {
		t.Error("expected an error for a malformed bucket URL")
	}
	// A bare host is accepted and assumed https.
	o, err := s.ProbeBucket(context.Background(), "127.0.0.1:1")
	if err != nil {
		t.Errorf("a bare host:port should be accepted: %v", err)
	}
	if !o.TLS.Enabled {
		t.Error("a bucket URL without a scheme should default to https")
	}
}

// ---------------------------------------------------------------------------
// Host reachability - the difference between "nothing here" and "no idea"
// ---------------------------------------------------------------------------

// A name that does not resolve must be reported as such. Before this existed,
// a typo'd hostname produced an empty finding list that graded A+, which is
// the worst thing a security scanner can say.
func TestUnresolvableHostIsReportedNotSilentlyClean(t *testing.T) {
	s := NewWithChecks(2*time.Second, DefaultChecks())
	got := s.ProbeHost(context.Background(), "ray-guard-nonexistent-host.invalid")

	if got.State != domain.HostUnresolved {
		t.Errorf("want %s, got %s", domain.HostUnresolved, got.State)
	}
	if len(got.Observations) != 0 {
		t.Errorf("an unresolvable host yields no observations, got %+v", got.Observations)
	}
}

// A host that refuses connections is alive, and an empty result from it is
// real evidence of a clean host.
func TestRefusingHostCountsAsResponded(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, portStr, _ := net.SplitHostPort(l.Addr().String())
	port, _ := strconv.Atoi(portStr)
	l.Close() // nothing listening now, so connects are refused

	s := NewWithChecks(2*time.Second, []Check{{"ray-dashboard", port, "http", "/"}})
	got := s.ProbeHost(context.Background(), "127.0.0.1")

	if got.State != domain.HostResponded {
		t.Errorf("a refused connection is an answer; want %s, got %s", domain.HostResponded, got.State)
	}
	if len(got.Observations) != 0 {
		t.Errorf("nothing is listening, so there should be no observations: %+v", got.Observations)
	}
}

func TestRespondingHostWithAnOpenPort(t *testing.T) {
	host, port := serve(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	got := NewWithChecks(2*time.Second, []Check{{"ray-dashboard", port, "http", "/"}}).
		ProbeHost(context.Background(), host)

	if got.State != domain.HostResponded {
		t.Errorf("want %s, got %s", domain.HostResponded, got.State)
	}
	if got.Summary().Host != host || got.Summary().State != domain.HostResponded {
		t.Errorf("summary does not match the scan: %+v", got.Summary())
	}
}

// An address that silently drops packets cannot be distinguished from a
// firewalled host, and must not be reported as either clean or exposed.
func TestSilentHostIsNoResponse(t *testing.T) {
	// TEST-NET-2, reserved for documentation - nothing answers.
	s := NewWithChecks(600*time.Millisecond, []Check{{"ray-dashboard", 8265, "http", "/"}})
	got := s.ProbeHost(context.Background(), "198.51.100.1")

	if got.State == domain.HostResponded {
		t.Errorf("a dark address must not count as responded: %+v", got)
	}
	if len(got.Observations) != 0 {
		t.Errorf("expected no observations from a dark address, got %+v", got.Observations)
	}
}

func TestIPLiteralsSkipResolution(t *testing.T) {
	s := NewWithChecks(time.Second, nil)
	for _, ip := range []string{"127.0.0.1", "::1", "10.1.2.3"} {
		if !s.resolves(context.Background(), ip) {
			t.Errorf("%s is an IP literal and must always resolve", ip)
		}
	}
	if s.resolves(context.Background(), "ray-guard-nonexistent-host.invalid") {
		t.Error("a .invalid name must not resolve")
	}
}

func TestPortStateDistinguishesClosedFromFiltered(t *testing.T) {
	s := NewWithChecks(300*time.Millisecond, nil)
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	_, portStr, _ := net.SplitHostPort(l.Addr().String())
	port, _ := strconv.Atoi(portStr)
	l.Close()

	if got := s.portState(context.Background(), "127.0.0.1", port); got != domain.PortClosed {
		t.Errorf("loopback with nothing listening should be closed, got %s", got)
	}

	// 198.51.100.0/24 is TEST-NET-2: reserved for documentation, so packets
	// are dropped rather than refused.
	if got := s.portState(context.Background(), "198.51.100.1", 8265); got != domain.PortFiltered {
		t.Logf("TEST-NET-2 returned %s (network-dependent; not asserted)", got)
	}
}
