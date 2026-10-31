package scan

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"gpusecurity/internal/domain"
)

// discriminating wraps a handler so it 404s the wildcard control path, which
// is what every real service in the integration stack does - Ray, Jupyter,
// MLflow, Ollama and TorchServe were all checked. Blanket-200 handlers are
// not a faithful stand-in for a service: they are a captive portal, and
// ProbeHost now refuses to attribute those. TestProbeRefusesToNameAWildcard
// covers that case deliberately.
func discriminating(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == controlPath {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		h(w, r)
	}
}

// serve starts a local HTTP server and returns its host and port.
func serve(t *testing.T, h http.HandlerFunc) (string, int) {
	t.Helper()
	srv := httptest.NewServer(discriminating(h))
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
	_ = l.Close()

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
	defer func() { _ = l.Close() }()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
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
	state, _ := s.tlsProbe(context.Background(), target{host, host}, port)
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

	state, _ := NewWithChecks(3*time.Second, nil).tlsProbe(context.Background(), target{host, host}, port)
	// Version is included here on purpose: it is the newest field on TLSState,
	// and every field that crosses the boundary has to be checkable as posture
	// rather than identity.
	switch state.Version {
	case "1.0", "1.1", "1.2", "1.3", "":
	default:
		t.Errorf("TLS version recorded as %q, which is not a protocol version", state.Version)
	}
	for _, leaked := range []string{"CN=", "O=", "Acme"} {
		if strings.Contains(state.Issue+state.NotAfter+state.Version, leaked) {
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
	defer func() { _ = l.Close() }()
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			// Hold the connection open, say nothing - the pathological case.
			go func() { <-done; _ = c.Close() }()
		}
	}()
	_, portStr, _ := net.SplitHostPort(l.Addr().String())
	port, _ := strconv.Atoi(portStr)

	const probeTimeout = 8 * time.Second
	s := NewWithChecks(probeTimeout, nil)

	start := time.Now()
	state, _ := s.tlsProbe(context.Background(), target{"127.0.0.1", "127.0.0.1"}, port)
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
	state, _ := NewWithChecks(2*time.Second, nil).tlsProbe(context.Background(), target{host, host}, port)
	if state.Enabled {
		t.Errorf("a plaintext HTTP port must not be reported as TLS-enabled: %+v", state)
	}
}

// A TLS service still gets probed: an unauthenticated API behind a bad
// certificate is exposed twice over, and must not be skipped.
func TestProbeReachesServiceBehindUntrustedTLS(t *testing.T) {
	srv := httptest.NewTLSServer(discriminating(func(w http.ResponseWriter, r *http.Request) {
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
	_ = l.Close() // nothing listening now, so connects are refused

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
		tgt, n, ok := s.resolve(context.Background(), ip)
		if !ok {
			t.Errorf("%s is an IP literal and must always resolve", ip)
		}
		if tgt.addr != ip || tgt.pinned() {
			t.Errorf("%s resolved to %+v; an address is its own target and needs no pinning", ip, tgt)
		}
		if n != 1 {
			t.Errorf("%s reported %d addresses, want 1", ip, n)
		}
	}
	if _, _, ok := s.resolve(context.Background(), "ray-guard-nonexistent-host.invalid"); ok {
		t.Error("a .invalid name must not resolve")
	}
}

func TestPortStateDistinguishesClosedFromFiltered(t *testing.T) {
	s := NewWithChecks(300*time.Millisecond, nil)
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	_, portStr, _ := net.SplitHostPort(l.Addr().String())
	port, _ := strconv.Atoi(portStr)
	_ = l.Close()

	got, failed := s.portState(context.Background(), target{"127.0.0.1", "127.0.0.1"}, port)
	if got != domain.PortClosed {
		t.Errorf("loopback with nothing listening should be closed, got %s", got)
	}
	if failed {
		t.Error("a refused connection was reported as a local probe failure")
	}

	// 198.51.100.0/24 is TEST-NET-2: reserved for documentation, so packets
	// are dropped rather than refused.
	if got, failed := s.portState(context.Background(), target{"198.51.100.1", "198.51.100.1"}, 8265); got != domain.PortFiltered {
		t.Logf("TEST-NET-2 returned %s (failed=%v; network-dependent, not asserted)", got, failed)
	}
}

// TestLocalResourceErrorsAreNotPortStates is the classifier behind the
// difference between "the host told us something" and "we ran out of
// descriptors". Getting this wrong is not a cosmetic bug: it is how a scan
// silently under-reports, because every local failure then looks like a
// filtered port on a quiet host.
func TestLocalResourceErrorsAreNotPortStates(t *testing.T) {
	local := []error{syscall.EMFILE, syscall.ENFILE, syscall.ENOBUFS, syscall.EADDRNOTAVAIL}
	for _, err := range local {
		if !localResourceError(err) {
			t.Errorf("%v should be recognized as a local resource failure", err)
		}
		// The real error arrives wrapped in *net.OpError, several layers deep.
		wrapped := &net.OpError{Op: "dial", Net: "tcp", Err: &os.SyscallError{Syscall: "socket", Err: err}}
		if !localResourceError(wrapped) {
			t.Errorf("%v wrapped in *net.OpError should still be recognized", err)
		}
	}
	remote := []error{syscall.ECONNREFUSED, syscall.ETIMEDOUT, syscall.EHOSTUNREACH, syscall.ENETUNREACH,
		context.Canceled, context.DeadlineExceeded}
	for _, err := range remote {
		if localResourceError(err) {
			t.Errorf("%v is a fact about the target or the scan, not a local resource limit", err)
		}
	}
}

// TestMaxHostConcurrencyLeavesHeadroom: the clamp has to be derived from the
// real limit, leave room for the descriptors that are not probe sockets, and
// never return zero - a scan that probes nothing is not a safe fallback.
func TestMaxHostConcurrencyLeavesHeadroom(t *testing.T) {
	var rl syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rl); err != nil {
		t.Skip("cannot read RLIMIT_NOFILE here")
	}
	checks := DefaultChecks()
	got := MaxHostConcurrency(checks)
	if got < 1 {
		t.Fatalf("MaxHostConcurrency = %d, want at least 1", got)
	}
	ports := map[int]bool{}
	for _, c := range checks {
		ports[c.Port] = true
	}
	if used := got * len(ports) * fdsPerHost; uint64(used) > rl.Cur {
		t.Errorf("clamp allows %d descriptors against a limit of %d", used, rl.Cur)
	}
	// Fewer ports to probe means more hosts fit; the formula must track that.
	one := MaxHostConcurrency([]Check{{"ray-dashboard", 8265, "http", "/"}})
	if one <= got {
		t.Errorf("a one-port check set allows %d hosts, no more than the full set's %d", one, got)
	}
}

// FuzzApplyPortOverrides fuzzes the one flag whose value is parsed into the
// probe table itself. TestDefaultProbePathsAreBenign guards the built-in
// checks, but -ports rewrites that table at runtime, so the property that
// matters here is that no operator-supplied string can introduce a path the
// allowlist never reviewed. A scanner that can be pointed at an arbitrary
// path by flag is an exploit tool with a different name.
func FuzzApplyPortOverrides(f *testing.F) {
	for _, seed := range []string{
		"", "vllm=8100", "9000", "vllm=8100,9000", "ray-dashboard=1",
		"triton=0", "triton=65536", "triton=-1", "nosuchservice=8000",
		"=8000", "vllm=", "vllm=8100,", ",,", " vllm = 8100 ",
		"vllm=8100=8200", "jupyter=8888;exec", "ollama=11434?x=1",
	} {
		f.Add(seed)
	}

	base := DefaultChecks()
	allowedPaths := map[string]bool{"/": true}
	for _, c := range base {
		allowedPaths[c.Path] = true
	}
	knownServices := map[string]bool{ServiceUnknown: true}
	for _, c := range base {
		knownServices[c.Service] = true
	}

	f.Fuzz(func(t *testing.T, spec string) {
		out, err := ApplyPortOverrides(DefaultChecks(), spec)
		if err != nil {
			return
		}
		if len(out) < len(base) {
			t.Errorf("ApplyPortOverrides(%q) dropped checks: %d < %d", spec, len(out), len(base))
		}
		for _, c := range out {
			if c.Port < 1 || c.Port > 65535 {
				t.Errorf("ApplyPortOverrides(%q) produced port %d for %s", spec, c.Port, c.Service)
			}
			if !allowedPaths[c.Path] {
				t.Errorf("ApplyPortOverrides(%q) introduced path %q, which the benign-path allowlist never reviewed",
					spec, c.Path)
			}
			if !knownServices[c.Service] {
				t.Errorf("ApplyPortOverrides(%q) introduced service %q", spec, c.Service)
			}
			if c.Scheme != "http" && c.Scheme != "tcp" {
				t.Errorf("ApplyPortOverrides(%q) produced scheme %q", spec, c.Scheme)
			}
		}
	})
}

// TestProbeOverIPv6 probes a real listener on the IPv6 loopback. The address
// handling is the point: an IPv6 literal has to be bracketed in a URL, and
// `[::1]:8265` is the kind of thing that works in net.Dial and then breaks
// one layer up in the HTTP client. CIDR expansion already accepts v6 blocks
// (/112 and narrower), so a v6-only management network is something an
// operator can legitimately point this at.
func TestProbeOverIPv6(t *testing.T) {
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback on this host: %v", err)
	}
	srv := &http.Server{
		Handler:           discriminating(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }),
		ReadHeaderTimeout: 2 * time.Second,
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("splitting listener address: %v", err)
	}
	port, _ := strconv.Atoi(portStr)

	obs := probeOne(t, "::1", []Check{{"ray-dashboard", port, "http", "/"}})
	if len(obs) != 1 {
		t.Fatalf("expected 1 observation over IPv6, got %+v", obs)
	}
	if !obs[0].Unauth || obs[0].Service != "ray-dashboard" {
		t.Errorf("expected an unauthenticated ray-dashboard over IPv6, got %+v", obs[0])
	}
	if obs[0].Host != "::1" {
		t.Errorf("the finding should name the target as given (%q), got %q", "::1", obs[0].Host)
	}

	// And the whole pipeline, since a report that renders the host wrongly is
	// as useless as one that missed it.
	findings := Detect(obs)
	if len(findings) != 1 || findings[0].RuleID != "RG-RAY-001" {
		t.Fatalf("expected RG-RAY-001 over IPv6, got %+v", findings)
	}
	if findings[0].Host != "::1" {
		t.Errorf("finding host = %q, want ::1", findings[0].Host)
	}
}

// TestProbeOverZoneScopedIPv6 is the regression test for a silent
// downgrade. A link-local address on a management network is written with a
// zone ("fe80::1%eth0"), net.Dial takes that form directly, and a URL must
// percent-escape it (RFC 6874). Unescaped, http.NewRequest fails to build
// before anything is sent: the TCP dial still succeeds, every HTTP probe on
// the port fails, and an unauthenticated Ray dashboard is reported as "port
// open, no HTTP response" at Info. The port looks probed. It was not.
//
// Found by FuzzNormalizeTarget's seed corpus, which asserts that an accepted
// target survives into a probe URL as itself.
func TestProbeOverZoneScopedIPv6(t *testing.T) {
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback on this host: %v", err)
	}
	srv := &http.Server{
		Handler:           discriminating(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }),
		ReadHeaderTimeout: 2 * time.Second,
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("splitting listener address: %v", err)
	}
	port, _ := strconv.Atoi(portStr)

	// The loopback zone is the only one portable enough to test against: an
	// interface name differs per host, and a scoped address only reaches
	// something on the interface it names.
	for _, zone := range []string{"lo", "lo0"} {
		host := "::1%" + zone
		if _, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(host, portStr)); err != nil {
			continue
		}
		obs := probeOne(t, host, []Check{{"ray-dashboard", port, "http", "/"}})
		if len(obs) != 1 {
			t.Fatalf("%s: expected 1 observation, got %+v", host, obs)
		}
		if !obs[0].Unauth || obs[0].Service != "ray-dashboard" {
			t.Errorf("%s: expected an unauthenticated ray-dashboard, got %+v (an unescaped zone makes every HTTP probe fail to build)", host, obs[0])
		}
		if obs[0].Host != host {
			t.Errorf("%s: the finding should name the target as given, got %q", host, obs[0].Host)
		}
		return
	}
	t.Skip("no usable IPv6 loopback zone on this host")
}

// TestURLHostEscapesTheZone pins the rendering itself, so the behaviour is
// checked even on a host with no usable v6 loopback zone.
func TestURLHostEscapesTheZone(t *testing.T) {
	cases := map[string]string{
		"fe80::1%eth0": "[fe80::1%25eth0]:8265",
		"::1":          "[::1]:8265",
		"10.0.0.5":     "10.0.0.5:8265",
		"ray-head":     "ray-head:8265",
	}
	for host, want := range cases {
		if got := urlHost(host, 8265); got != want {
			t.Errorf("urlHost(%q) = %q, want %q", host, got, want)
		}
		if _, err := http.NewRequest(http.MethodGet, "http://"+urlHost(host, 8265)+"/", nil); err != nil {
			t.Errorf("urlHost(%q) produced a URL http.NewRequest rejects: %v", host, err)
		}
	}
}

// TestProbeRefusesToNameAWildcard is the regression test for a real false
// positive. A server that answers 2xx to everything - an SPA dev server, a
// catch-all ingress route, a captive portal - used to be reported as
// whatever service happens to share its port. On 8265 that is a *critical*
// "unauthenticated Ray dashboard"; on 8000 it was vLLM and Triton at once,
// two services on one port, which cannot happen and is visibly wrong to the
// person reading the report.
func TestProbeRefusesToNameAWildcard(t *testing.T) {
	// Deliberately NOT wrapped in discriminating(): 200 on every path.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	host, portStr, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	t.Run("a single check is not promoted to a critical finding", func(t *testing.T) {
		obs := probeOne(t, host, []Check{{"ray-dashboard", port, "http", "/"}})
		if len(obs) != 1 {
			t.Fatalf("expected 1 observation, got %+v", obs)
		}
		if obs[0].Service != ServiceUnknown {
			t.Errorf("a catch-all server was named %q; it answers 2xx on any path", obs[0].Service)
		}
		findings := Detect(obs)
		if len(findings) != 1 || findings[0].RuleID != "RG-EXPOSURE-001" {
			t.Fatalf("expected one RG-EXPOSURE-001, got %+v", findings)
		}
		if findings[0].Severity != domain.Info {
			t.Errorf("severity = %s, want info: we do not know what this is", findings[0].Severity)
		}
	})

	t.Run("a shared port does not yield two services at once", func(t *testing.T) {
		obs := probeOne(t, host, []Check{
			{"vllm", port, "http", "/v1/models"},
			{"triton", port, "http", "/v2/health/ready"},
		})
		if len(obs) != 1 {
			t.Fatalf("expected a single unidentified observation, got %+v", obs)
		}
		for _, f := range Detect(obs) {
			if f.RuleID == "RG-VLLM-001" || f.RuleID == "RG-TRITON-001" {
				t.Errorf("a catch-all server was attributed to %s", f.RuleID)
			}
		}
	})
}

// TestControlProbeCostsOneRequest pins the cost of the wildcard control, since
// "one GET per service check" is a claim we make to CISOs in writing. The
// control runs only on a port where a service was identified.
func TestControlProbeCostsOneRequest(t *testing.T) {
	var mu sync.Mutex
	paths := []string{}
	// Counted before discriminating(), so the control request is visible to
	// the test rather than short-circuited by the helper.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		if r.URL.Path == controlPath {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	host, portStr, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	probeOne(t, host, []Check{{"ray-dashboard", port, "http", "/"}})

	mu.Lock()
	defer mu.Unlock()
	if len(paths) != 2 {
		t.Fatalf("expected exactly 2 requests (health path + control), got %d: %v", len(paths), paths)
	}
	if paths[0] != "/" || paths[1] != controlPath {
		t.Errorf("requests = %v, want [/ %s]", paths, controlPath)
	}
}

// TestMetricsPortsAreExemptFromTheWildcardControl pins the exemption and the
// reason for it. Real Triton's metrics server answers 200 on any path, which
// is ordinary for a Prometheus-style endpoint. Applying the wildcard control
// there would mean RG-TRITON-002 could never fire against Triton itself.
func TestMetricsPortsAreExemptFromTheWildcardControl(t *testing.T) {
	// 200 on everything, exactly like Triton's metrics server.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	host, portStr, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	obs := probeOne(t, host, []Check{{"triton-metrics", port, "http", "/metrics"}})
	if len(obs) != 1 || obs[0].Service != "triton-metrics" {
		t.Fatalf("a metrics endpoint that ignores the path must still be attributed, got %+v", obs)
	}
	findings := Detect(obs)
	if len(findings) != 1 || findings[0].RuleID != "RG-TRITON-002" {
		t.Fatalf("expected RG-TRITON-002, got %+v", findings)
	}

	// But a service rule on the same kind of server is still refused: the
	// exemption is per service, not per port.
	obs = probeOne(t, host, []Check{{"triton", port, "http", "/v2/health/ready"}})
	if len(obs) != 1 || obs[0].Service != ServiceUnknown {
		t.Errorf("the service rule must still refuse a catch-all server, got %+v", obs)
	}
}

// TestEveryPathAgnosticServiceExists guards against the exemption list
// outliving the checks it names - a typo there silently re-enables the
// control for a metrics rule and the rule quietly stops firing.
func TestEveryPathAgnosticServiceExists(t *testing.T) {
	known := map[string]bool{}
	for _, c := range DefaultChecks() {
		known[c.Service] = true
	}
	for svc := range pathAgnosticServices {
		if !known[svc] {
			t.Errorf("pathAgnosticServices names %q, which is not in the default check set", svc)
		}
	}
}

// TestValidateBucketURLAgreesWithProbeBucket. The up-front check in main and
// the probe itself must accept exactly the same strings: a validator that is
// stricter rejects a scan that would have worked, and one that is looser puts
// the error back where it was, mid-sweep.
func TestValidateBucketURLAgreesWithProbeBucket(t *testing.T) {
	cases := []struct {
		in    string
		valid bool
	}{
		{"https://bucket.s3.amazonaws.com", true},
		{"bucket.s3.amazonaws.com", true}, // scheme defaulted to https
		{"http://127.0.0.1:9000/models", true},
		{"://nonsense", false},
		{"https://", false},
		{"", false},
		{"https://bucket name.example.com", false},
	}
	s := New(50 * time.Millisecond)
	for _, tc := range cases {
		gotValid := ValidateBucketURL(tc.in) == nil
		if gotValid != tc.valid {
			t.Errorf("ValidateBucketURL(%q) valid=%v, want %v", tc.in, gotValid, tc.valid)
		}
		_, err := s.ProbeBucket(context.Background(), tc.in)
		if probeAccepted := err == nil; probeAccepted != tc.valid {
			t.Errorf("ProbeBucket(%q) accepted=%v but the validator said %v: the two must agree",
				tc.in, probeAccepted, tc.valid)
		}
	}
}

// TestValidateBucketURLErrorNamesTheInput: the operator has to be able to see
// which of five -buckets entries they fat-fingered.
func TestValidateBucketURLErrorNamesTheInput(t *testing.T) {
	err := ValidateBucketURL("://typo")
	if err == nil {
		t.Fatal("no error for a malformed URL")
	}
	if !strings.Contains(err.Error(), "://typo") {
		t.Errorf("error %q does not quote the offending entry", err)
	}
}

// TestMaxHostConcurrencyHandlesAnUnlimitedBudget. RLIM_INFINITY is
// math.MaxUint64; converted naively it goes negative and clamps the scan to
// one host at a time, so the machines with no limits at all would have been
// the slowest to scan.
func TestMaxHostConcurrencyHandlesAnUnlimitedBudget(t *testing.T) {
	var rl syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rl); err != nil {
		t.Skip("cannot read RLIMIT_NOFILE here")
	}
	if rl.Cur < 1<<20 {
		t.Skipf("local limit is %d; the saturating path is covered by the cap in MaxHostConcurrency", rl.Cur)
	}
	if got := MaxHostConcurrency(DefaultChecks()); got < 1000 {
		t.Errorf("MaxHostConcurrency = %d on a host with a %d descriptor limit", got, rl.Cur)
	}
}

// openFDs counts this process's open descriptors. Linux-only, which is why
// the test that uses it skips elsewhere.
func openFDs(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skipf("cannot count open descriptors here: %v", err)
	}
	return len(entries)
}

// TestProbeHostUnderDescriptorExhaustion drives the real failure, with a real
// EMFILE from a real dial, because that is the one link in this chain only the
// kernel can prove. Everything downstream (no clean grade, the banner, exit 7)
// is tested from ScanResult; this is the test that the dial error is
// recognized at all.
//
// The target is a loopback port with nothing on it, which makes the assertion
// sharp: with descriptors available that port is *closed*, which is an answer
// and proves the host is alive. With none available the same probe must not
// produce that answer - or any other - because we never got as far as asking.
func TestProbeHostUnderDescriptorExhaustion(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("descriptor accounting is read from /proc/self/fd")
	}
	const deadPort = 1 // nothing listens on port 1; loopback refuses it
	s := NewWithChecks(time.Second, []Check{{"ray-dashboard", deadPort, "http", "/"}})

	var orig syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &orig); err != nil {
		t.Skipf("cannot read RLIMIT_NOFILE: %v", err)
	}
	// Below what is already open: existing descriptors keep working (Linux
	// does not retroactively close them), and no new one - no socket - can be
	// created. A couple spare, because counting /proc/self/fd uses one itself
	// and the runtime may hold a descriptor that has just been released. The
	// window is one call long, with nothing in it that needs a descriptor.
	open := openFDs(t)
	if open < 8 {
		t.Skipf("only %d descriptors open; cannot construct an exhausted state safely", open)
	}
	tight := orig
	tight.Cur = uint64(open - 4)
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &tight); err != nil {
		t.Skipf("cannot lower RLIMIT_NOFILE: %v", err)
	}
	hs := s.ProbeHost(context.Background(), "127.0.0.1")
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &orig); err != nil {
		t.Fatalf("could not restore RLIMIT_NOFILE: %v", err)
	}

	if hs.ProbeErrors == 0 {
		t.Fatalf("no probe error recorded under descriptor exhaustion: %+v", hs)
	}
	if hs.State == domain.HostNoResponse {
		t.Error("the host is reported as silent; it said nothing because we could not ask")
	}
	if hs.State == domain.HostResponded {
		t.Error("the host is reported as responding, which it never got the chance to do")
	}
	if hs.State != domain.HostProbeFailed {
		t.Errorf("state = %s, want %s", hs.State, domain.HostProbeFailed)
	}
	if len(hs.Observations) != 0 {
		t.Errorf("recorded %d observation(s) from probes that never completed: %+v",
			len(hs.Observations), hs.Observations)
	}

	// The control: the same probe, with descriptors available, is an answer.
	healthy := s.ProbeHost(context.Background(), "127.0.0.1")
	if healthy.ProbeErrors != 0 {
		t.Errorf("probe errors reported with descriptors available: %+v", healthy)
	}
	if healthy.State != domain.HostResponded {
		t.Errorf("state = %s with descriptors available, want %s (a refused port is an answer)",
			healthy.State, domain.HostResponded)
	}
}

// serveTLSCapped starts an HTTPS server that will negotiate no higher than
// maxVersion, which is how a TLS-terminating proxy with an old configuration
// behaves.
func serveTLSCapped(t *testing.T, maxVersion uint16, h http.HandlerFunc) (string, int) {
	t.Helper()
	srv := httptest.NewUnstartedServer(discriminating(h))
	srv.TLS = &tls.Config{MaxVersion: maxVersion, MinVersion: tls.VersionTLS10}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	host, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("splitting test server address: %v", err)
	}
	port, _ := strconv.Atoi(portStr)
	return host, port
}

// TestProbeSeesServiceBehindObsoleteTLS is the blind spot this floor exists to
// close. Go's client refuses TLS 1.0/1.1 by default, which is correct for a
// client protecting its own traffic and wrong for a scanner: the handshake
// fails, the port is concluded not to speak TLS, the plaintext GET gets
// nothing, and an unauthenticated Ray dashboard behind an old terminating
// proxy is reported as an unidentified open port at Info. Measured before the
// fix, not assumed.
func TestProbeSeesServiceBehindObsoleteTLS(t *testing.T) {
	for _, tc := range []struct {
		name    string
		max     uint16
		wantVer string
	}{
		{"TLS 1.0", tls.VersionTLS10, "1.0"},
		{"TLS 1.1", tls.VersionTLS11, "1.1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host, port := serveTLSCapped(t, tc.max, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})
			obs := probeOne(t, host, []Check{{"ray-dashboard", port, "http", "/"}})

			var service, transport *domain.Observation
			for i := range obs {
				switch obs[i].Service {
				case "ray-dashboard":
					service = &obs[i]
				case ServiceTLS:
					transport = &obs[i]
				}
			}
			if service == nil || !service.Unauth {
				t.Fatalf("the service behind %s was not identified: %+v", tc.name, obs)
			}
			if !service.TLS.Enabled {
				t.Error("the service was reported as plaintext; it is TLS, just old TLS")
			}
			if service.TLS.Version != tc.wantVer {
				t.Errorf("negotiated version recorded as %q, want %q", service.TLS.Version, tc.wantVer)
			}
			if transport == nil {
				t.Fatal("no transport observation, so RG-TLS-003 cannot fire")
			}
			findings := Detect(obs)
			var sawObsolete bool
			for _, f := range findings {
				if f.RuleID == "RG-TLS-003" {
					sawObsolete = true
					if !strings.Contains(f.Detail, tc.wantVer) {
						t.Errorf("the finding does not name the version: %q", f.Detail)
					}
				}
				if f.RuleID == "RG-EXPOSURE-001" {
					t.Errorf("the port was reported as unidentified: %q", f.Detail)
				}
			}
			if !sawObsolete {
				t.Errorf("RG-TLS-003 did not fire against %s: %+v", tc.name, findings)
			}
		})
	}
}

// TestModernTLSStillNegotiatesHigh: lowering the floor must not drag modern
// services down with it. Negotiation picks the highest both sides support.
func TestModernTLSStillNegotiatesHigh(t *testing.T) {
	host, port := serveTLSCapped(t, tls.VersionTLS13, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	obs := probeOne(t, host, []Check{{"ray-dashboard", port, "http", "/"}})
	for _, o := range obs {
		if o.Service != "ray-dashboard" {
			continue
		}
		if o.TLS.Version != "1.3" {
			t.Errorf("negotiated TLS %q against a 1.3-capable server, want 1.3", o.TLS.Version)
		}
		if o.TLS.ObsoleteTLS() {
			t.Error("a 1.3 handshake was classified as obsolete")
		}
	}
	for _, f := range Detect(obs) {
		if f.RuleID == "RG-TLS-003" {
			t.Errorf("RG-TLS-003 fired against modern TLS: %q", f.Detail)
		}
	}
}

// A name's probes must all reach the ONE address resolution chose, while the
// request still names the host. This is the whole point of pinning: without
// it every probe hands the name back to the resolver, so a name with several
// A records is probed at a different machine from port to port - and the
// report, which records the name, cannot say which machine it describes.
//
// The test pins a name that does not resolve at all ("...invalid" is reserved
// for exactly this, RFC 2606). If the dial were not pinned, nothing could
// connect, so a passing request is itself the proof.
func TestProbesDialThePinnedAddressAndStillNameTheHost(t *testing.T) {
	const name = "ray-guard-pinning.invalid"
	var gotHost string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	addr, portStr, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	s := NewWithChecks(2*time.Second, nil)
	tgt := target{name: name, addr: addr}
	if !tgt.pinned() {
		t.Fatal("a name and an address are not the same target")
	}
	client, insecure := s.clientsFor(tgt)
	if client == s.client || insecure == s.insecure {
		t.Error("a pinned target must not reuse the shared clients, whose dialer resolves the URL host")
	}

	o, failed := s.httpProbe(context.Background(), probeCtx{tgt, client, insecure},
		Check{"ray-dashboard", port, "http", "/api/version"}, domain.TLSState{})
	if failed {
		t.Fatal("the probe failed locally")
	}
	if o.HTTPStatus != http.StatusOK {
		t.Fatalf("pinned probe got status %d; the dial did not reach the pinned address", o.HTTPStatus)
	}
	// The name is what we asked the service to be, so it has to survive into
	// the request: a name-based virtual host serves a different site without
	// it, and we would report the wrong one.
	if gotHost != net.JoinHostPort(name, portStr) {
		t.Errorf("server saw Host %q, want the operator's name %q", gotHost, name)
	}
	// And the finding has to be filed under the name, which is the identity
	// the operator passed and what detect.go and the Rego input contract key on.
	if o.Host != name {
		t.Errorf("observation recorded host %q, want %q", o.Host, name)
	}
}

// An address target must keep using the shared clients: a /24 sweep would
// otherwise allocate a client pair per host for no benefit.
func TestAddressTargetsReuseTheSharedClients(t *testing.T) {
	s := NewWithChecks(time.Second, nil)
	client, insecure := s.clientsFor(target{"10.1.2.3", "10.1.2.3"})
	if client != s.client || insecure != s.insecure {
		t.Error("an address needs no pinning and must reuse the shared clients")
	}
}

// TLS is dialed at the pinned address but handshaken under the name, because a
// terminating proxy picks its certificate from SNI. Handshaking with the
// address gets the default virtual host's certificate, so we would classify a
// certificate the service never serves to its real clients.
func TestTLSProbeDialsTheAddressAndOffersTheNameAsSNI(t *testing.T) {
	const name = "ray-guard-sni.invalid"
	var gotSNI string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.TLS = &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			gotSNI = h.ServerName
			return nil, nil
		},
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	addr, portStr, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	s := NewWithChecks(3*time.Second, nil)
	state, failed := s.tlsProbe(context.Background(), target{name: name, addr: addr}, port)
	if failed {
		t.Fatal("the handshake failed locally")
	}
	if !state.Enabled {
		t.Fatal("TLS was not detected; the dial did not reach the pinned address")
	}
	if gotSNI != name {
		t.Errorf("server saw SNI %q, want the operator's name %q", gotSNI, name)
	}
	// httptest's certificate is for 127.0.0.1/example.com, never our name, so
	// verification must fail against the NAME rather than silently pass
	// against the address we happened to dial.
	if state.Issue == "" {
		t.Error("a certificate that does not cover the target name must be reported as an issue")
	}
}

// An address is not a legal SNI value (RFC 6066), and a zone is local
// addressing rather than identity. Both must yield no SNI rather than a
// literal Go would silently drop anyway.
func TestSNIIsOfferedOnlyForNames(t *testing.T) {
	for _, in := range []string{"10.1.2.3", "::1", "fe80::1%eth0", "127.0.0.1"} {
		if got := sniName(in); got != "" {
			t.Errorf("sniName(%q) = %q, want no SNI for an address", in, got)
		}
	}
	for _, in := range []string{"ray.customer.internal", "host_1.example"} {
		if got := sniName(in); got != in {
			t.Errorf("sniName(%q) = %q, want the name offered as SNI", in, got)
		}
	}
}
