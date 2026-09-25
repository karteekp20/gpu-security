package scan

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"gpusecurity/internal/domain"
)

// Check is one benign probe: an orchestrator we know how to recognize, the
// port it usually listens on, and a health/info path that answers without
// side effects. NEVER add exploit payloads or code-execution paths here
// (metadata-only-guard). We confirm exposure by observation, never by
// exploitation.
type Check struct {
	Service string
	Port    int
	Scheme  string // "http" (probe Path) or "tcp" (reachability only)
	Path    string
}

// ServiceUnknown is used when a port on the known AI-infrastructure list is
// open but no probe could identify what is listening. Reported, not guessed at.
const ServiceUnknown = "unknown"

// ServiceTLS carries transport-layer posture for an open port.
const ServiceTLS = "tls"

// ServiceBucket carries object-storage exposure.
const ServiceBucket = "bucket"

// maxBodyDrain is how much of a response we read before discarding. We read
// nothing into memory that we keep; draining a bounded amount lets the
// connection be reused and guarantees we never buffer a large body (P3).
const maxBodyDrain = 2048

func defaultChecks() []Check {
	return []Check{
		{"ray-dashboard", 8265, "http", "/"},
		{"ray-client", 10001, "tcp", ""},
		{"vllm", 8000, "http", "/v1/models"},
		{"triton", 8000, "http", "/v2/health/ready"},
		{"triton-grpc", 8001, "tcp", ""},
		{"triton-metrics", 8002, "http", "/metrics"},
		{"mlflow", 5000, "http", "/"},
		{"jupyter", 8888, "http", "/api"},
		{"ollama", 11434, "http", "/api/tags"},
		{"slurmctld", 6817, "tcp", ""},
	}
}

// DefaultChecks returns the built-in probe set.
func DefaultChecks() []Check { return defaultChecks() }

// ApplyPortOverrides rewrites the default check set from a comma-separated
// spec. Each element is either "service=port" (move a known service to a
// non-default port) or a bare "port" (probe an extra port as an unidentified
// HTTP service). Ports are defaults, not assumptions - clusters move them.
func ApplyPortOverrides(checks []Check, spec string) ([]Check, error) {
	out := append([]Check(nil), checks...)
	for _, raw := range strings.Split(spec, ",") {
		item := strings.TrimSpace(raw)
		if item == "" {
			continue
		}
		name, portStr, hasName := strings.Cut(item, "=")
		if !hasName {
			port, err := strconv.Atoi(item)
			if err != nil || port < 1 || port > 65535 {
				return nil, fmt.Errorf("invalid -ports entry %q: want service=port or a port number", item)
			}
			out = append(out, Check{ServiceUnknown, port, "http", "/"})
			continue
		}
		port, err := strconv.Atoi(strings.TrimSpace(portStr))
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("invalid port in -ports entry %q", item)
		}
		name = strings.TrimSpace(name)
		found := false
		for i := range out {
			if out[i].Service == name {
				out[i].Port = port
				found = true
			}
		}
		if !found {
			return nil, fmt.Errorf("unknown service %q in -ports; known: %s", name, strings.Join(serviceNames(checks), ", "))
		}
	}
	return out, nil
}

func serviceNames(checks []Check) []string {
	seen := map[string]bool{}
	var names []string
	for _, c := range checks {
		if !seen[c.Service] {
			seen[c.Service] = true
			names = append(names, c.Service)
		}
	}
	sort.Strings(names)
	return names
}

type Scanner struct {
	timeout time.Duration
	checks  []Check
	client  *http.Client
	// insecure is a second client used only to complete a handshake whose
	// certificate failed verification, so we can report *why* it failed.
	insecure *http.Client
}

func New(timeout time.Duration) *Scanner { return NewWithChecks(timeout, defaultChecks()) }

func NewWithChecks(timeout time.Duration, checks []Check) *Scanner {
	mk := func(skipVerify bool) *http.Client {
		return &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				TLSClientConfig:     &tls.Config{InsecureSkipVerify: skipVerify},
				DisableKeepAlives:   true,
				TLSHandshakeTimeout: timeout,
			},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	return &Scanner{timeout: timeout, checks: checks, client: mk(false), insecure: mk(true)}
}

// HostScan is everything one target yielded: whether we reached it at all,
// and what we saw if we did. The state matters as much as the observations -
// an empty observation list from a host that never answered is not evidence
// of a clean host (see domain.HostState).
type HostScan struct {
	Host         string
	State        domain.HostState
	Observations []domain.Observation
}

// Summary reduces the scan to its coverage record.
func (h HostScan) Summary() domain.HostSummary {
	return domain.HostSummary{Host: h.Host, State: h.State}
}

// ProbeHost probes every distinct port once, concurrently, then runs the
// checks bound to each open port. Probing per-port rather than per-check
// avoids dialing a shared port (8000 is both vLLM and Triton) twice and keeps
// a host with filtered ports from costing timeout x len(checks) seconds.
func (s *Scanner) ProbeHost(ctx context.Context, host string) HostScan {
	result := HostScan{Host: host, State: domain.HostNoResponse}

	// Resolve once, up front. Doing it here rather than implicitly on every
	// dial both saves repeated lookups and - the reason it matters - lets us
	// tell "this name does not exist" apart from "this host is firewalled".
	if !s.resolves(ctx, host) {
		result.State = domain.HostUnresolved
		return result
	}

	byPort := map[int][]Check{}
	var ports []int
	for _, c := range s.checks {
		if _, seen := byPort[c.Port]; !seen {
			ports = append(ports, c.Port)
		}
		byPort[c.Port] = append(byPort[c.Port], c)
	}
	sort.Ints(ports)

	var mu sync.Mutex
	var wg sync.WaitGroup
	obs := make([][]domain.Observation, len(ports))
	responded := false
	for i, port := range ports {
		i, port := i, port
		wg.Add(1)
		go func() {
			defer wg.Done()
			state := s.portState(ctx, host, port)
			mu.Lock()
			defer mu.Unlock()
			// A refused connection is an answer: the host is alive and simply
			// is not listening there. Only an all-timeout host is a blank.
			if state == domain.PortOpen || state == domain.PortClosed {
				responded = true
			}
			if state != domain.PortOpen {
				return
			}
			obs[i] = s.probeOpenPort(ctx, host, port, byPort[port])
		}()
	}
	wg.Wait()

	if responded {
		result.State = domain.HostResponded
	}
	for _, o := range obs {
		result.Observations = append(result.Observations, o...)
	}
	return result
}

// resolves reports whether the target can be turned into an address. IP
// literals always resolve; names go to the resolver once.
func (s *Scanner) resolves(ctx context.Context, host string) bool {
	if _, err := netip.ParseAddr(host); err == nil {
		return true
	}
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(ctx, host)
	return err == nil && len(addrs) > 0
}

// portState distinguishes closed (the host refused) from filtered (something
// dropped the packet, or the host is not there at all). Both are "not
// exposed", but they mean different things to an operator reading the report -
// and only "closed" proves a host is alive.
//
// The bar for "closed" is deliberately narrow: a TCP RST, and nothing else.
// "No route to host" and "host unreachable" also arrive promptly rather than
// as timeouts, but they come from the network telling us the host is absent,
// not from the host itself. Treating them as an answer would let an empty
// subnet masquerade as a clean one - which is exactly the false all-clear this
// whole distinction exists to prevent.
func (s *Scanner) portState(ctx context.Context, host string, port int) domain.PortState {
	d := net.Dialer{Timeout: s.timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err == nil {
		_ = conn.Close()
		return domain.PortOpen
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return domain.PortClosed
	}
	return domain.PortFiltered
}

func (s *Scanner) probeOpenPort(ctx context.Context, host string, port int, checks []Check) []domain.Observation {
	tlsState := s.tlsProbe(ctx, host, port)
	var obs []domain.Observation

	if tlsState.Enabled && tlsState.Issue != "" {
		obs = append(obs, domain.Observation{
			Host: host, Port: port, Service: ServiceTLS, State: domain.PortOpen,
			TLS: tlsState, Note: tlsState.Issue,
		})
	}

	var identified []domain.Observation
	var authRequired *domain.Observation
	var responded *domain.Observation
	var tcpOnly []domain.Observation

	for _, c := range checks {
		if c.Scheme != "http" {
			tcpOnly = append(tcpOnly, domain.Observation{
				Host: host, Port: port, Service: c.Service, State: domain.PortOpen,
				TLS: tlsState, Note: "control/RPC port; speaks no HTTP",
			})
			continue
		}
		o := s.httpProbe(ctx, host, c, tlsState)
		switch {
		case o.Unauth:
			identified = append(identified, o)
		case o.HTTPStatus == http.StatusUnauthorized || o.HTTPStatus == http.StatusForbidden:
			if authRequired == nil {
				cp := o
				authRequired = &cp
			}
		case o.HTTPStatus > 0:
			if responded == nil {
				cp := o
				cp.Service = ServiceUnknown
				responded = &cp
			}
		}
	}

	obs = append(obs, tcpOnly...)
	switch {
	case len(identified) > 0:
		// A 2xx on a service's own health path is what identifies it. On a
		// shared port (8000) only the real service answers 2xx on its path.
		obs = append(obs, identified...)
	case authRequired != nil:
		obs = append(obs, *authRequired)
	case responded != nil && len(tcpOnly) == 0:
		obs = append(obs, *responded)
	case len(tcpOnly) == 0:
		obs = append(obs, domain.Observation{
			Host: host, Port: port, Service: ServiceUnknown, State: domain.PortOpen,
			TLS: tlsState, Note: "port open, no HTTP response",
		})
	}
	return obs
}

// handshakeTimeout bounds the TLS handshake separately from the overall probe
// timeout.
//
// A peer that speaks TLS answers a ClientHello within a round trip. A peer
// that does not either rejects it immediately (Ray) or - and this is the case
// that matters - accepts the connection and waits silently for a complete
// HTTP request that will never come (Jupyter, MLflow, and plenty of others).
// Without a separate bound, every such port costs the full -timeout before we
// conclude "not TLS", which on a cluster with many plaintext ports is a large
// and entirely wasted delay.
//
// So a short handshake deadline is the correct behaviour, not a compromise.
func (s *Scanner) handshakeTimeout() time.Duration {
	const floor, ceiling = time.Second, 3 * time.Second
	d := s.timeout / 2
	if d < floor {
		d = floor
	}
	if d > ceiling {
		d = ceiling
	}
	if d > s.timeout {
		d = s.timeout
	}
	return d
}

// tlsProbe completes a TLS handshake and then verifies the presented chain
// ourselves, so we can report *why* verification failed rather than just
// "no TLS". We record only whether TLS is on, the failure class, and the
// expiry date - never the subject, issuer CN, serial, or chain bytes (P3).
func (s *Scanner) tlsProbe(ctx context.Context, host string, port int) domain.TLSState {
	d := &net.Dialer{Timeout: s.handshakeTimeout()}
	conn, err := tls.DialWithDialer(d, "tcp", net.JoinHostPort(host, strconv.Itoa(port)),
		&tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return domain.TLSState{Enabled: false}
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return domain.TLSState{Enabled: true}
	}
	leaf := certs[0]
	state := domain.TLSState{Enabled: true, NotAfter: leaf.NotAfter.UTC().Format("2006-01-02")}

	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	if _, verr := leaf.Verify(x509.VerifyOptions{
		DNSName: host, Roots: roots, Intermediates: inter,
	}); verr != nil {
		state.Issue = classifyTLSError(verr, leaf)
	}
	return state
}

func classifyTLSError(err error, leaf *x509.Certificate) string {
	now := time.Now()
	switch {
	case now.After(leaf.NotAfter):
		return "expired"
	case now.Before(leaf.NotBefore):
		return "not-yet-valid"
	}
	var hostErr x509.HostnameError
	if errors.As(err, &hostErr) {
		return "hostname-mismatch"
	}
	var authErr x509.UnknownAuthorityError
	if errors.As(err, &authErr) {
		return "self-signed"
	}
	var invalid x509.CertificateInvalidError
	if errors.As(err, &invalid) && invalid.Reason == x509.Expired {
		return "expired"
	}
	return "untrusted"
}

// httpProbe sends ONE benign GET to a known health/info path and records
// whether the service answered without requiring auth. It sends no body, uses
// no method other than GET, and discards the response body without inspecting
// it. Status code and headers-level facts only - never content (P3).
func (s *Scanner) httpProbe(ctx context.Context, host string, c Check, tlsState domain.TLSState) domain.Observation {
	o := domain.Observation{Host: host, Port: c.Port, Service: c.Service, State: domain.PortOpen, TLS: tlsState}

	schemes := []string{"http"}
	if tlsState.Enabled {
		schemes = []string{"https"}
	}
	for _, scheme := range schemes {
		target := fmt.Sprintf("%s://%s%s", scheme, net.JoinHostPort(host, strconv.Itoa(c.Port)), c.Path)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "ray-guard/"+domain.Version+" (+benign posture probe)")
		client := s.client
		if tlsState.Enabled && tlsState.Issue != "" {
			client = s.insecure
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		// Drain a bounded amount and discard. The body is never inspected,
		// parsed, logged, or stored.
		_, _ = io.CopyN(io.Discard, resp.Body, maxBodyDrain)
		_ = resp.Body.Close()

		o.HTTPStatus = resp.StatusCode
		o.Unauth = resp.StatusCode >= 200 && resp.StatusCode < 300
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			o.Note = "reachable but requires auth"
		}
		return o
	}
	o.Note = "no HTTP response"
	return o
}

// ProbeBucket checks whether an object-storage bucket lists publicly. It
// issues one unauthenticated GET and decides from the STATUS CODE ALONE. The
// response body is discarded unparsed: object keys are customer data, not
// metadata, so we never look at them (P3).
func (s *Scanner) ProbeBucket(ctx context.Context, raw string) (domain.Observation, error) {
	target := raw
	if !strings.Contains(target, "://") {
		target = "https://" + target
	}
	u, err := url.Parse(target)
	if err != nil || u.Host == "" {
		return domain.Observation{}, fmt.Errorf("invalid bucket URL %q", raw)
	}
	o := domain.Observation{Host: u.Host, Service: ServiceBucket, State: domain.PortOpen,
		TLS: domain.TLSState{Enabled: u.Scheme == "https"}}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return domain.Observation{}, err
	}
	req.Header.Set("User-Agent", "ray-guard/"+domain.Version+" (+benign posture probe)")
	resp, err := s.client.Do(req)
	if err != nil {
		o.Note = "bucket endpoint unreachable"
		return o, nil
	}
	_, _ = io.CopyN(io.Discard, resp.Body, maxBodyDrain)
	_ = resp.Body.Close()

	o.HTTPStatus = resp.StatusCode
	o.Unauth = resp.StatusCode >= 200 && resp.StatusCode < 300
	if !o.Unauth {
		o.Note = "listing not public"
	}
	return o, nil
}
