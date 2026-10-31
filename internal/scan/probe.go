// Package scan probes targets and decides what is wrong with them.
//
// The two halves are deliberately separate. probe.go observes what is true -
// this port is open, this service answered 200, this certificate is
// self-signed - and detect.go decides what is bad. That split keeps detection
// unit-testable without a network, lets severities be re-tuned after buyer
// feedback without touching probing, and marks the seam where the Phase-1
// OPA/Rego rule library will replace detect.go.
//
// Probes are read-only and benign: one GET per check, no request body, to
// documented health endpoints only, plus one control GET to controlPath on a
// port where something was identified. We confirm exposure by observation,
// never by exploitation.
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

// controlPath is a path no real service serves. It is requested only on a
// port where a service was already identified, to catch servers that answer
// 2xx to anything: SPA dev servers, catch-all ingress routes, captive
// portals. Without it, a wildcard server on 8265 is reported as a critical
// "unauthenticated Ray dashboard", and one on 8000 as vLLM *and* Triton at
// once - two services on one port, which is impossible and visibly wrong on
// a customer's report.
//
// Real Ray, Jupyter, MLflow, Ollama and TorchServe all answer 404 here
// (verified against the running containers, not assumed), so the control
// costs attribution nothing. The path names us on purpose: an operator
// reading their access log should be able to tell immediately who sent it.
const controlPath = "/ray-guard-probe-404"

// pathAgnosticServices legitimately answer 2xx on any path, so the wildcard
// control does not apply to them. Prometheus-style endpoints are the whole
// category: real Triton's metrics server on 8002 returns 200 for
// controlPath, which is normal for an exporter and not evidence of a
// catch-all.
//
// This is a deliberate, bounded trade. Applying the control here would mean
// RG-TRITON-002 could never fire against Triton - a rule that cannot detect
// the software it is named after is worse than no rule, because it makes the
// detection table look bigger than it is. Skipping it means a catch-all
// server on 8002 may be reported as a reachable metrics endpoint: a Low
// finding whose remediation ("restrict the metrics port to your monitoring
// network") is sound advice whatever is actually listening. The strong guard
// stays where misattribution is expensive - the Critical and High service
// rules.
var pathAgnosticServices = map[string]bool{
	"triton-metrics":     true,
	"torchserve-metrics": true,
	"dcgm-exporter":      true,
}

func defaultChecks() []Check {
	return []Check{
		// 8265 is probed at /api/version, not /. Measured against real Ray
		// 2.9.0: / returns the dashboard's HTML shell, which is the least
		// discriminating path in this table - any web server answers it - while
		// /api/version returns {"ray_version": "...", "ray_commit": "..."} and
		// so is evidence that Ray's own dashboard API answered us without
		// credentials. Ray has no per-route authentication, so an API that
		// answers us answers anyone who can reach the port.
		//
		// NOT /api/jobs/, which was the obvious choice because POST to that same
		// path is the code-execution endpoint. Measured: GET /api/jobs/ returns
		// each job's "entrypoint" - the customer's literal command line - plus
		// runtime_env, which can carry environment variables. That is the most
		// payload-adjacent document on the host, and requesting it to discard it
		// is not a trade worth making for the same conclusion (P3). It is also
		// why "job" is a forbidden substring in the benign-path allowlist.
		//
		// The ceiling, stated: a Ray old enough not to serve /api/version would
		// be reported as an unidentified service on 8265 at Info rather than as
		// this Critical. Verified present on 2.9.0; the endpoint reports a
		// dashboard API version of its own ("4"), so it is long-standing.
		{"ray-dashboard", 8265, "http", "/api/version"},
		{"ray-client", 10001, "tcp", ""},
		{"vllm", 8000, "http", "/v1/models"},
		{"triton", 8000, "http", "/v2/health/ready"},
		{"triton-grpc", 8001, "tcp", ""},
		{"triton-metrics", 8002, "http", "/metrics"},
		{"mlflow", 5000, "http", "/"},
		{"jupyter", 8888, "http", "/api"},
		{"ollama", 11434, "http", "/api/tags"},
		{"slurmctld", 6817, "tcp", ""},
		// TorchServe's management API is the dangerous half: it registers
		// models from a URL the caller supplies (CVE-2023-43654).
		{"torchserve-mgmt", 8081, "http", "/models"},
		{"torchserve-metrics", 8082, "http", "/metrics"},
		{"sglang", 30000, "http", "/get_model_info"},
		// DCGM is NVIDIA's standard GPU exporter: present on essentially
		// every GPU node, and the only check here that is about GPUs rather
		// than about something serving a model.
		{"dcgm-exporter", 9400, "http", "/metrics"},
		// 8080 is probed but never attributed. TorchServe's inference API,
		// TGI, LocalAI and most things with a model behind them default
		// here, and the only GET TorchServe offers on it is /ping - so "200
		// on /ping on 8080" would name a large fraction of the web as
		// TorchServe. Reporting "something is open on 8080, we did not
		// identify it" at Info is the honest result, and it is the question
		// worth asking in the room.
		{ServiceUnknown, 8080, "http", "/"},
	}
}

// DefaultChecks returns the built-in probe set.
func DefaultChecks() []Check { return defaultChecks() }

// fdsPerHost is how many descriptors one host in flight can hold at once: each
// distinct port is dialled in its own goroutine, and an open one then does a
// TLS handshake and an HTTP request. Two per port is the honest ceiling.
const fdsPerHost = 2

// fdReserve leaves room for everything that is not a probe socket: stdio, the
// report files, the resolver's sockets, and the Go runtime's own descriptors.
const fdReserve = 64

// MaxHostConcurrency returns the most hosts that can be probed at once without
// the scan running the process out of file descriptors.
//
// This is not tidiness. Exceeding the limit does not make the scan fail, it
// makes it *lie*: dials start failing for local reasons, and measured against
// a real cluster with the limit at 128 the demo stack graded C with 3 findings
// instead of F with 19, with the unauthenticated Ray dashboard reported as an
// unidentified service. localResourceError now catches that and marks the run
// degraded, but the better outcome is not to get there, so the scan is clamped
// to what the host can actually sustain and the operator is told why.
//
// What binds here is the HARD limit, not the soft one: since Go 1.19 the
// runtime raises RLIMIT_NOFILE's soft limit to the hard limit at startup, so
// the familiar low soft defaults (macOS ships 256) are raised before any of
// this runs and are not the case to worry about. Verified rather than assumed:
// a shell soft limit of 128 with a hard limit of 524288 is seen by the Go
// process as 524288. The cases that actually bind are containers and CI images
// with a low hard limit, and hosts whose limits.conf sets one. Such a machine
// gets a slower, correct scan rather than a fast, wrong one.
func MaxHostConcurrency(checks []Check) int {
	var rl syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rl); err != nil {
		return 0 // unknown: impose no limit of our own
	}
	ports := map[int]bool{}
	for _, c := range checks {
		ports[c.Port] = true
	}
	perHost := len(ports) * fdsPerHost
	if perHost < 1 {
		perHost = 1
	}
	// rl.Cur can be RLIM_INFINITY (math.MaxUint64), which converts to a
	// negative int and would clamp the scan to a single host at a time - the
	// opposite of what an unlimited descriptor budget should mean. Cap it at a
	// number we would never need instead. Caught by gosec (G115), which is the
	// kind of bug that would have shown up as "the scan is mysteriously slow
	// on exactly the machines with no limits".
	const maxBudget = 1 << 20
	cur := rl.Cur
	if cur > maxBudget {
		cur = maxBudget
	}
	budget := int(cur) - fdReserve
	if budget < perHost {
		return 1
	}
	return budget / perHost
}

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
	s := &Scanner{timeout: timeout, checks: checks}
	s.client, s.insecure = s.clientPair(nil)
	return s
}

// clientPair builds the verifying and non-verifying clients, both dialing
// through dial. A nil dial means the default dialer, which resolves the URL's
// host itself - correct only when that host is already an address.
func (s *Scanner) clientPair(dial dialFunc) (secure, insecure *http.Client) {
	mk := func(skipVerify bool) *http.Client {
		return &http.Client{
			Timeout: s.timeout,
			Transport: &http.Transport{
				// #nosec G402 -- MinVersion is deliberately at the floor: see
				// scanTLSFloor. We are measuring other people's transport
				// posture, not protecting our own traffic.
				TLSClientConfig:     &tls.Config{InsecureSkipVerify: skipVerify, MinVersion: scanTLSFloor},
				DisableKeepAlives:   true,
				TLSHandshakeTimeout: s.timeout,
				DialContext:         dial,
			},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	return mk(false), mk(true)
}

type dialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// target is one host as the operator named it, pinned to the single address
// every probe for it will dial.
//
// The two are separate on purpose. The address is how we reach the machine;
// the name is what we are asking the service to be, so it stays in the URL,
// the Host header, the SNI extension and the x509 SAN check. Dialing the
// address but verifying against it instead of the name would turn a valid
// certificate for ray.customer.internal into a hostname-mismatch finding, and
// would ask a name-based virtual host for the wrong site.
type target struct {
	name string
	addr string
}

// probeCtx is everything the probes for one host share: the target and the
// two clients pinned to its address.
type probeCtx struct {
	t              target
	client         *http.Client
	insecureClient *http.Client
}

// dialTo is the address:port every probe for this target connects to.
func (t target) dialTo(port int) string {
	return net.JoinHostPort(t.addr, strconv.Itoa(port))
}

// pinned reports whether the dial has to be redirected at all. A target the
// operator gave as an address needs no pinning, which keeps a /24 sweep on
// the shared clients rather than allocating a pair per host.
func (t target) pinned() bool { return t.addr != t.name }

// clientsFor returns the clients to use for this target: the shared pair for
// an address, or a pair pinned to the resolved address for a name.
//
// Pinning the dial is the whole point. Without it every probe passes the name
// to net.Dial and the resolver answers again, so a name with several A records
// is probed at a different machine from port to port - and the report, which
// records the name, cannot say which.
func (s *Scanner) clientsFor(t target) (secure, insecure *http.Client) {
	if !t.pinned() {
		return s.client, s.insecure
	}
	timeout := s.timeout
	addr := t.addr
	return s.clientPair(func(ctx context.Context, network, address string) (net.Conn, error) {
		// Keep the port the URL asked for; replace only the host.
		_, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		d := net.Dialer{Timeout: timeout}
		return d.DialContext(ctx, network, net.JoinHostPort(addr, port))
	})
}

// HostScan is everything one target yielded: whether we reached it at all,
// and what we saw if we did. The state matters as much as the observations -
// an empty observation list from a host that never answered is not evidence
// of a clean host (see domain.HostState).
type HostScan struct {
	Host string
	// Addr is the address every probe for this host dialed, and AddrCount how
	// many the name resolved to. Both are empty/zero when the operator passed
	// an address: there is nothing to disclose.
	Addr         string
	AddrCount    int
	State        domain.HostState
	Observations []domain.Observation
	// ProbeErrors counts ports whose probe failed inside the scanner - the
	// process ran out of file descriptors or ephemeral ports - rather than
	// because of anything the target did. Such a port yields no observation at
	// all: we learned nothing about it, and a report that says "open, service
	// unidentified" where the truth is "we could not look" understates the
	// finding. See localResourceError.
	ProbeErrors int
}

// Summary reduces the scan to its coverage record.
func (h HostScan) Summary() domain.HostSummary {
	return domain.HostSummary{
		Host: h.Host, State: h.State,
		Address: h.Addr, AddressesFound: h.AddrCount,
	}
}

// ProbeHost probes every distinct port once, concurrently, then runs the
// checks bound to each open port. Probing per-port rather than per-check
// avoids dialing a shared port (8000 is both vLLM and Triton) twice and keeps
// a host with filtered ports from costing timeout x len(checks) seconds.
func (s *Scanner) ProbeHost(ctx context.Context, host string) HostScan {
	result := HostScan{Host: host, State: domain.HostNoResponse}

	// Resolve once, up front, and probe only the address we got. Doing it
	// here rather than implicitly on every dial lets us tell "this name does
	// not exist" apart from "this host is firewalled", and pins every probe
	// for this host to one machine so the report describes a single subject.
	t, count, ok := s.resolve(ctx, host)
	if !ok {
		result.State = domain.HostUnresolved
		return result
	}
	if t.pinned() {
		result.Addr, result.AddrCount = t.addr, count
	}
	client, insecure := s.clientsFor(t)

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
	probeErrors := 0
	for i, port := range ports {
		i, port := i, port
		wg.Add(1)
		go func() {
			defer wg.Done()
			state, failed := s.portState(ctx, t, port)
			mu.Lock()
			defer mu.Unlock()
			if failed {
				// Our own limits, not the target's posture. Counting it is the
				// only honest thing to do with it.
				probeErrors++
				return
			}
			// A refused connection is an answer: the host is alive and simply
			// is not listening there. Only an all-timeout host is a blank.
			if state == domain.PortOpen || state == domain.PortClosed {
				responded = true
			}
			if state != domain.PortOpen {
				return
			}
			portObs, errs := s.probeOpenPort(ctx, probeCtx{t, client, insecure}, port, byPort[port])
			if errs > 0 {
				// The port is open but we could not characterize what is on
				// it. Dropping the observations costs a line on the report and
				// keeps us from reporting Ray's dashboard as an unidentified
				// service, which is what this used to do.
				probeErrors += errs
				return
			}
			obs[i] = portObs
		}()
	}
	wg.Wait()

	result.ProbeErrors = probeErrors
	switch {
	case responded:
		result.State = domain.HostResponded
	case probeErrors > 0:
		// Not "no response": we never managed to ask.
		result.State = domain.HostProbeFailed
	}
	for _, o := range obs {
		result.Observations = append(result.Observations, o...)
	}
	return result
}

// resolve turns a target into the single address its probes will dial, and
// reports how many addresses the name has. IP literals resolve to themselves;
// names go to the resolver exactly once.
//
// The address chosen is the resolver's first, not the numerically lowest: that
// is the one an ordinary client would connect to, which is the posture the
// scan is supposed to measure. What matters for correctness is that the choice
// is made once per host rather than once per dial - a name with several A
// records otherwise moves between machines from port to port, and the report
// has no way to say so.
func (s *Scanner) resolve(ctx context.Context, host string) (target, int, bool) {
	if _, err := netip.ParseAddr(host); err == nil {
		return target{name: host, addr: host}, 1, true
	}
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil || len(addrs) == 0 {
		return target{}, 0, false
	}
	return target{name: host, addr: addrs[0]}, len(addrs), true
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
// It returns a second value: whether the dial failed for a reason local to the
// scanner. That case is not a port state at all and must not be recorded as
// one (localResourceError).
func (s *Scanner) portState(ctx context.Context, t target, port int) (domain.PortState, bool) {
	d := net.Dialer{Timeout: s.timeout}
	conn, err := d.DialContext(ctx, "tcp", t.dialTo(port))
	if err == nil {
		_ = conn.Close()
		return domain.PortOpen, false
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return domain.PortClosed, false
	}
	if localResourceError(err) {
		return domain.PortFiltered, true
	}
	return domain.PortFiltered, false
}

// localResourceError reports whether an error is the scanner running out of
// its own resources rather than the network saying something about the target.
//
// This distinction is the same one as "closed vs filtered", one layer in: a
// dial that fails with EMFILE tells us about our file-descriptor limit and
// nothing whatsoever about the host. Treating it as "filtered" is how a scan
// silently under-reports - measured, not theorized. With the open-file limit
// at 128, a /24 of the demo cluster graded C with 3 findings instead of F with
// 19, and the unauthenticated Ray dashboard was reported as an unidentified
// service on 8265, because the TCP dial succeeded and the HTTP GET did not.
// Nothing in the report said anything had gone wrong.
//
// EADDRNOTAVAIL is included because ephemeral-port exhaustion produces the
// same shape of failure from the same cause - probing faster than the local
// stack can keep up.
func localResourceError(err error) bool {
	return errors.Is(err, syscall.EMFILE) ||
		errors.Is(err, syscall.ENFILE) ||
		errors.Is(err, syscall.ENOBUFS) ||
		errors.Is(err, syscall.EADDRNOTAVAIL)
}

func (s *Scanner) probeOpenPort(ctx context.Context, p probeCtx, port int, checks []Check) ([]domain.Observation, int) {
	host := p.t.name
	tlsState, failed := s.tlsProbe(ctx, p.t, port)
	if failed {
		// Without knowing whether the port speaks TLS we cannot classify
		// anything on it, and guessing "plaintext" would raise RG-TLS-002
		// against a service that is in fact encrypted.
		return nil, 1
	}
	var obs []domain.Observation
	probeErrors := 0

	if tlsState.Enabled && (tlsState.Issue != "" || tlsState.ObsoleteTLS()) {
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
		o, failed := s.httpProbe(ctx, p, c, tlsState)
		if failed {
			probeErrors++
			continue
		}
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

	if probeErrors > 0 {
		// Any check on this port failed inside the scanner, so what we have is
		// a partial view of a port we cannot characterize. Report nothing
		// rather than the weakest thing we happened to see.
		return nil, probeErrors
	}

	obs = append(obs, tcpOnly...)
	switch {
	case len(identified) > 0 && needsWildcardControl(identified) &&
		s.answersAnything(ctx, p, port, tlsState):
		// The port answered 2xx on a service's health path - and on a path
		// that cannot exist. It discriminates nothing, so neither can we.
		obs = append(obs, domain.Observation{
			Host: host, Port: port, Service: ServiceUnknown, State: domain.PortOpen,
			TLS: tlsState, HTTPStatus: identified[0].HTTPStatus, Unauth: true,
			Note: "answers 2xx on any path, including one that cannot exist; no service could be identified",
		})
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
	return obs, 0
}

// needsWildcardControl reports whether any service claimed on this port makes
// a claim strong enough to be worth a control request. A port where only
// path-agnostic services matched needs none: a 2xx there proves nothing
// either way.
func needsWildcardControl(identified []domain.Observation) bool {
	for _, o := range identified {
		if !pathAgnosticServices[o.Service] {
			return true
		}
	}
	return false
}

// answersAnything reports whether the port returns 2xx for a path that cannot
// exist, which means its 2xx on a health path proved nothing. One extra GET,
// and only on a port where something was already identified.
//
// A failed control request counts as "discriminates fine": if we cannot get
// an answer we keep the attribution we already have, because silently
// downgrading a real finding is the worse error.
func (s *Scanner) answersAnything(ctx context.Context, p probeCtx, port int, tlsState domain.TLSState) bool {
	o, _ := s.httpProbe(ctx, p, Check{ServiceUnknown, port, "http", controlPath}, tlsState)
	return o.Unauth
}

// scanTLSFloor is the lowest TLS version the scanner will negotiate, and it is
// deliberately lower than any version we would accept for our own traffic.
//
// Go's client default is TLS 1.2, which is right for a client protecting its
// own data and wrong for a scanner: measured against a server capped at TLS
// 1.0, the handshake fails, tlsProbe concludes "not TLS", the HTTP probe then
// speaks plaintext to a TLS port and gets nothing, and an unauthenticated Ray
// dashboard behind an old TLS-terminating proxy is reported as an unidentified
// open port at Info. The obsolete version - a finding in itself - is invisible
// for the same reason.
//
// Lowering the floor costs nothing on modern services: negotiation still
// settles on the highest version both sides support (verified: a TLS 1.3
// server still negotiates 1.3). Nothing secret is sent either way - one GET to
// a health path, no credentials, no body.
//
// SSLv3 and older are not supported by Go at all, so a server offering only
// those is still reported as an unidentified open port. That is the honest
// ceiling of this check.
const scanTLSFloor = tls.VersionTLS10

// tlsVersionName maps the negotiated version to the string the report uses.
// An unknown future version is recorded as "" rather than guessed at: a wrong
// version on a report is worse than a missing one.
func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "1.0"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS13:
		return "1.3"
	default:
		return ""
	}
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
// It returns a second value: whether the handshake failed for a reason local
// to the scanner, in which case the result says nothing about the port.
func (s *Scanner) tlsProbe(ctx context.Context, t target, port int) (domain.TLSState, bool) {
	d := &net.Dialer{Timeout: s.handshakeTimeout()}
	// Dial the pinned address, but send the operator's name as SNI: a
	// TLS-terminating proxy selects the certificate from SNI, so handshaking
	// with the address would be served the default virtual host's certificate
	// and we would classify the wrong one.
	// #nosec G402 -- see scanTLSFloor: a scanner that refuses obsolete TLS
	// cannot see what is behind it, and cannot report that it is obsolete.
	conn, err := tls.DialWithDialer(d, "tcp", t.dialTo(port),
		&tls.Config{InsecureSkipVerify: true, MinVersion: scanTLSFloor,
			ServerName: sniName(t.name)})
	if err != nil {
		return domain.TLSState{Enabled: false}, localResourceError(err)
	}
	defer func() { _ = conn.Close() }()
	cs := conn.ConnectionState()
	version := tlsVersionName(cs.Version)
	certs := cs.PeerCertificates
	if len(certs) == 0 {
		return domain.TLSState{Enabled: true, Version: version}, false
	}
	leaf := certs[0]
	state := domain.TLSState{Enabled: true, Version: version,
		NotAfter: leaf.NotAfter.UTC().Format("2006-01-02")}

	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	if _, verr := leaf.Verify(x509.VerifyOptions{
		// x509 has no concept of a zone, and a scoped address would never
		// match a SAN. Verify the address itself.
		DNSName: stripZone(t.name), Roots: roots, Intermediates: inter,
	}); verr != nil {
		state.Issue = classifyTLSError(verr, leaf)
	}
	return state, false
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

// urlHost renders host:port for use in a URL.
//
// It exists for one case: a zone-scoped IPv6 address, which is how a
// link-local address on a management network is written ("fe80::1%eth0").
// net.Dial takes that form directly, but a URL must percent-escape the zone
// (RFC 6874, "fe80::1%25eth0"). Unescaped, http.NewRequest fails to parse
// every URL we build for such a host - so the TCP dial succeeds, all of the
// HTTP probes fail to be built, and the port is reported as "open, no HTTP
// response". Measured against a real listener: an unauthenticated dashboard
// on a scoped address became an Info-level unidentified port, which is the
// flagship Critical silently downgraded. Verified that the escaped form does
// reach a real server (status 200 on ::1%lo), rather than assumed from the RFC.
func urlHost(host string, port int) string {
	if i := strings.IndexByte(host, '%'); i >= 0 {
		host = host[:i] + "%25" + host[i+1:]
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// sniName is the name to offer as SNI, or "" to offer none. An address is
// never a legal SNI value (RFC 6066 forbids literals), and Go would silently
// send nothing; returning "" says so explicitly. A zone is local addressing,
// not identity, so it never belongs in SNI either.
func sniName(host string) string {
	if _, err := netip.ParseAddr(stripZone(host)); err == nil {
		return ""
	}
	return host
}

// stripZone removes an IPv6 zone from an address. The zone is a local
// interface name: it is how we reach the host, not part of its identity.
func stripZone(host string) string {
	if i := strings.IndexByte(host, '%'); i >= 0 {
		return host[:i]
	}
	return host
}

// httpProbe sends ONE benign GET to a known health/info path and records
// whether the service answered without requiring auth. It sends no body, uses
// no method other than GET, and discards the response body without inspecting
// it. Status code and headers-level facts only - never content (P3).
// It returns a second value: whether the request failed for a reason local to
// the scanner, which is not a fact about the service.
func (s *Scanner) httpProbe(ctx context.Context, p probeCtx, c Check, tlsState domain.TLSState) (domain.Observation, bool) {
	host := p.t.name
	o := domain.Observation{Host: host, Port: c.Port, Service: c.Service, State: domain.PortOpen, TLS: tlsState}
	failed := false

	schemes := []string{"http"}
	if tlsState.Enabled {
		schemes = []string{"https"}
	}
	for _, scheme := range schemes {
		target := fmt.Sprintf("%s://%s%s", scheme, urlHost(host, c.Port), c.Path)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "ray-guard/"+domain.Version+" (+benign posture probe)")
		client := p.client
		if tlsState.Enabled && tlsState.Issue != "" {
			client = p.insecureClient
		}
		resp, err := client.Do(req)
		if err != nil {
			if localResourceError(err) {
				failed = true
			}
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
		return o, false
	}
	o.Note = "no HTTP response"
	return o, failed
}

// ValidateBucketURL reports whether a -buckets entry is probeable at all. It
// exists so a typo is rejected before the scan starts: the alternative is a
// line on stderr half-way through a sweep and a bucket that was in scope
// quietly missing from the report.
func ValidateBucketURL(raw string) error {
	_, err := parseBucketURL(raw)
	return err
}

func parseBucketURL(raw string) (*url.URL, error) {
	target := raw
	if !strings.Contains(target, "://") {
		target = "https://" + target
	}
	u, err := url.Parse(target)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("invalid bucket URL %q: want a URL or host, e.g. https://bucket.s3.amazonaws.com", raw)
	}
	return u, nil
}

// ProbeBucket checks whether an object-storage bucket lists without credentials. It
// issues one unauthenticated GET and decides from the STATUS CODE ALONE. The
// response body is discarded unparsed: object keys are customer data, not
// metadata, so we never look at them (P3).
func (s *Scanner) ProbeBucket(ctx context.Context, raw string) (domain.Observation, error) {
	u, err := parseBucketURL(raw)
	if err != nil {
		return domain.Observation{}, err
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
		if localResourceError(err) {
			return domain.Observation{}, fmt.Errorf("bucket %s: probe failed locally (file-descriptor or ephemeral-port limit): %w", u.Host, err)
		}
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
