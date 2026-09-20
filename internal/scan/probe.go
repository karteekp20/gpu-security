package scan

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"gpusecurity/internal/domain"
)

type check struct {
	service string
	port    int
	scheme  string
	path    string
}

// Benign, read-only checks. NEVER add exploit payloads here (metadata-only-guard).
var defaultChecks = []check{
	{"ray-dashboard", 8265, "http", "/"},
	{"ray-client", 10001, "tcp", ""},
	{"vllm", 8000, "http", "/v1/models"},
	{"triton", 8000, "http", "/v2/health/ready"},
	{"triton-metrics", 8002, "http", "/metrics"},
	{"mlflow", 5000, "http", "/"},
	{"jupyter", 8888, "http", "/api"},
	{"ollama", 11434, "http", "/api/tags"},
	{"slurmctld", 6817, "tcp", ""},
}

type Scanner struct {
	timeout    time.Duration
	httpClient *http.Client
}

func New(timeout time.Duration) *Scanner {
	return &Scanner{
		timeout: timeout,
		httpClient: &http.Client{
			Timeout:       timeout,
			Transport:     &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

func (s *Scanner) ProbeHost(ctx context.Context, host string) []domain.Observation {
	var obs []domain.Observation
	for _, c := range defaultChecks {
		if !s.portOpen(host, c.port) {
			continue
		}
		o := domain.Observation{Host: host, Port: c.port, Service: c.service, Open: true}
		if c.scheme == "http" {
			s.httpProbe(ctx, host, c, &o)
		} else {
			o.Note = "control/RPC port reachable"
		}
		obs = append(obs, o)
	}
	return obs
}

func (s *Scanner) portOpen(host string, port int) bool {
	d := net.Dialer{Timeout: s.timeout}
	conn, err := d.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// httpProbe sends ONE benign GET to a known health/info path and records whether
// the service answered without requiring auth. No payload; executes nothing.
func (s *Scanner) httpProbe(ctx context.Context, host string, c check, o *domain.Observation) {
	for _, scheme := range []string{"https", "http"} {
		url := fmt.Sprintf("%s://%s:%d%s", scheme, host, c.port, c.path)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "ray-guard/0.1 (+benign posture probe)")
		resp, err := s.httpClient.Do(req)
		if err != nil {
			continue
		}
		_, _ = io.CopyN(io.Discard, resp.Body, 2048)
		_ = resp.Body.Close()
		o.HTTPStatus = resp.StatusCode
		o.TLS = scheme == "https"
		o.Unauth = resp.StatusCode >= 200 && resp.StatusCode < 300
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			o.Unauth = false
			o.Note = "reachable but requires auth"
		}
		return
	}
	o.Note = "port open, no HTTP response"
}
