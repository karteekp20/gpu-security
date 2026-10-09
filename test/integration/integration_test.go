//go:build integration

// Package integration exercises ray-guard against services that actually run,
// rather than against stubs returning whatever status code we assumed.
//
// This matters more than it sounds. RG-RAY-001 carries the entire ShadowRay
// pitch, and a unit test proves only that our detection logic agrees with our
// own mock. If real Ray redirected, served a SPA shell, or answered on a
// different path, every unit test would still pass and the detection would
// misfire during a buyer-led assessment. These tests close that gap.
//
// Run with: make test-integration
// (Never part of `go test ./...` - the images are multi-gigabyte.)
package integration

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"gpusecurity/internal/domain"
	"gpusecurity/internal/scan"
)

// Addresses are pinned in docker-compose.yml so tests can target a service
// directly and -cidr discovery has a known range.
const (
	subnet = "172.31.77.0/24"

	addrRay      = "172.31.77.10"
	addrJupyter  = "172.31.77.11"
	addrMLflow   = "172.31.77.12"
	addrOllama   = "172.31.77.13"
	addrVLLM     = "172.31.77.20"
	addrTriton   = "172.31.77.21"
	addrTorch    = "172.31.77.22"
	addrSGLang   = "172.31.77.23"
	addrDCGM     = "172.31.77.24"
	addrSlurm    = "172.31.77.30"
	addrSecured  = "172.31.77.40"
	addrLoopback = "172.31.77.41"
)

const probeTimeout = 5 * time.Second

// fixtureServices are represented by replayed response shapes rather than the
// real software, because their images are GPU-bound. Named here so the test
// output says so out loud instead of implying coverage we do not have.
var fixtureServices = map[string]string{
	addrVLLM:   "vLLM (fixture: GPU-only image)",
	addrTriton: "Triton (fixture: GPU-only image)",
	addrTorch:  "TorchServe (fixture: unmaintained upstream, multi-GB pull)",
	addrSGLang: "SGLang (fixture: GPU-only image)",
	addrDCGM:   "dcgm-exporter (fixture: needs a real GPU)",
	addrSlurm:  "Slurm (fixture: TCP listener; RG-SLURM-001 is reachability-only)",
}

func TestMain(m *testing.M) {
	if os.Getenv("RAY_GUARD_INTEGRATION") == "" {
		fmt.Println("set RAY_GUARD_INTEGRATION=1 (make test-integration) to run these")
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// scanHost probes one address with the default check set.
func scanHost(t *testing.T, host string) []domain.Finding {
	t.Helper()
	s := scan.New(probeTimeout)
	return scan.Detect(s.ProbeHost(context.Background(), host).Observations)
}

func ruleIDs(findings []domain.Finding) []string {
	var ids []string
	for _, f := range findings {
		ids = append(ids, f.RuleID)
	}
	return ids
}

func findRule(findings []domain.Finding, ruleID string) *domain.Finding {
	for i := range findings {
		if findings[i].RuleID == ruleID {
			return &findings[i]
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// The flagship detection, against real Ray
// ---------------------------------------------------------------------------

// TestRealRayDashboardIsDetected is the single most important test in the
// repo. Ray's dashboard bound to 0.0.0.0 without authentication is
// CVE-2023-48022 / CVE-2025-62593 - the exposure ShadowRay exploited in the
// wild. If this fails, the product's headline claim is false.
func TestRealRayDashboardIsDetected(t *testing.T) {
	findings := scanHost(t, addrRay)

	ray := findRule(findings, "RG-RAY-001")
	if ray == nil {
		t.Fatalf("RG-RAY-001 did not fire against REAL Ray; got %v", ruleIDs(findings))
	}
	if ray.Severity != domain.Critical {
		t.Errorf("unauthenticated Ray must be critical, got %s", ray.Severity)
	}
	if ray.Port != 8265 {
		t.Errorf("expected the dashboard on 8265, got %d", ray.Port)
	}
	if len(ray.CVEs) != 2 {
		t.Errorf("RG-RAY-001 must carry the ShadowRay CVEs, got %v", ray.CVEs)
	}
	if ray.Remediation == "" {
		t.Error("a critical finding without remediation text is not actionable")
	}

	// Ray's client server port is a separate exposure.
	if findRule(findings, "RG-RAY-002") == nil {
		t.Errorf("expected the Ray client port to be flagged; got %v", ruleIDs(findings))
	}
}

// TestRealRayGradesF checks the whole pipeline, not just the rule: a cluster
// with an exposed Ray dashboard must come out at the bottom of the grading
// matrix (CLAUDE.md 10.0) with a rationale that names the cause.
func TestRealRayGradesF(t *testing.T) {
	hs := scan.New(probeTimeout).ProbeHost(context.Background(), addrRay)
	findings := scan.Detect(hs.Observations)
	now := time.Now()
	result := domain.NewScanResult(now.Add(-time.Second), now,
		[]domain.HostSummary{hs.Summary()}, findings)

	if result.Grade != "F" {
		t.Errorf("an exposed Ray dashboard must grade F, got %s (score %d)", result.Grade, result.Score)
	}
	if result.ExitCode() != 6 {
		t.Errorf("expected exit code 6 for a critical finding, got %d", result.ExitCode())
	}
	if !strings.Contains(result.GradeReason, "remote code execution") {
		t.Errorf("the rationale should say what an exposed Ray dashboard means, got %q", result.GradeReason)
	}
}

// ---------------------------------------------------------------------------
// The other real services
// ---------------------------------------------------------------------------

func TestRealServicesAreDetected(t *testing.T) {
	cases := []struct {
		name   string
		host   string
		rule   string
		minSev domain.Severity
	}{
		{"Jupyter (real)", addrJupyter, "RG-JUPYTER-001", domain.High},
		{"MLflow (real)", addrMLflow, "RG-MLFLOW-001", domain.High},
		{"Ollama (real)", addrOllama, "RG-OLLAMA-001", domain.Medium},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := scanHost(t, tc.host)
			f := findRule(findings, tc.rule)
			if f == nil {
				t.Fatalf("%s did not fire against %s; got %v", tc.rule, tc.name, ruleIDs(findings))
			}
			if domain.SeverityRank(f.Severity) > domain.SeverityRank(tc.minSev) {
				t.Errorf("%s: expected at least %s, got %s", tc.rule, tc.minSev, f.Severity)
			}
		})
	}
}

func TestFixtureServicesAreDetected(t *testing.T) {
	cases := []struct {
		host string
		rule string
	}{
		{addrVLLM, "RG-VLLM-001"},
		{addrTriton, "RG-TRITON-001"},
		{addrTorch, "RG-TORCHSERVE-001"},
		{addrSGLang, "RG-SGLANG-001"},
		{addrDCGM, "RG-DCGM-001"},
		{addrSlurm, "RG-SLURM-001"},
	}
	for _, tc := range cases {
		t.Run(fixtureServices[tc.host], func(t *testing.T) {
			t.Logf("NOTE: %s - this is a replayed response shape, not the real service",
				fixtureServices[tc.host])
			findings := scanHost(t, tc.host)
			if findRule(findings, tc.rule) == nil {
				t.Errorf("%s did not fire; got %v", tc.rule, ruleIDs(findings))
			}
		})
	}
}

// The TorchServe fixture also serves 8080, TorchServe's inference port, whose
// only GET is /ping. ray-guard must report that something is listening
// without claiming to know what - naming a random 8080 as TorchServe on a
// buyer's report is the failure mode this behaviour exists to prevent.
func TestPort8080IsReportedWithoutBeingNamed(t *testing.T) {
	findings := scanHost(t, addrTorch)
	f := findRule(findings, "RG-EXPOSURE-001")
	if f == nil {
		t.Fatalf("expected RG-EXPOSURE-001 for the open 8080; got %v", ruleIDs(findings))
	}
	if f.Port != 8080 {
		t.Errorf("RG-EXPOSURE-001 fired on port %d, want 8080", f.Port)
	}
	if f.Severity != domain.Info {
		t.Errorf("severity = %s, want info: an unidentified port is not a judgement", f.Severity)
	}
	for _, id := range ruleIDs(findings) {
		if id == "RG-VLLM-001" || id == "RG-TRITON-001" {
			t.Errorf("8080 was attributed to a named service: %v", ruleIDs(findings))
		}
	}
}

// Triton shares port 8000 with vLLM. Each must be attributed to the host that
// actually answers on its own health path - never both, never the wrong one.
func TestSharedPortAttributionAgainstRunningServices(t *testing.T) {
	vllm := scanHost(t, addrVLLM)
	if findRule(vllm, "RG-TRITON-001") != nil {
		t.Errorf("vLLM host was misattributed as Triton: %v", ruleIDs(vllm))
	}
	triton := scanHost(t, addrTriton)
	if findRule(triton, "RG-VLLM-001") != nil {
		t.Errorf("Triton host was misattributed as vLLM: %v", ruleIDs(triton))
	}
}

// ---------------------------------------------------------------------------
// Negative cases - false positives are how a security tool loses a customer
// ---------------------------------------------------------------------------

// A service that enforces authentication must not raise its exposure rule.
// It does still raise RG-TLS-002, because auth over plaintext is a real
// finding - so assert precisely that, and nothing more.
func TestAuthenticatedServiceRaisesNoExposureFinding(t *testing.T) {
	findings := scanHost(t, addrSecured)

	if f := findRule(findings, "RG-VLLM-001"); f != nil {
		t.Errorf("FALSE POSITIVE: an authenticated service was reported as exposed: %+v", f)
	}
	for _, f := range findings {
		if f.Severity == domain.Critical || f.Severity == domain.High {
			t.Errorf("FALSE POSITIVE: authenticated service produced a %s finding: %s",
				f.Severity, f.RuleID)
		}
	}
	if findRule(findings, "RG-TLS-002") == nil {
		t.Errorf("expected plaintext auth to be flagged as RG-TLS-002; got %v", ruleIDs(findings))
	}
}

// A service bound to loopback inside its own network namespace is reachable
// from nowhere. Scanning it must produce nothing at all.
func TestLoopbackBoundServiceIsInvisible(t *testing.T) {
	findings := scanHost(t, addrLoopback)
	if len(findings) != 0 {
		t.Errorf("FALSE POSITIVE: a loopback-bound service was reported as reachable: %v",
			ruleIDs(findings))
	}
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

// The operator should not have to know the addresses. Sweeping the subnet
// must find the exposed services on its own - this is how a real assessment
// starts.
func TestCIDRDiscoveryFindsTheStack(t *testing.T) {
	hosts, err := scan.ExpandCIDR(subnet, false)
	if err != nil {
		t.Fatalf("expanding %s: %v", subnet, err)
	}

	s := scan.New(2 * time.Second)
	var all []domain.Observation
	results := make(chan []domain.Observation, len(hosts))
	sem := make(chan struct{}, 64)
	for _, h := range hosts {
		h := h
		go func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			results <- s.ProbeHost(context.Background(), h).Observations
		}()
	}
	for range hosts {
		all = append(all, <-results...)
	}

	findings := scan.Detect(all)
	if findRule(findings, "RG-RAY-001") == nil {
		t.Errorf("a subnet sweep missed the exposed Ray dashboard; found %v", ruleIDs(findings))
	}

	hostsFound := map[string]bool{}
	for _, f := range findings {
		hostsFound[f.Host] = true
	}
	if len(hostsFound) < 4 {
		t.Errorf("expected the sweep to find at least 4 affected hosts, found %d: %v",
			len(hostsFound), hostsFound)
	}
	if hostsFound[addrLoopback] {
		t.Error("FALSE POSITIVE: the loopback-bound host was reported by the sweep")
	}
}

// ---------------------------------------------------------------------------
// Coverage - "we reached nothing" must never look like "we found nothing"
// ---------------------------------------------------------------------------

// The highest-consequence failure this tool can have is a false all-clear.
// These run against the live stack so the distinction is proven end to end,
// not just in unit tests over hand-built host lists.
func TestCoverageIsDistinguishedFromCleanliness(t *testing.T) {
	s := scan.New(2 * time.Second)
	ctx := context.Background()

	t.Run("live exposed host responds", func(t *testing.T) {
		if got := s.ProbeHost(ctx, addrRay).State; got != domain.HostResponded {
			t.Errorf("real Ray must register as responded, got %s", got)
		}
	})

	t.Run("unused address in the same subnet does not respond", func(t *testing.T) {
		// .200 is inside the compose subnet but no container holds it.
		if got := s.ProbeHost(ctx, "172.31.77.200").State; got == domain.HostResponded {
			t.Errorf("an unused address must not register as responded, got %s", got)
		}
	})

	t.Run("a scan that reached nothing is inconclusive, not A+", func(t *testing.T) {
		hs := s.ProbeHost(ctx, "172.31.77.200")
		now := time.Now()
		r := domain.NewScanResult(now.Add(-time.Second), now,
			[]domain.HostSummary{hs.Summary()}, scan.Detect(hs.Observations))

		if r.Grade == "A+" {
			t.Error("FALSE ALL-CLEAR: an unreachable host graded A+")
		}
		if !r.Inconclusive() || r.ExitCode() != 7 {
			t.Errorf("want inconclusive with exit 7, got grade %s exit %d", r.Grade, r.ExitCode())
		}
	})

	t.Run("partial coverage is disclosed alongside a real grade", func(t *testing.T) {
		live := s.ProbeHost(ctx, addrRay)
		dark := s.ProbeHost(ctx, "172.31.77.200")
		now := time.Now()
		r := domain.NewScanResult(now.Add(-time.Second), now,
			[]domain.HostSummary{live.Summary(), dark.Summary()},
			scan.Detect(live.Observations))

		if r.Grade != "F" {
			t.Errorf("the exposed host still drives the grade, got %s", r.Grade)
		}
		if !r.PartialCoverage() {
			t.Error("a target that did not answer must be disclosed as a coverage gap")
		}
		if len(r.Unreachable) != 1 {
			t.Errorf("expected 1 unreachable target recorded, got %d", len(r.Unreachable))
		}
	})
}

// ---------------------------------------------------------------------------
// P3, against real responses
// ---------------------------------------------------------------------------

// The unit suite proves no payload escapes from a server we wrote. This
// proves it against what real Ray, Jupyter, MLflow and Ollama actually send -
// including their headers, error pages, and SPA shells.
func TestNoPayloadFromRealServicesReachesFindings(t *testing.T) {
	hosts := []string{addrRay, addrJupyter, addrMLflow, addrOllama}

	s := scan.New(probeTimeout)
	var obs []domain.Observation
	for _, h := range hosts {
		obs = append(obs, s.ProbeHost(context.Background(), h).Observations...)
	}
	findings := scan.Detect(obs)
	if len(findings) == 0 {
		t.Fatal("precondition failed: no findings, so this test would pass vacuously")
	}

	rendered := fmt.Sprintf("%#v%#v", obs, findings)

	// Markers that only appear in real service response bodies: Ray's
	// dashboard HTML, Jupyter's API JSON, MLflow's SPA, Ollama's model list.
	for _, marker := range []string{
		"<!DOCTYPE", "<!doctype", "<html", "<script", "<body",
		"\"models\"", "\"version\"", "static/js", "favicon",
	} {
		if strings.Contains(rendered, marker) {
			t.Errorf("P3 VIOLATION: response content %q from a real service reached our structures", marker)
		}
	}
}

// ---------------------------------------------------------------------------
// Compose sanity
// ---------------------------------------------------------------------------

// If the stack is not actually up, every test above would fail for the wrong
// reason. Fail loudly and early instead.
func TestComposeStackIsUp(t *testing.T) {
	out, err := exec.Command("docker", "compose", "-f", "docker-compose.yml", "ps",
		"--services", "--filter", "status=running").Output()
	if err != nil {
		t.Skipf("could not query compose state: %v", err)
	}
	running := strings.Fields(string(out))
	if len(running) < 6 {
		t.Fatalf("expected the full stack to be running, got %d services: %v", len(running), running)
	}
}
