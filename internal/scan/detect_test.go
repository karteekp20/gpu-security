package scan

import (
	"strings"
	"testing"

	"gpusecurity/internal/domain"
)

func obs(service string, port, status int, unauth bool) domain.Observation {
	return domain.Observation{
		Host: "h", Port: port, Service: service, State: domain.PortOpen,
		HTTPStatus: status, Unauth: unauth, TLS: domain.TLSState{Enabled: true},
	}
}

func TestDetectRayUnauthIsCritical(t *testing.T) {
	f := Detect([]domain.Observation{obs("ray-dashboard", 8265, 200, true)})
	if len(f) != 1 || f[0].RuleID != "RG-RAY-001" || f[0].Severity != domain.Critical {
		t.Fatalf("expected 1 critical RG-RAY-001, got %+v", f)
	}
	if len(f[0].CVEs) != 2 {
		t.Errorf("expected ShadowRay CVEs on RG-RAY-001, got %v", f[0].CVEs)
	}
}

func TestDetectAuthedHTTPSNoFinding(t *testing.T) {
	if f := Detect([]domain.Observation{obs("vllm", 8000, 401, false)}); len(f) != 0 {
		t.Fatalf("expected no findings for an authed TLS service, got %+v", f)
	}
}

func TestDetectAuthedPlaintextRaisesTLSFinding(t *testing.T) {
	o := obs("vllm", 8000, 401, false)
	o.TLS = domain.TLSState{Enabled: false}
	f := Detect([]domain.Observation{o})
	if len(f) != 1 || f[0].RuleID != "RG-TLS-002" {
		t.Fatalf("expected RG-TLS-002 for plaintext auth, got %+v", f)
	}
}

func TestDetectNoTLSNotedOnUnauthFinding(t *testing.T) {
	o := obs("jupyter", 8888, 200, true)
	o.TLS = domain.TLSState{Enabled: false}
	f := Detect([]domain.Observation{o})
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %+v", f)
	}
	if want := "(no TLS)"; !contains(f[0].Detail, want) {
		t.Errorf("expected detail to note %q, got %q", want, f[0].Detail)
	}
}

func TestDetectTLSIssue(t *testing.T) {
	o := domain.Observation{Host: "h", Port: 8265, Service: ServiceTLS, State: domain.PortOpen,
		TLS: domain.TLSState{Enabled: true, Issue: "expired", NotAfter: "2020-01-01"}}
	f := Detect([]domain.Observation{o})
	if len(f) != 1 || f[0].RuleID != "RG-TLS-001" {
		t.Fatalf("expected RG-TLS-001, got %+v", f)
	}
	if !contains(f[0].Detail, "expired") || !contains(f[0].Detail, "2020-01-01") {
		t.Errorf("expected expiry detail, got %q", f[0].Detail)
	}
}

func TestDetectPublicBucket(t *testing.T) {
	o := domain.Observation{Host: "bucket.example.com", Service: ServiceBucket,
		State: domain.PortOpen, HTTPStatus: 200, Unauth: true}
	f := Detect([]domain.Observation{o})
	if len(f) != 1 || f[0].RuleID != "RG-BUCKET-001" || f[0].Severity != domain.High {
		t.Fatalf("expected high RG-BUCKET-001, got %+v", f)
	}
}

func TestDetectPrivateBucketNoFinding(t *testing.T) {
	o := domain.Observation{Host: "bucket.example.com", Service: ServiceBucket,
		State: domain.PortOpen, HTTPStatus: 403}
	if f := Detect([]domain.Observation{o}); len(f) != 0 {
		t.Fatalf("expected no finding for a private bucket, got %+v", f)
	}
}

func TestDetectUnknownServiceIsInfo(t *testing.T) {
	o := domain.Observation{Host: "h", Port: 9000, Service: ServiceUnknown,
		State: domain.PortOpen, HTTPStatus: 404}
	f := Detect([]domain.Observation{o})
	if len(f) != 1 || f[0].RuleID != "RG-EXPOSURE-001" || f[0].Severity != domain.Info {
		t.Fatalf("expected info RG-EXPOSURE-001, got %+v", f)
	}
}

func TestDetectSortsWorstFirst(t *testing.T) {
	f := Detect([]domain.Observation{
		obs("triton-metrics", 8002, 200, true), // low
		obs("ray-dashboard", 8265, 200, true),  // critical
		obs("ollama", 11434, 200, true),        // medium
	})
	if len(f) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(f))
	}
	want := []domain.Severity{domain.Critical, domain.Medium, domain.Low}
	for i, w := range want {
		if f[i].Severity != w {
			t.Errorf("finding %d: want %s, got %s", i, w, f[i].Severity)
		}
	}
}

func TestEveryRuleHasRemediation(t *testing.T) {
	all := []ruleDef{ruleTLSInvalid, ruleTLSPlaintext, ruleBucketPublic, ruleUnknownExposure}
	for _, r := range rules {
		all = append(all, r)
	}
	for _, r := range all {
		if r.ruleID == "" || r.title == "" || r.remediation == "" || r.severity == "" {
			t.Errorf("incomplete rule definition: %+v", r)
		}
		if !strings.HasPrefix(r.ruleID, "RG-") {
			t.Errorf("rule %q does not use the RG- prefix", r.ruleID)
		}
	}
}

func contains(haystack, needle string) bool { return strings.Contains(haystack, needle) }

// TestDetectNewOrchestratorRulesExposed covers the exposed case for each
// detection added after the original set. Ports and health paths were taken
// from the upstream documentation, not from memory - a check on the wrong
// port is a silent miss, which reads as a clean result.
func TestDetectNewOrchestratorRulesExposed(t *testing.T) {
	cases := []struct {
		service  string
		port     int
		wantRule string
		wantSev  domain.Severity
	}{
		{"torchserve-mgmt", 8081, "RG-TORCHSERVE-001", domain.Critical},
		{"torchserve-metrics", 8082, "RG-TORCHSERVE-002", domain.Low},
		{"sglang", 30000, "RG-SGLANG-001", domain.High},
		{"dcgm-exporter", 9400, "RG-DCGM-001", domain.Medium},
	}
	for _, c := range cases {
		t.Run(c.service, func(t *testing.T) {
			f := Detect([]domain.Observation{obs(c.service, c.port, 200, true)})
			if len(f) != 1 {
				t.Fatalf("expected exactly 1 finding, got %+v", f)
			}
			if f[0].RuleID != c.wantRule {
				t.Errorf("rule = %s, want %s", f[0].RuleID, c.wantRule)
			}
			if f[0].Severity != c.wantSev {
				t.Errorf("severity = %s, want %s", f[0].Severity, c.wantSev)
			}
			if f[0].Remediation == "" {
				t.Error("no remediation: a finding without a fix is noise")
			}
		})
	}
}

// TestDetectNewOrchestratorRulesConfiguredCorrectly is the other half of the
// pair CONTRIBUTING.md requires: a rule that cannot tell an exposed service
// from a protected one is worse than no rule.
func TestDetectNewOrchestratorRulesConfiguredCorrectly(t *testing.T) {
	for _, c := range []struct {
		service string
		port    int
	}{
		{"torchserve-mgmt", 8081},
		{"torchserve-metrics", 8082},
		{"sglang", 30000},
		{"dcgm-exporter", 9400},
	} {
		t.Run(c.service, func(t *testing.T) {
			// 401 behind TLS is the correctly-configured shape.
			if f := Detect([]domain.Observation{obs(c.service, c.port, 401, false)}); len(f) != 0 {
				t.Errorf("expected no findings for an authenticated service, got %+v", f)
			}
		})
	}
}

// TestDetectTorchServeCarriesShellTorchCVE: the CVE is most of why the
// management API is Critical rather than High, so it has to reach the report.
func TestDetectTorchServeCarriesShellTorchCVE(t *testing.T) {
	f := Detect([]domain.Observation{obs("torchserve-mgmt", 8081, 200, true)})
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %+v", f)
	}
	found := false
	for _, c := range f[0].CVEs {
		if c == "CVE-2023-43654" {
			found = true
		}
	}
	if !found {
		t.Errorf("CVEs = %v, want CVE-2023-43654 (ShellTorch)", f[0].CVEs)
	}
}

// TestPort8080IsProbedButNeverAttributed pins a deliberate decision. /ping is
// the only GET TorchServe's inference API offers, and a 200 on /ping on 8080
// would name a large fraction of the web as TorchServe. So 8080 is swept and
// reported at Info without a service name: misattribution on a buyer's
// report costs more than the missing name does, and "what is on 8080?" is a
// question the operator can answer in the room.
func TestPort8080IsProbedButNeverAttributed(t *testing.T) {
	var found bool
	for _, c := range DefaultChecks() {
		if c.Port != 8080 {
			continue
		}
		found = true
		if c.Service != ServiceUnknown {
			t.Errorf("8080 is attributed to %q; 8080 is shared by TorchServe, TGI, LocalAI and most model servers, so it must stay unattributed",
				c.Service)
		}
	}
	if !found {
		t.Error("nothing probes 8080; an open model-server port should at least be reported at Info")
	}

	// And the resulting finding must be the Info-level "we did not identify
	// this", not a guess.
	f := Detect([]domain.Observation{obs(ServiceUnknown, 8080, 404, false)})
	if len(f) != 1 || f[0].RuleID != "RG-EXPOSURE-001" || f[0].Severity != domain.Info {
		t.Errorf("expected one Info RG-EXPOSURE-001 for an unidentified 8080, got %+v", f)
	}
}

// TestTLSCertificateAndVersionAreSeparateFindings. They have different fixes -
// replace the certificate, disable the protocol - and they travel together in
// the field, so collapsing them to one finding means the operator fixes the
// certificate, re-scans, and only then hears about TLS 1.0.
func TestTLSCertificateAndVersionAreSeparateFindings(t *testing.T) {
	obs := []domain.Observation{{
		Host: "10.0.0.5", Port: 8443, Service: ServiceTLS, State: domain.PortOpen,
		TLS: domain.TLSState{Enabled: true, Issue: "self-signed", NotAfter: "2027-01-01", Version: "1.0"},
	}}
	got := map[string]string{}
	for _, f := range Detect(obs) {
		got[f.RuleID] = f.Detail
	}
	if _, ok := got["RG-TLS-001"]; !ok {
		t.Error("the certificate problem was not reported")
	}
	if detail, ok := got["RG-TLS-003"]; !ok {
		t.Error("the obsolete protocol version was not reported")
	} else if !strings.Contains(detail, "1.0") || !strings.Contains(detail, "RFC 8996") {
		t.Errorf("the version finding does not say what is wrong: %q", detail)
	}
}

func TestModernTLSRaisesNoTransportFinding(t *testing.T) {
	for _, v := range []string{"1.2", "1.3"} {
		obs := []domain.Observation{{
			Host: "10.0.0.5", Port: 8443, Service: ServiceTLS, State: domain.PortOpen,
			TLS: domain.TLSState{Enabled: true, Version: v},
		}}
		if got := Detect(obs); len(got) != 0 {
			t.Errorf("TLS %s raised %d finding(s): %+v", v, len(got), got)
		}
	}
}

// TestUnknownTLSVersionIsNotGuessedAt: a version we cannot name must not be
// called obsolete. A wrong TLS finding on a buyer's report is expensive, and a
// future TLS 1.4 would otherwise be reported as deprecated.
func TestUnknownTLSVersionIsNotGuessedAt(t *testing.T) {
	obs := []domain.Observation{{
		Host: "10.0.0.5", Port: 8443, Service: ServiceTLS, State: domain.PortOpen,
		TLS: domain.TLSState{Enabled: true, Version: ""},
	}}
	if got := Detect(obs); len(got) != 0 {
		t.Errorf("an unrecognized version raised %d finding(s): %+v", len(got), got)
	}
}
