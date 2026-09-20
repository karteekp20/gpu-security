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
