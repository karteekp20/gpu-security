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
	// One asserted, one cited-but-unconfirmed. This used to expect 2 asserted,
	// which was the defect: CVE-2025-62593 is fixed in Ray 2.52.0 and this
	// scan never reads a version.
	if len(f[0].CVEs) != 1 || len(f[0].UnconfirmedCVEs) != 1 {
		t.Errorf("expected 1 asserted + 1 unconfirmed ShadowRay CVE on RG-RAY-001, got %v / %+v",
			f[0].CVEs, f[0].UnconfirmedCVEs)
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
	// ShellTorch must be CITED, but as unconfirmed rather than asserted. NVD
	// bounds CVE-2023-43654 at 0.8.2 and this rule fires on reachability
	// alone, so asserting it on, say, 0.12.0 is a claim the operator refutes
	// with one command. Dropping the citation would be the other error: the
	// behaviour it describes is still the default, so the reader needs it.
	found := false
	for _, c := range f[0].UnconfirmedCVEs {
		if c.ID == "CVE-2023-43654" {
			found = true
		}
	}
	if !found {
		t.Errorf("unconfirmed CVEs = %+v, want CVE-2023-43654 (ShellTorch) cited there",
			f[0].UnconfirmedCVEs)
	}
	if len(f[0].CVEs) != 0 {
		t.Errorf("asserted CVEs = %v, want none", f[0].CVEs)
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

// advisoryFacts is what the published advisories say about every CVE this
// scanner cites, recorded here independently of the rule table so the rule
// table can be checked against something it does not itself define. Read from
// NVD on 2026-11-01; the value is the fixed version the advisory names, or ""
// when it names none.
//
// This is deliberately not derived from detect.go. A test that asked the rule
// table to agree with itself would pass no matter what the table claimed - and
// the defect this guards against is exactly someone adding a CVE to a rule
// because it is famous, without checking whether it is version-gated.
var advisoryFacts = map[string]string{
	// Disputed, and NVD lists no fixed version: the vendor's position is that
	// Ray is for trusted networks. So reachability is the whole condition.
	"CVE-2023-48022": "",
	"CVE-2025-62593": "2.52.0",
	"CVE-2023-43654": "0.8.2",
}

func TestEveryCitedCVEHasItsAdvisoryFactsRecorded(t *testing.T) {
	for id, r := range goRules() {
		for _, c := range r.cves {
			want, ok := advisoryFacts[c.id]
			if !ok {
				t.Errorf("%s cites %s, which has no entry in advisoryFacts. Look the "+
					"advisory up and record whether it names a fixed version before "+
					"shipping the citation - that fact is what decides whether we may "+
					"assert it", id, c.id)
				continue
			}
			if c.fixedIn != want {
				t.Errorf("%s cites %s with fixedIn %q, but the advisory says %q",
					id, c.id, c.fixedIn, want)
			}
		}
	}
}

// TestAVersionGatedCVEIsNeverAssertedOnAFinding walks the real detection path
// rather than the rule table, because the table is only half the story: the
// split happens in mkFinding, and that is what reaches report.json.
func TestAVersionGatedCVEIsNeverAssertedOnAFinding(t *testing.T) {
	gated := map[string]string{}
	for id, fixed := range advisoryFacts {
		if fixed != "" {
			gated[id] = fixed
		}
	}
	if len(gated) == 0 {
		t.Fatal("no version-gated CVE in advisoryFacts; this test would prove nothing")
	}

	// Every service whose rule cites anything, through Detect, as a scan does.
	var obsv []domain.Observation
	port := 9000
	for service, r := range rules {
		if len(r.cves) > 0 {
			// The port is arbitrary: Detect keys off the service. It only has
			// to differ per observation so the findings stay distinct.
			obsv = append(obsv, obs(service, port, 200, true))
			port++
		}
	}
	findings := Detect(obsv)
	if len(findings) == 0 {
		t.Fatal("no findings produced; the CVE-carrying rules did not fire")
	}

	var sawUnconfirmed int
	for _, f := range findings {
		for _, cve := range f.CVEs {
			if fixed, bad := gated[cve]; bad {
				t.Errorf("%s asserts %s, which the advisory says is fixed in %s. This "+
					"scan never determines a version, so that is a claim about "+
					"something nobody looked at - it belongs in cves_unconfirmed",
					f.RuleID, cve, fixed)
			}
		}
		for _, u := range f.UnconfirmedCVEs {
			sawUnconfirmed++
			if _, bad := gated[u.ID]; !bad {
				t.Errorf("%s lists %s as unconfirmed, but the advisory names no fixed "+
					"version, so reachability is the whole condition and it should be "+
					"asserted", f.RuleID, u.ID)
			}
			for _, a := range f.CVEs {
				if a == u.ID {
					t.Errorf("%s has %s in both lists", f.RuleID, u.ID)
				}
			}
		}
	}
	if sawUnconfirmed == 0 {
		t.Error("no unconfirmed CVE reached any finding, so the split is not wired up")
	}
}

func TestEveryUnconfirmedCVESaysWhatToCheck(t *testing.T) {
	for id, r := range goRules() {
		for _, c := range r.cves {
			if c.asserted() {
				if c.why != "" {
					t.Errorf("%s: %s is asserted but carries a `why`, which only "+
						"applies to a CVE we are declining to assert", id, c.id)
				}
				continue
			}
			// A bare label ("version-specific") sends the reader back to us
			// mid-engagement. The text has to name the check that closes it.
			if len(c.why) < 60 {
				t.Errorf("%s: %s has no usable `why` (%q). It must name the check that "+
					"settles the CVE, so a reader can close it without asking us",
					id, c.id, c.why)
			}
		}
	}
}

// TestTheRayRuleAssertsOnlyTheUnpatchableCVE pins the specific pair this
// change was made for, so a future edit that re-adds the version-gated CVE to
// the asserted list fails by name rather than only through the general rule.
func TestTheRayRuleAssertsOnlyTheUnpatchableCVE(t *testing.T) {
	f := Detect([]domain.Observation{obs("ray-dashboard", 8265, 200, true)})
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if got := f[0].CVEs; len(got) != 1 || got[0] != "CVE-2023-48022" {
		t.Errorf("asserted CVEs = %v, want only CVE-2023-48022", got)
	}
	if got := f[0].UnconfirmedCVEs; len(got) != 1 || got[0].ID != "CVE-2025-62593" {
		t.Errorf("unconfirmed CVEs = %+v, want only CVE-2025-62593", got)
	}
}

// TestTheTorchServeRuleAssertsNoCVE records that this is intended, not a gap.
// The rule is Critical on what it observed - a management API that registers a
// model from any URL the caller names - and that does not depend on the CVE.
func TestTheTorchServeRuleAssertsNoCVE(t *testing.T) {
	f := Detect([]domain.Observation{obs("torchserve-mgmt", 8081, 200, true)})
	if len(f) != 1 || f[0].Severity != domain.Critical {
		t.Fatalf("expected 1 critical finding, got %+v", f)
	}
	if len(f[0].CVEs) != 0 {
		t.Errorf("asserted CVEs = %v; CVE-2023-43654 is bounded at 0.8.2 by NVD and "+
			"this rule fires on reachability alone", f[0].CVEs)
	}
	if len(f[0].UnconfirmedCVEs) != 1 {
		t.Fatalf("expected CVE-2023-43654 cited as unconfirmed, got %+v", f[0].UnconfirmedCVEs)
	}
}
