package scan

import (
	"strings"
	"testing"

	"gpusecurity/internal/domain"
)

// Evidence levels and bases (G3). Two findings at the same severity can rest
// on very different evidence, and until now nothing in the report said so.
// These tests pin the three properties that make the field worth having:
// every rule states a basis, no rule overstates the tier, and the path a
// reader would re-run can never contain something an operator typed.

func validBasis(b domain.EvidenceBasis) bool {
	switch b {
	case domain.BasisServiceAPI, domain.BasisMetricsEndpoint,
		domain.BasisGenericPath, domain.BasisPortOnly, domain.BasisTransport:
		return true
	}
	return false
}

// TestEveryRuleHasAValidEvidenceBasis is the fall-through guard. basisForService
// returns BasisPortOnly for a service with no check, which is the conservative
// answer rather than the right one - if a rule ever reaches it, the rule needs
// an entry in nonServiceBasis instead of a silent understatement.
func TestEveryRuleHasAValidEvidenceBasis(t *testing.T) {
	for id := range goRules() {
		b := evidenceBasisForRule(id)
		if !validBasis(b) {
			t.Errorf("%s: evidence basis %q is not one of the five bases", id, b)
			continue
		}
		_, isService := serviceForRule[id]
		_, pinned := nonServiceBasis[id]
		if !isService && !pinned {
			t.Errorf("%s: not a service rule and not in nonServiceBasis, so its basis "+
				"fell through to the conservative default; pin it explicitly", id)
		}
	}
}

// everyRuleObservations returns one observation per detection path, so a sweep
// covers all 19 rules rather than the handful a hand-written case would.
func everyRuleObservations() []domain.Observation {
	obs := []domain.Observation{
		// TLS: bad certificate AND obsolete version, which is one observation
		// raising two findings (RG-TLS-001, RG-TLS-003).
		{Host: "h1", Port: 8265, Service: ServiceTLS, State: domain.PortOpen,
			TLS: domain.TLSState{Enabled: true, Issue: "self-signed", Version: "1.0"}},
		// RG-TLS-002: auth enforced, no TLS.
		{Host: "h2", Port: 5000, Service: "mlflow", State: domain.PortOpen, HTTPStatus: 401},
		// RG-BUCKET-001.
		{Host: "bucket.example.invalid", Service: ServiceBucket, State: domain.PortOpen,
			HTTPStatus: 200, Unauth: true},
		// RG-EXPOSURE-001.
		{Host: "h3", Port: 8080, Service: ServiceUnknown, State: domain.PortOpen, HTTPStatus: 404},
	}
	// Every service rule: a 2xx without auth for HTTP checks, and a
	// reachability-only observation for the tcp ones.
	for service := range rules {
		c := checksByService[service]
		o := domain.Observation{
			Host: "h-" + service, Port: c.Port, Service: service, State: domain.PortOpen,
		}
		if c.Scheme == "http" {
			o.HTTPStatus = 200
			o.Unauth = true
		} else {
			o.Note = "control/RPC port; speaks no HTTP"
		}
		obs = append(obs, o)
	}
	return obs
}

// TestL1CannotExceedObserved is the evidence-level sibling of
// TestL1CannotEarnAPlus. An agentless probe sees a service answer, once, from
// outside: that is `observed` and nothing further. The risk this guards is the
// same one tier-scoped grades guard - a Phase-1 credential issued off a
// finding that claims its config was read or its hardware attested, when all
// that happened was an HTTP 200.
func TestL1CannotExceedObserved(t *testing.T) {
	findings := Detect(everyRuleObservations())
	if len(findings) == 0 {
		t.Fatal("no findings produced; the sweep cannot prove anything")
	}
	seen := map[string]bool{}
	for _, f := range findings {
		seen[f.RuleID] = true
		if f.Evidence.Level != domain.EvidenceObserved {
			t.Errorf("%s on %s: evidence level is %q, but L1 observes and cannot verify",
				f.RuleID, f.Host, f.Evidence.Level)
		}
		if f.Evidence.Level != domain.L1EvidenceCeiling {
			t.Errorf("%s: level %q exceeds the stated L1 ceiling %q",
				f.RuleID, f.Evidence.Level, domain.L1EvidenceCeiling)
		}
		if !validBasis(f.Evidence.Basis) {
			t.Errorf("%s: basis %q is not one of the five bases", f.RuleID, f.Evidence.Basis)
		}
	}
	// The sweep is only worth anything if it actually reached every rule.
	for id := range goRules() {
		if !seen[id] {
			t.Errorf("%s produced no finding in the sweep, so its evidence was never checked", id)
		}
	}
}

// TestProbedPathComesOnlyFromTheCheckTable is the P3/P9 guard on the new
// field. ProbedPath exists so a reader can re-run the request themselves, and
// the tempting implementation is "whatever we requested" - which for the
// bucket probe is a URL the operator typed, and a bucket URL routinely carries
// the customer's name. A new field must not become a new route for that into
// the report, and from there into the benchmark snapshot.
func TestProbedPathComesOnlyFromTheCheckTable(t *testing.T) {
	const hostile = "<script>alert(1)</script>/secret-customer-name"

	allowed := map[string]bool{"": true}
	for _, c := range defaultChecks() {
		allowed[c.Path] = true
	}

	obs := everyRuleObservations()
	for i := range obs {
		obs[i].Host = hostile
		obs[i].Note = hostile
	}
	// The bucket case is the pointed one: its "host" IS operator input.
	obs = append(obs, domain.Observation{
		Host: hostile, Service: ServiceBucket, State: domain.PortOpen,
		HTTPStatus: 200, Unauth: true,
	})

	for _, f := range Detect(obs) {
		if !allowed[f.Evidence.ProbedPath] {
			t.Errorf("%s: probed_path %q is not a path from the check table",
				f.RuleID, f.Evidence.ProbedPath)
		}
		if strings.Contains(f.Evidence.ProbedPath, "script") ||
			strings.Contains(f.Evidence.ProbedPath, "customer") {
			t.Errorf("%s: probed_path carried scanned input: %q", f.RuleID, f.Evidence.ProbedPath)
		}
	}
}

// TestTheWeakestEvidenceIsDistinguishable is G3's actual point, as a test.
// Before this field, MLflow-on-"/" and Ollama-on-"/api/tags" produced findings
// that looked equally well-evidenced, and a reader who spot-checked the weak
// one first had no way to know it was the weak one.
func TestTheWeakestEvidenceIsDistinguishable(t *testing.T) {
	byRule := map[string]domain.Finding{}
	for _, f := range Detect(everyRuleObservations()) {
		byRule[f.RuleID] = f
	}

	for _, tc := range []struct {
		rule      string
		wantBasis domain.EvidenceBasis
		wantPath  string
		why       string
	}{
		{"RG-MLFLOW-001", domain.BasisGenericPath, "/",
			"MLflow is identified by its root page, which any web server answers"},
		{"RG-OLLAMA-001", domain.BasisServiceAPI, "/api/tags",
			"Ollama's own API; nothing else serves this path"},
		{"RG-RAY-001", domain.BasisServiceAPI, "/api/version",
			"the flagship critical must rest on Ray's own dashboard API"},
		{"RG-DCGM-001", domain.BasisMetricsEndpoint, "/metrics",
			"exporters answer 2xx on any path, so they skip the wildcard control"},
		{"RG-SLURM-001", domain.BasisPortOnly, "",
			"reachability only; no path to state and nothing identified"},
		{"RG-TLS-001", domain.BasisTransport, "",
			"the evidence is the handshake, not a path"},
	} {
		f, ok := byRule[tc.rule]
		if !ok {
			t.Errorf("%s not produced by the sweep", tc.rule)
			continue
		}
		if f.Evidence.Basis != tc.wantBasis {
			t.Errorf("%s basis = %q, want %q (%s)", tc.rule, f.Evidence.Basis, tc.wantBasis, tc.why)
		}
		if f.Evidence.ProbedPath != tc.wantPath {
			t.Errorf("%s probed_path = %q, want %q", tc.rule, f.Evidence.ProbedPath, tc.wantPath)
		}
	}

	// The whole point, stated as one assertion: same tier, same kind of
	// exposure, different strength of evidence.
	if byRule["RG-MLFLOW-001"].Evidence.Basis == byRule["RG-OLLAMA-001"].Evidence.Basis {
		t.Error("MLflow and Ollama report the same evidence basis; the field " +
			"is not discriminating what it was added to discriminate")
	}
}
