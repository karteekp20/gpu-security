package scan

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gpusecurity/internal/domain"
)

// The L1 rule set now exists twice: as Go in detect.go, which is what ships in
// the static binary, and as Rego in /policies, which is what the Phase-1
// control plane evaluates and what the signed credential is issued from.
//
// That duplication is deliberate - OPA cannot go into the zero-dependency
// air-gap binary (CLAUDE.md §14, §15) - but two implementations of one rule set
// drift, and the drift would be invisible until a customer's report and their
// credential disagreed about a severity. These tests make drift a build
// failure instead.
//
// They are intentionally structural: they do not evaluate Rego (that is
// `opa test`, which runs in CI). They check that the two sides agree on the
// facts a buyer sees - the rule IDs, titles, severities, remediation text and
// CVEs - and that every rule carries both halves of its sentinel plus a test.

const policiesDir = "../../policies"

type regoRule struct {
	path     string
	pkg      string
	metadata struct {
		ID          string   `json:"id"`
		Title       string   `json:"title"`
		Severity    string   `json:"severity"`
		CVE         []string `json:"cve"`
		Remediation string   `json:"remediation"`
		Compliance  []string `json:"compliance"`
	}
	hasFinding      bool
	hasVerification bool
}

var (
	pkgRe  = regexp.MustCompile(`(?m)^package\s+(\S+)`)
	quoted = regexp.MustCompile(`"([^"]+)"`)
)

// regoRuleFiles lists the rule files, walking the domains §8 defines. A domain
// that is not built yet is skipped rather than failed: fabric, hardware,
// attestation and k8s rules arrive with L2/L3, and this test should not demand
// them early.
func regoRuleFiles(t *testing.T) []string {
	t.Helper()
	var files []string
	for _, domain := range []string{"orchestrator", "cloud", "fabric", "hardware", "attestation", "k8s"} {
		dir := filepath.Join(policiesDir, domain)
		entries, err := os.ReadDir(dir)
		if os.IsNotExist(err) {
			continue // a domain that is not built yet is not an error
		}
		if err != nil {
			t.Fatalf("reading %s: %v", dir, err)
		}
		for _, e := range entries {
			name := e.Name()
			if !strings.HasSuffix(name, ".rego") || strings.HasSuffix(name, "_test.rego") {
				continue
			}
			files = append(files, filepath.Join(dir, name))
		}
	}
	sort.Strings(files)
	return files
}

// extractMetadata pulls the finding_metadata object out of a rule file. The
// generator writes it as strict JSON inside the braces precisely so this can
// read it without an OPA dependency; a rule that hand-edits it into something
// JSON cannot parse fails here, which is the intended feedback.
func extractMetadata(src string) (string, error) {
	i := strings.Index(src, "finding_metadata")
	if i < 0 {
		return "", fmt.Errorf("no finding_metadata")
	}
	open := strings.Index(src[i:], "{")
	if open < 0 {
		return "", fmt.Errorf("finding_metadata has no object")
	}
	start := i + open
	depth := 0
	for j := start; j < len(src); j++ {
		switch src[j] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return src[start : j+1], nil
			}
		}
	}
	return "", fmt.Errorf("unbalanced braces in finding_metadata")
}

func parseRegoRules(t *testing.T) map[string]regoRule {
	t.Helper()
	rules := map[string]regoRule{}
	for _, path := range regoRuleFiles(t) {
		b, err := os.ReadFile(path) // #nosec G304 -- fixed test-local paths
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		src := string(b)
		var r regoRule
		r.path = path
		if m := pkgRe.FindStringSubmatch(src); m != nil {
			r.pkg = m[1]
		}
		r.hasFinding = strings.Contains(src, "finding_condition")
		r.hasVerification = strings.Contains(src, "verification_condition")

		raw, err := extractMetadata(src)
		if err != nil {
			t.Errorf("%s: %v", path, err)
			continue
		}
		if err := json.Unmarshal([]byte(raw), &r.metadata); err != nil {
			t.Errorf("%s: finding_metadata is not parseable as JSON: %v", path, err)
			continue
		}
		if prev, dup := rules[r.metadata.ID]; dup {
			t.Errorf("rule ID %s is used twice: %s and %s", r.metadata.ID, prev.path, path)
		}
		rules[r.metadata.ID] = r
	}
	return rules
}

// goRules flattens detect.go's two tables into one map keyed by rule ID.
func goRules() map[string]ruleDef {
	out := map[string]ruleDef{}
	for _, r := range rules {
		out[r.ruleID] = r
	}
	for _, r := range []ruleDef{
		ruleTLSInvalid, ruleTLSPlaintext, ruleTLSObsolete, ruleBucketPublic, ruleUnknownExposure,
	} {
		out[r.ruleID] = r
	}
	return out
}

// TestEveryRegoRuleHasBothHalvesOfItsSentinel is the check CI exists for
// (CLAUDE.md §8): a rule that detects but cannot verify is not shippable,
// because a credential is only worth signing if closures are verified by us.
func TestEveryRegoRuleHasBothHalvesOfItsSentinel(t *testing.T) {
	regoRules := parseRegoRules(t)
	if len(regoRules) == 0 {
		t.Fatal("no Rego rules found under /policies; the parity test is not actually checking anything")
	}
	for id, r := range regoRules {
		if !r.hasFinding {
			t.Errorf("%s (%s) has no finding_condition", id, r.path)
		}
		if !r.hasVerification {
			t.Errorf("%s (%s) has no verification_condition - a rule that cannot "+
				"verify its own fix may not ship (CLAUDE.md §8)", id, r.path)
		}
	}
}

// TestEveryRegoRuleHasATest enforces the other half of §8: both paths asserted.
// It checks the file exists and names both conditions; `opa test` in CI proves
// the assertions actually pass.
func TestEveryRegoRuleHasATest(t *testing.T) {
	for _, path := range regoRuleFiles(t) {
		testPath := strings.TrimSuffix(path, ".rego") + "_test.rego"
		b, err := os.ReadFile(testPath) // #nosec G304 -- fixed test-local paths
		if os.IsNotExist(err) {
			t.Errorf("%s has no %s", filepath.Base(path), filepath.Base(testPath))
			continue
		}
		if err != nil {
			t.Fatalf("reading %s: %v", testPath, err)
		}
		src := string(b)
		for _, want := range []string{"finding_condition", "verification_condition"} {
			if !strings.Contains(src, want) {
				t.Errorf("%s never exercises %s", filepath.Base(testPath), want)
			}
		}
		// The sentinel hazard this library is built around: a closure that a
		// never-reached host satisfies would let "we could not look" become
		// "we attest it is fixed", over our signature.
		if !strings.Contains(src, "host_never_reached") && !strings.Contains(src, "unreachable") {
			t.Errorf("%s has no case proving an unreached host does NOT close the "+
				"finding; that is the one test this library cannot omit", filepath.Base(testPath))
		}
	}
}

// TestGoAndRegoRuleSetsAgree is the drift gate: same IDs, same buyer-facing
// text, same severities, same CVEs.
func TestGoAndRegoRuleSetsAgree(t *testing.T) {
	regoRules := parseRegoRules(t)
	goSet := goRules()

	var missingInRego, missingInGo []string
	for id := range goSet {
		if _, ok := regoRules[id]; !ok {
			missingInRego = append(missingInRego, id)
		}
	}
	for id := range regoRules {
		if _, ok := goSet[id]; !ok {
			missingInGo = append(missingInGo, id)
		}
	}
	sort.Strings(missingInRego)
	sort.Strings(missingInGo)
	if len(missingInRego) > 0 {
		t.Errorf("in detect.go but not in /policies: %v", missingInRego)
	}
	if len(missingInGo) > 0 {
		t.Errorf("in /policies but not in detect.go: %v", missingInGo)
	}

	for id, g := range goSet {
		r, ok := regoRules[id]
		if !ok {
			continue
		}
		if r.metadata.Title != g.title {
			t.Errorf("%s title differs:\n  go:   %q\n  rego: %q", id, g.title, r.metadata.Title)
		}
		if r.metadata.Severity != string(g.severity) {
			t.Errorf("%s severity differs: go %q, rego %q", id, g.severity, r.metadata.Severity)
		}
		if r.metadata.Remediation != g.remediation {
			t.Errorf("%s remediation differs (a buyer reads this text):\n  go:   %q\n  rego: %q",
				id, g.remediation, r.metadata.Remediation)
		}
		gotCVEs := append([]string(nil), r.metadata.CVE...)
		wantCVEs := append([]string(nil), g.cves...)
		sort.Strings(gotCVEs)
		sort.Strings(wantCVEs)
		if strings.Join(gotCVEs, ",") != strings.Join(wantCVEs, ",") {
			t.Errorf("%s CVEs differ: go %v, rego %v", id, wantCVEs, gotCVEs)
		}
		if len(r.metadata.Compliance) == 0 {
			t.Errorf("%s has no compliance mappings; a single scan is supposed to "+
				"produce multi-framework evidence (CLAUDE.md §11)", id)
		}
		if sev := domain.Severity(r.metadata.Severity); !validSeverity(sev) {
			t.Errorf("%s severity %q is not one of the five domain severities", id, sev)
		}
	}
}

// TestRegoKnownServiceSetMatchesTheScanner guards RG-TLS-002, which applies
// only to services the library can name. If the scanner learns a service and
// the Rego set is not updated, that rule silently stops covering it.
func TestRegoKnownServiceSetMatchesTheScanner(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(policiesDir, "lib", "evidence.rego"))
	if err != nil {
		t.Fatalf("reading the shared library: %v", err)
	}
	src := string(b)
	i := strings.Index(src, "known_services :=")
	if i < 0 {
		t.Fatal("lib/evidence.rego no longer defines known_services")
	}
	end := strings.Index(src[i:], "}")
	if end < 0 {
		t.Fatal("known_services set is unterminated")
	}
	var got []string
	for _, m := range quoted.FindAllStringSubmatch(src[i:i+end], -1) {
		got = append(got, m[1])
	}
	var want []string
	for service := range rules {
		want = append(want, service)
	}
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("known_services differs from detect.go's rule table:\n  rego: %v\n  go:   %v", got, want)
	}
}

func validSeverity(s domain.Severity) bool {
	switch s {
	case domain.Critical, domain.High, domain.Medium, domain.Low, domain.Info:
		return true
	}
	return false
}

// TestAggregateWalksEveryPolicyDomain guards the one thing that cannot be
// expressed inside the aggregator: it lists its domain paths literally,
// because a rule-valued set made OPA treat the walk as possibly recursive.
// Literal paths mean a new domain has to be wired in by hand, and forgetting
// would silently drop a whole tier of rules from every evaluation - the
// control plane would return "no findings" for L2 and L3 and look correct.
func TestAggregateWalksEveryPolicyDomain(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(policiesDir, "aggregate.rego"))
	if err != nil {
		t.Fatalf("reading the aggregator: %v", err)
	}
	src := string(b)

	entries, err := os.ReadDir(policiesDir)
	if err != nil {
		t.Fatalf("reading %s: %v", policiesDir, err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		switch e.Name() {
		case "lib", "tools", "testdata":
			continue // not rule domains
		}
		// A domain directory with no rules in it yet does not need wiring.
		rules, err := filepath.Glob(filepath.Join(policiesDir, e.Name(), "*.rego"))
		if err != nil {
			t.Fatalf("globbing %s: %v", e.Name(), err)
		}
		hasRule := false
		for _, r := range rules {
			if !strings.HasSuffix(r, "_test.rego") {
				hasRule = true
				break
			}
		}
		if !hasRule {
			continue
		}
		if !strings.Contains(src, "data.gpusecurity."+e.Name()+"[") {
			t.Errorf("policies/%s/ holds rules but aggregate.rego never walks "+
				"data.gpusecurity.%s - every evaluation would silently skip them",
				e.Name(), e.Name())
		}
	}
}

// stateComparisonRe matches a comparison between one of the scanner's state
// fields and a string literal, in either the `obs.` (library) or `input.`
// (rule) spelling, and with `==`, `!=` or `in {...}`.
var stateComparisonRe = regexp.MustCompile(
	`(?:obs|input)\.(host_state|state|tls\.version)\s*(?:==|!=|in)\s*(\{[^}]*\}|"[^"]*")`)

// hostReachedRe isolates the one comparison the signed credential rests on.
var hostReachedRe = regexp.MustCompile(
	`host_reached\(obs\)\s+if\s+obs\.host_state\s*==\s*"([^"]*)"`)

// TestRegoStateVocabularyMatchesTheScanner pins the strings the rule library
// compares against to the strings the scanner actually emits.
//
// This exists because of a measured hole, not a hypothetical one. Renaming
// domain.HostResponded's value from "responded" to anything else left the
// whole Go suite green, regenerated the finding corpus cleanly, and - before
// the closure corpus existed - kept the Rego differential at 26/26, because no
// finding_condition reads host_state. Only closures do. Every one of the 19
// verification sentinels would have become permanently unsatisfiable: no
// finding would ever auto-close, the credential's verified-closure machinery
// would be dead, and every gate would have reported healthy.
//
// test/policy-corpus/closures.json now catches that in CI. This catches it
// locally, with no OPA installed, which is where it should be caught.
func TestRegoStateVocabularyMatchesTheScanner(t *testing.T) {
	vocab := map[string]map[string]bool{
		"host_state": {
			string(domain.HostResponded):   true,
			string(domain.HostNoResponse):  true,
			string(domain.HostUnresolved):  true,
			string(domain.HostProbeFailed): true,
		},
		"state": {
			string(domain.PortOpen):     true,
			string(domain.PortClosed):   true,
			string(domain.PortFiltered): true,
		},
		"tls.version": {},
	}
	// The TLS versions the scanner can report, from the function that reports
	// them. "" is excluded deliberately: an unknown future version is recorded
	// as empty rather than guessed at, and no rule may treat that as modern.
	for _, v := range []uint16{
		tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12, tls.VersionTLS13,
	} {
		vocab["tls.version"][tlsVersionName(v)] = true
	}

	paths := append(regoRuleFiles(t), filepath.Join(policiesDir, "lib", "evidence.rego"))
	var checked int
	for _, path := range paths {
		b, err := os.ReadFile(path) // #nosec G304 -- fixed test-local paths
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		for _, m := range stateComparisonRe.FindAllStringSubmatch(string(b), -1) {
			field, operand := m[1], m[2]
			for _, lit := range quoted.FindAllStringSubmatch(operand, -1) {
				checked++
				if !vocab[field][lit[1]] {
					t.Errorf("%s compares %s against %q, which the scanner never emits. "+
						"Either the rule is dead code or an enum in internal/domain was "+
						"renamed without the rules following; both make the rule silently "+
						"unsatisfiable.", filepath.Base(path), field, lit[1])
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("matched no state comparisons at all; the regex has drifted from the " +
			"rule library's spelling and this test is no longer checking anything")
	}

	// And the load-bearing one, by name: the precondition every closure chains
	// to must be the state the scanner uses for "this host answered".
	ev, err := os.ReadFile(filepath.Join(policiesDir, "lib", "evidence.rego")) // #nosec G304 -- fixed test-local paths
	if err != nil {
		t.Fatalf("reading evidence.rego: %v", err)
	}
	m := hostReachedRe.FindStringSubmatch(string(ev))
	if m == nil {
		t.Fatal("lib/evidence.rego no longer defines host_reached as a comparison " +
			"against obs.host_state; every verification sentinel chains to it, so a " +
			"change here changes what the signed credential means")
	}
	if m[1] != string(domain.HostResponded) {
		t.Errorf("host_reached requires host_state == %q but the scanner reports %q "+
			"for a host that answered; no finding could ever auto-close",
			m[1], domain.HostResponded)
	}
}

// TestPolicyBundleShipsNoDataFiles keeps test fixtures out of the policy
// bundle.
//
// OPA loads every .json/.yaml it finds under a bundle path into the data
// document, mounted at a path derived from the directory. So the differential
// corpus sitting in policies/testdata/ was silently becoming part of the
// evaluated policy data - harmless while the aggregate only walks
// data.gpusecurity, but /policies is also what ships as the signed air-gap
// update bundle (CLAUDE.md §13), which means a fixture would have been
// delivered to a customer as policy data. Adding a second corpus turned the
// quiet version into a hard failure (`conflicting values at
// data.testdata._comment`), which is how it was found.
func TestPolicyBundleShipsNoDataFiles(t *testing.T) {
	err := filepath.Walk(policiesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		switch strings.ToLower(filepath.Ext(path)) {
		case ".json", ".yaml", ".yml":
			t.Errorf("%s is inside the policy bundle, so OPA loads it into the data "+
				"document and the air-gap bundle (§13) would ship it to a customer as "+
				"policy data. Test fixtures belong under /test.", path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", policiesDir, err)
	}
}
