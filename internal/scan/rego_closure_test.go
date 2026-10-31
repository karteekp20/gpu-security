package scan

import (
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

// The closure corpus: the differential test for the OTHER half of every
// sentinel.
//
// test/policy-corpus/corpus.json compares what the two implementations FIND.
// Nothing compared what they CLOSE, and that asymmetry had a measurable
// consequence: renaming domain.HostResponded's value from "responded" to
// anything else left the entire Go suite green, regenerated the finding corpus
// cleanly, and kept the differential at 26/26 - because no finding_condition
// reads host_state, only closures do. Every one of the 19 verification
// sentinels would have become permanently unsatisfiable, no finding would ever
// have auto-closed, and every gate would have reported healthy.
//
// Where the expectations come from, since Go has no closure implementation to
// generate them from (closures exist only in Rego, and only the control plane
// evaluates them):
//
//   - The VOCABULARY is generated from internal/domain - the port states and
//     host states the scanner actually emits. That is what makes enum drift a
//     failure here rather than silence.
//   - The POSITIVE expectation is each rule's own declared scope: the rule that
//     says it is about service S must close when S is observed isolated on a
//     host that answered. Asserted as a subset, not an equality, because one
//     isolation observation legitimately closes several rules at once (an
//     isolated vLLM port closes RG-VLLM-001 and RG-TLS-002 together).
//   - The NEGATIVE expectation needs no per-rule knowledge at all, which is
//     why it is the stronger half: on a host we did not reach, NOTHING may
//     close, whatever else the observation says. That is the property the
//     signed credential rests on (CLAUDE.md §8, and the 2026-09-25 decision
//     that a scan reaching nothing may not grade clean).
const closuresPath = "../../test/policy-corpus/closures.json"

// serviceBindingRe matches the `input.service == "x"` a verification clause
// uses to scope itself. Scoping is not cosmetic: before it, a Ray observation
// returning 401 satisfied RG-BUCKET-001's sentinel.
var serviceBindingRe = regexp.MustCompile(`input\.service\s*==\s*"([^"]+)"`)

// closureCase is one synthesized verification input plus what must be true of
// the `verified` set it produces. The two expectations are deliberately
// different shapes: `contains` is a subset check, `empty` is an equality.
type closureCase struct {
	Name     string          `json:"name"`
	Why      string          `json:"why,omitempty"`
	Input    json.RawMessage `json:"input"`
	Contains []string        `json:"expect_verified_contains,omitempty"`
	Empty    bool            `json:"expect_verified_empty,omitempty"`
}

// verificationScope is what the closure corpus needs to know about one rule,
// read from the rule itself rather than restated here.
type verificationScope struct {
	ruleID  string
	service string
	// isolating records whether the rule offers an isolation closure. Only
	// RG-BUCKET-001 does not: a bucket is fixed by changing a permission,
	// observed as a 4xx, and there is no port to close.
	isolating bool
}

// verificationBlocks returns the text of every verification_condition clause
// in a rule file, concatenated. Brace-depth scanned rather than regexed so a
// nested object cannot end the block early.
func verificationBlocks(src string) string {
	var b strings.Builder
	rest := src
	for {
		i := strings.Index(rest, "verification_condition")
		if i < 0 {
			return b.String()
		}
		rest = rest[i:]
		open := strings.IndexByte(rest, '{')
		if open < 0 {
			return b.String()
		}
		depth := 0
		end := -1
		for j := open; j < len(rest); j++ {
			switch rest[j] {
			case '{':
				depth++
			case '}':
				depth--
				if depth == 0 {
					end = j
				}
			}
			if end >= 0 {
				break
			}
		}
		if end < 0 {
			return b.String()
		}
		b.WriteString(rest[open : end+1])
		b.WriteString("\n")
		rest = rest[end+1:]
	}
}

// serviceRe pulls the service a verification clause binds itself to. Every
// rule binds one except RG-TLS-002, which binds lib.known_service instead
// because it applies to any service the library can name.
func verificationScopes(t *testing.T) []verificationScope {
	t.Helper()
	var out []verificationScope
	for id, r := range parseRegoRules(t) {
		b, err := os.ReadFile(r.path) // #nosec G304 -- fixed test-local paths
		if err != nil {
			t.Fatalf("reading %s: %v", r.path, err)
		}
		block := verificationBlocks(string(b))
		if block == "" {
			t.Errorf("%s: could not read a verification_condition block", r.path)
			continue
		}
		scope := verificationScope{
			ruleID:    id,
			isolating: strings.Contains(block, "lib.isolated("),
		}
		if m := serviceBindingRe.FindStringSubmatch(block); m != nil {
			scope.service = m[1]
		} else if strings.Contains(block, "lib.known_service(") {
			// RG-TLS-002 applies to any named service, so the corpus picks
			// one. Any member of known_services would do.
			scope.service = "ray-dashboard"
		} else {
			t.Errorf("%s: verification_condition binds neither a service nor "+
				"lib.known_service, so a sentinel could be satisfied by an "+
				"observation of some other service entirely", r.path)
			continue
		}
		out = append(out, scope)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ruleID < out[j].ruleID })
	return out
}

// isolationInput is the shape the control plane synthesizes when a port that
// held a finding no longer answers: the finding's own service, the new scan's
// host state, and no HTTP to reason about (policies/README.md, "the
// verification-input synthesis contract" - a fixed port yields no observation
// of its own, so one is built).
func isolationInput(service string, hs domain.HostState) json.RawMessage {
	return mk(domain.Observation{
		Host: "10.0.0.5", Port: 8265, Service: service, State: domain.PortClosed,
	}, hs)
}

// permissionInput is the shape for a finding with no port to close: the same
// unauthenticated request, now refused.
func permissionInput(service string, hs domain.HostState) json.RawMessage {
	return mk(domain.Observation{
		Host: "bucket.s3.amazonaws.com", Service: service, State: domain.PortOpen,
		HTTPStatus: 403, TLS: domain.TLSState{Enabled: true},
	}, hs)
}

// unreachedStates is every host state the scanner can report EXCEPT the one
// that permits a closure. Generated from the domain constants so a new host
// state joins the negative cases automatically, and so renaming any of them
// changes this corpus rather than silently diverging from the rules.
func unreachedStates() []domain.HostState {
	all := []domain.HostState{
		domain.HostResponded, domain.HostNoResponse,
		domain.HostUnresolved, domain.HostProbeFailed,
	}
	var out []domain.HostState
	for _, s := range all {
		if s != domain.HostResponded {
			out = append(out, s)
		}
	}
	return out
}

func closureCorpus(t *testing.T) []closureCase {
	t.Helper()
	scopes := verificationScopes(t)

	// Positive cases, deduped by input: one isolation observation closes every
	// rule scoped to that service, so the expectations are unioned rather than
	// asserted one rule at a time.
	type key struct {
		service string
		shape   string
	}
	positives := map[key][]string{}
	for _, s := range scopes {
		shape := "permission"
		if s.isolating {
			shape = "isolation"
		}
		k := key{service: s.service, shape: shape}
		positives[k] = append(positives[k], s.ruleID)
	}

	var keys []key
	for k := range positives {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].service != keys[j].service {
			return keys[i].service < keys[j].service
		}
		return keys[i].shape < keys[j].shape
	})

	var cases []closureCase
	for _, k := range keys {
		ids := positives[k]
		sort.Strings(ids)
		build := isolationInput
		why := "the port that held the finding no longer answers, on a host that did"
		if k.shape == "permission" {
			build = permissionInput
			why = "the same unauthenticated request is now refused, on a host that answered"
		}
		cases = append(cases, closureCase{
			Name:     fmt.Sprintf("%s: %s closes on a host that answered", k.service, k.shape),
			Why:      why,
			Input:    build(k.service, domain.HostResponded),
			Contains: ids,
		})
		for _, hs := range unreachedStates() {
			cases = append(cases, closureCase{
				Name: fmt.Sprintf("%s: %s must NOT close when host_state=%s", k.service, k.shape, hs),
				Why: "absence of evidence is not evidence of a fix; closing here would " +
					"put \"we could not look\" into a signed credential as \"we attest it is fixed\"",
				Input: build(k.service, hs),
				Empty: true,
			})
		}
	}
	return cases
}

// TestRegoClosureCorpusIsCurrent regenerates the closure corpus and fails if
// the checked-in file has drifted. Set RAY_GUARD_UPDATE_CORPUS=1 to accept a
// deliberate change (the same switch the finding corpus uses).
func TestRegoClosureCorpusIsCurrent(t *testing.T) {
	cases := closureCorpus(t)

	// Every rule must have a positive closure case, so a rule cannot be added
	// without its sentinel being exercised against OPA.
	covered := map[string]bool{}
	for _, c := range cases {
		for _, id := range c.Contains {
			covered[id] = true
		}
	}
	for id := range parseRegoRules(t) {
		if !covered[id] {
			t.Errorf("%s has no positive closure case; its verification sentinel is "+
				"never evaluated by the differential test", id)
		}
	}

	// And the negative half must outnumber the positive, which is only a
	// sanity check that the host-state loop ran at all.
	var empties int
	for _, c := range cases {
		if c.Empty {
			empties++
		}
	}
	if empties < len(cases)-empties {
		t.Errorf("only %d of %d closure cases assert that an unreached host closes "+
			"nothing; the unreached-host loop is the credential-critical half", empties, len(cases))
	}

	out, err := json.MarshalIndent(struct {
		Comment string        `json:"_comment"`
		Cases   []closureCase `json:"cases"`
	}{
		Comment: "Generated by internal/scan/rego_closure_test.go. Vocabulary from " +
			"internal/domain; scope from each rule's own verification_condition. " +
			"Replayed through OPA by policies/tools/differential.py in CI. Do not " +
			"hand-edit: run `go test ./internal/scan` with RAY_GUARD_UPDATE_CORPUS=1.",
		Cases: cases,
	}, "", "  ")
	if err != nil {
		t.Fatalf("marshalling closure corpus: %v", err)
	}
	out = append(out, '\n')

	existing, readErr := os.ReadFile(closuresPath)
	if os.Getenv("RAY_GUARD_UPDATE_CORPUS") == "1" {
		if err := os.MkdirAll(filepath.Dir(closuresPath), 0o755); err != nil {
			t.Fatalf("creating testdata dir: %v", err)
		}
		if err := os.WriteFile(closuresPath, out, 0o644); err != nil { // #nosec G306 -- test fixture, no secrets
			t.Fatalf("writing closure corpus: %v", err)
		}
		t.Logf("closure corpus updated: %d cases", len(cases))
		return
	}
	if readErr != nil {
		t.Fatalf("%s is missing; regenerate with RAY_GUARD_UPDATE_CORPUS=1", closuresPath)
	}
	if string(existing) != string(out) {
		t.Errorf("%s is stale. The scanner's state vocabulary or a rule's declared "+
			"scope has changed and the closure differential is now comparing against "+
			"yesterday's contract. Regenerate with RAY_GUARD_UPDATE_CORPUS=1 and "+
			"review the diff.", closuresPath)
	}
}
