package scan

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
)

// README.md's "Detections" table restates the rule set: every rule's ID, its
// severity, and which CVEs it cites. All three are generated in detect.go,
// and nothing checked that the table still agreed with them.
//
// It did not. v0.3.0 split CVE citations into asserted and unconfirmed -
// RG-TORCHSERVE-001 stopped asserting CVE-2023-43654 entirely - and the table
// went on presenting it as asserted, on the front page of a public
// repository, for as long as it took someone to diff the two by hand
// (decision row 2026-11-07). The Go<->Rego parity test exists for the same
// reason one level down; this is the surface a buyer actually reads first.
//
// What is deliberately not pinned: the wording of the Service column. The
// table is written for a reader skimming it and should stay free to say
// "Jupyter reachable without token/auth" where the rule says something
// longer. Facts are pinned; prose is not.

var readmeRow = regexp.MustCompile(`(?m)^\|\s*` + "`" + `(RG-[A-Z]+-\d+)` + "`" + `\s*\|([^|]*)\|\s*([a-z]+)\s*\|`)

func readmeDetectionRows(t *testing.T) map[string]struct{ desc, severity string } {
	t.Helper()
	b, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatalf("reading README.md: %v", err)
	}
	rows := map[string]struct{ desc, severity string }{}
	for _, m := range readmeRow.FindAllStringSubmatch(string(b), -1) {
		id := m[1]
		if _, dup := rows[id]; dup {
			t.Errorf("%s appears in more than one table row; a reader cannot tell "+
				"which is current and a drift can hide in the other", id)
		}
		rows[id] = struct{ desc, severity string }{strings.TrimSpace(m[2]), m[3]}
	}
	if len(rows) == 0 {
		t.Fatal("parsed no rule rows out of README.md; the table format changed " +
			"and this guard silently stopped guarding")
	}
	return rows
}

// TestReadmeListsEveryRuleAtItsRealSeverity is the structural half. A rule
// missing from the table is a detection a buyer does not know they get; a
// rule in the table that no longer exists is a detection they think they get
// and do not.
func TestReadmeListsEveryRuleAtItsRealSeverity(t *testing.T) {
	rows := readmeDetectionRows(t)
	code := goRules()

	for id, r := range code {
		row, ok := rows[id]
		if !ok {
			t.Errorf("%s is implemented but absent from README's Detections table", id)
			continue
		}
		if row.severity != string(r.severity) {
			t.Errorf("%s: README says severity %q, the rule is %q",
				id, row.severity, r.severity)
		}
	}
	for id := range rows {
		if _, ok := code[id]; !ok {
			t.Errorf("README's table lists %s, which no rule implements", id)
		}
	}
}

// TestReadmeDoesNotAssertACVETheRuleWithholds is the half that would have
// caught the real defect. The asserted/unconfirmed split is the whole point
// of v0.3.0: `cves` carries only CVEs whose condition is the condition we
// observed, and a CVE whose advisory names a fixed version moves to
// `cves_unconfirmed` because L1 reads no response bodies and so never learns
// a version. A table that prints both in one parenthesis erases exactly that
// distinction - and prints, about a specific rule, a claim the scanner
// refuses to make.
func TestReadmeDoesNotAssertACVETheRuleWithholds(t *testing.T) {
	rows := readmeDetectionRows(t)
	cveID := regexp.MustCompile(`CVE-\d{4}-\d+`)

	for id, r := range goRules() {
		row, ok := rows[id]
		if !ok {
			continue // reported by the structural test
		}
		asserted, unconfirmed := map[string]bool{}, map[string]bool{}
		for _, c := range assertedCVEs(r.cves) {
			asserted[c] = true
		}
		for _, c := range unconfirmedCVEs(r.cves) {
			unconfirmed[c.ID] = true
		}

		for c := range asserted {
			if !strings.Contains(row.desc, c) {
				t.Errorf("%s asserts %s and README's row does not mention it", id, c)
			}
		}
		for c := range unconfirmed {
			if !strings.Contains(row.desc, c) {
				t.Errorf("%s cites %s as unconfirmed and README's row does not mention it", id, c)
				continue
			}
			if !strings.Contains(strings.ToLower(row.desc), "unconfirmed") {
				t.Errorf("%s: README's row names %s but never says it is unconfirmed, "+
					"so it reads as a claim the scanner deliberately withholds "+
					"(the v0.3.0 defect, exactly)", id, c)
			}
		}
		// A CVE in the row that the rule does not cite at all is the same
		// error in its purest form: a citation with nothing behind it.
		for _, c := range cveID.FindAllString(row.desc, -1) {
			if !asserted[c] && !unconfirmed[c] {
				t.Errorf("README's %s row cites %s, which the rule does not reference "+
					"in either list", id, c)
			}
		}
	}
}

// TestReadmeTableIsCompleteEnoughToTrust guards the guard. Both tests above
// iterate the rules they found; if the regex ever stops matching the table,
// they pass vacuously while checking nothing. Pinning the count means the
// table and the rule set have to be reconciled deliberately.
func TestReadmeTableIsCompleteEnoughToTrust(t *testing.T) {
	rows := readmeDetectionRows(t)
	if got, want := len(rows), len(goRules()); got != want {
		t.Errorf("README's table has %d rule rows, the scanner has %d rules: %s",
			got, want, missingEitherWay(rows, goRules()))
	}
}

func missingEitherWay(rows map[string]struct{ desc, severity string }, code map[string]ruleDef) string {
	var onlyCode, onlyDoc []string
	for id := range code {
		if _, ok := rows[id]; !ok {
			onlyCode = append(onlyCode, id)
		}
	}
	for id := range rows {
		if _, ok := code[id]; !ok {
			onlyDoc = append(onlyDoc, id)
		}
	}
	return fmt.Sprintf("implemented but undocumented %v; documented but unimplemented %v",
		onlyCode, onlyDoc)
}
