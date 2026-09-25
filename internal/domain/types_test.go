package domain

import (
	"strings"
	"testing"
	"time"
)

func f(rule string, sev Severity, host string, port int) Finding {
	return Finding{RuleID: rule, Title: rule + " title", Severity: sev, Host: host, Port: port}
}

// resultWith builds a result where every target answered, which is the normal
// case and keeps these tests focused on grading rather than coverage.
func resultWith(findings ...Finding) ScanResult {
	return resultWithHosts(responded("host-a", "host-b"), findings...)
}

func resultWithHosts(hosts []HostSummary, findings ...Finding) ScanResult {
	start := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	return NewScanResult(start, start.Add(time.Second), hosts, findings)
}

func responded(hosts ...string) []HostSummary {
	out := make([]HostSummary, 0, len(hosts))
	for _, h := range hosts {
		out = append(out, HostSummary{Host: h, State: HostResponded})
	}
	return out
}

func TestGradeIsDrivenByWorstFinding(t *testing.T) {
	cases := []struct {
		name      string
		findings  []Finding
		wantGrade Grade
		wantScore int
	}{
		{"clean", nil, "A+", 100},
		{"info only", []Finding{f("RG-EXPOSURE-001", Info, "h", 9000)}, "A", 90},
		{"low", []Finding{f("RG-TRITON-002", Low, "h", 8002)}, "A", 90},
		{"medium", []Finding{f("RG-OLLAMA-001", Medium, "h", 11434)}, "B", 78},
		{"high", []Finding{f("RG-VLLM-001", High, "h", 8000)}, "C", 60},
		{"critical", []Finding{f("RG-RAY-001", Critical, "h", 8265)}, "F", 40},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := resultWith(tc.findings...)
			if r.Grade != tc.wantGrade || r.Score != tc.wantScore {
				t.Errorf("want %s/%d, got %s/%d", tc.wantGrade, tc.wantScore, r.Grade, r.Score)
			}
		})
	}
}

func TestOneCriticalOutweighsManyLows(t *testing.T) {
	r := resultWith(
		f("RG-TRITON-002", Low, "a", 8002),
		f("RG-TRITON-002", Low, "b", 8002),
		f("RG-TRITON-002", Low, "c", 8002),
		f("RG-RAY-001", Critical, "d", 8265),
	)
	if r.Grade != "F" {
		t.Errorf("a critical RCE must dominate the grade, got %s", r.Grade)
	}
}

func TestGradeReasonNamesTheCause(t *testing.T) {
	r := resultWith(f("RG-RAY-001", Critical, "h", 8265))
	if !strings.Contains(r.GradeReason, "RG-RAY-001 title") {
		t.Errorf("the rationale should name the driving finding, got %q", r.GradeReason)
	}
	if !strings.Contains(r.GradeReason, "remote code execution") {
		t.Errorf("a critical grade should say what it means, got %q", r.GradeReason)
	}

	clean := resultWith()
	if !strings.Contains(clean.GradeReason, "No exposure") {
		t.Errorf("a clean scan needs a rationale too, got %q", clean.GradeReason)
	}
}

func TestSummaryAndHostCount(t *testing.T) {
	r := resultWith(
		f("RG-RAY-001", Critical, "host-a", 8265),
		f("RG-OLLAMA-001", Medium, "host-a", 11434),
		f("RG-VLLM-001", High, "host-b", 8000),
	)
	if r.Summary[Critical] != 1 || r.Summary[High] != 1 || r.Summary[Medium] != 1 {
		t.Errorf("unexpected severity summary: %+v", r.Summary)
	}
	if r.HostsWithFindings != 2 {
		t.Errorf("three findings across two hosts should count 2 hosts, got %d", r.HostsWithFindings)
	}
}

func TestSortFindingsIsDeterministic(t *testing.T) {
	in := []Finding{
		f("RG-B", High, "10.0.0.9", 8000),
		f("RG-A", High, "10.0.0.1", 9000),
		f("RG-C", Critical, "10.0.0.9", 8265),
		f("RG-A", High, "10.0.0.1", 8000),
	}
	got := SortFindings(in)

	if got[0].Severity != Critical {
		t.Fatalf("worst severity must sort first, got %s", got[0].Severity)
	}
	// Then host, then port.
	if got[1].Host != "10.0.0.1" || got[1].Port != 8000 {
		t.Errorf("expected 10.0.0.1:8000 second, got %s:%d", got[1].Host, got[1].Port)
	}
	if got[2].Host != "10.0.0.1" || got[2].Port != 9000 {
		t.Errorf("expected 10.0.0.1:9000 third, got %s:%d", got[2].Host, got[2].Port)
	}

	// Sorting must not mutate the caller's slice - report and snapshot both
	// sort the same findings.
	if in[0].RuleID != "RG-B" {
		t.Error("SortFindings mutated its input")
	}
}

func TestWorstFinding(t *testing.T) {
	if WorstFinding(nil) != nil {
		t.Error("no findings means no worst finding")
	}
	w := WorstFinding([]Finding{
		f("RG-LOW", Low, "h", 1),
		f("RG-CRIT", Critical, "h", 2),
	})
	if w == nil || w.RuleID != "RG-CRIT" {
		t.Errorf("expected the critical finding, got %+v", w)
	}
}

func TestSeverityRankOrdersWorstFirst(t *testing.T) {
	if SeverityRank(Critical) >= SeverityRank(Info) {
		t.Error("critical must rank ahead of info")
	}
	if SeverityRank("not-a-severity") != len(SeverityOrder()) {
		t.Error("an unknown severity should sort last rather than ahead of everything")
	}
}

func TestSeverityOrderIsNotAliased(t *testing.T) {
	a := SeverityOrder()
	a[0] = "tampered"
	if SeverityOrder()[0] != Critical {
		t.Error("SeverityOrder must return a copy; the package ordering was mutated")
	}
}

func TestExitCodeEncodesWorstSeverity(t *testing.T) {
	cases := []struct {
		sev  Severity
		want int
	}{
		{Critical, 6}, {High, 5}, {Medium, 4}, {Low, 3}, {Info, 3},
	}
	for _, tc := range cases {
		if got := resultWith(f("RG-X", tc.sev, "h", 1)).ExitCode(); got != tc.want {
			t.Errorf("%s: want exit %d, got %d", tc.sev, tc.want, got)
		}
	}
	if got := resultWith().ExitCode(); got != 0 {
		t.Errorf("a clean scan must exit 0, got %d", got)
	}
}

// The false all-clear is the most damaging thing this tool could say. A scan
// that reached nothing must never look like a scan that found nothing.
func TestUnreachableTargetsNeverGradeClean(t *testing.T) {
	cases := []struct {
		name  string
		hosts []HostSummary
	}{
		{"all names unresolvable", []HostSummary{
			{Host: "typo.invalid", State: HostUnresolved},
			{Host: "also-typo.invalid", State: HostUnresolved},
		}},
		{"all hosts silent", []HostSummary{
			{Host: "198.51.100.1", State: HostNoResponse},
			{Host: "198.51.100.2", State: HostNoResponse},
		}},
		{"nothing scanned at all", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := resultWithHosts(tc.hosts)
			if r.Grade == "A+" {
				t.Errorf("FALSE ALL-CLEAR: graded A+ without reaching anything")
			}
			if r.Grade != GradeInconclusive {
				t.Errorf("want %s, got %s", GradeInconclusive, r.Grade)
			}
			if !r.Inconclusive() {
				t.Error("a scan that reached nothing must report itself inconclusive")
			}
			if r.Score != 0 {
				t.Errorf("an inconclusive scan has no score, got %d", r.Score)
			}
			if r.ExitCode() != 7 {
				t.Errorf("inconclusive must exit non-zero (7) so CI fails, got %d", r.ExitCode())
			}
			if !strings.Contains(r.GradeReason, "not a clean result") &&
				!strings.Contains(r.GradeReason, "No targets") {
				t.Errorf("the rationale must say this is not a pass, got %q", r.GradeReason)
			}
		})
	}
}

// A host that answers - even by refusing every port - is real evidence.
func TestRespondingHostWithNoServicesIsGenuinelyClean(t *testing.T) {
	r := resultWithHosts(responded("10.0.0.1"))
	if r.Grade != "A+" || r.Score != 100 {
		t.Errorf("a live host running nothing is a real A+, got %s/%d", r.Grade, r.Score)
	}
	if r.Inconclusive() || r.ExitCode() != 0 {
		t.Errorf("a genuine clean result must exit 0, got %d", r.ExitCode())
	}
}

func TestPartialCoverageIsDisclosedOnACleanGrade(t *testing.T) {
	hosts := append(responded("10.0.0.1"),
		HostSummary{Host: "10.0.0.2", State: HostNoResponse},
		HostSummary{Host: "bad.invalid", State: HostUnresolved})
	r := resultWithHosts(hosts)

	if r.Grade != "A+" {
		t.Errorf("one responding clean host still grades A+, got %s", r.Grade)
	}
	if !r.PartialCoverage() {
		t.Error("expected partial coverage to be flagged")
	}
	if !strings.Contains(r.GradeReason, "did not respond") {
		t.Errorf("an A+ with gaps must disclose them, got %q", r.GradeReason)
	}
	if r.HostsResponded != 1 || r.HostsUnanswered != 1 || r.HostsUnresolved != 1 {
		t.Errorf("coverage counts wrong: %+v", r)
	}
	if len(r.Unreachable) != 2 {
		t.Errorf("expected 2 unreachable targets recorded, got %d", len(r.Unreachable))
	}
}

// Findings outrank coverage: an exposure found on a reachable host is still
// the headline even if most of the range was dark.
func TestFindingsStillGradeWhenMostTargetsWereDark(t *testing.T) {
	hosts := append(responded("10.0.0.1"),
		HostSummary{Host: "10.0.0.2", State: HostNoResponse},
		HostSummary{Host: "10.0.0.3", State: HostNoResponse})
	r := resultWithHosts(hosts, f("RG-RAY-001", Critical, "10.0.0.1", 8265))

	if r.Grade != "F" {
		t.Errorf("a critical finding grades F regardless of coverage, got %s", r.Grade)
	}
	if r.ExitCode() != 6 {
		t.Errorf("want exit 6 for critical, got %d", r.ExitCode())
	}
}

func TestScanResultCarriesVersion(t *testing.T) {
	if resultWith().ScannerVersion != Version {
		t.Error("the report must record which scanner produced it")
	}
}
