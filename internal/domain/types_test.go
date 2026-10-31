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
		{"clean", nil, L1GradeCeiling, L1CleanScore},
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
	if r.Grade != L1GradeCeiling || r.Score != L1CleanScore {
		t.Errorf("a live host running nothing is a genuine clean L1 result, want %s/%d, got %s/%d",
			L1GradeCeiling, L1CleanScore, r.Grade, r.Score)
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

	if r.Grade != L1GradeCeiling {
		t.Errorf("one responding clean host still earns the L1 ceiling, got %s", r.Grade)
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

// -----------------------------------------------------------------------------
// Interrupted scans
//
// Ctrl-C mid-scan is an ordinary event in the room: the operator pointed at
// the wrong subnet, or the authorization window closed. What comes out must be
// readable as partial, and must never read as a pass.
// -----------------------------------------------------------------------------

func partialResult(requested int, hosts []HostSummary, findings ...Finding) ScanResult {
	start := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	return NewResult(Run{Start: start, End: start.Add(time.Second), Requested: requested,
		Hosts: hosts, Findings: findings, Interrupted: true})
}

// degradedResult is a run that finished but whose own probes failed part-way.
func degradedResult(probeErrors int, hosts []HostSummary, findings ...Finding) ScanResult {
	start := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	return NewResult(Run{Start: start, End: start.Add(time.Second), Requested: len(hosts),
		Hosts: hosts, Findings: findings, ProbeErrors: probeErrors})
}

// TestInterruptedScanNeverGradesClean is the point of the whole change. A scan
// that covered 2 of 254 targets and found nothing has not found nothing.
func TestInterruptedScanNeverGradesClean(t *testing.T) {
	cases := []struct {
		name     string
		findings []Finding
	}{
		{"no findings at all", nil},
		{"only info", []Finding{f("RG-EXPOSURE-001", Info, "host-a", 8080)}},
		{"only low", []Finding{f("RG-TRITON-002", Low, "host-a", 8002)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := partialResult(254, responded("host-a", "host-b"), tc.findings...)
			if r.Grade != GradeInconclusive {
				t.Errorf("grade %s on an interrupted scan; a clean grade claims coverage we do not have", r.Grade)
			}
			if r.Score != 0 {
				t.Errorf("score %d on an interrupted scan, want 0", r.Score)
			}
			if r.Graded() {
				t.Error("Graded() is true, so the report will print a score for a non-result")
			}
		})
	}
}

// TestInterruptedScanStillReportsWhatItSaw is the other half: an observed
// exposure is observed. Withholding an F because the scan was cut short would
// bury the finding that mattered.
func TestInterruptedScanStillReportsWhatItSaw(t *testing.T) {
	r := partialResult(254, responded("host-a"), f("RG-RAY-001", Critical, "host-a", 8265))
	if r.Grade != "F" {
		t.Errorf("grade = %s, want F: a critical exposure is positive evidence", r.Grade)
	}
	if !strings.Contains(r.GradeReason, "stopped before it finished") {
		t.Errorf("reason does not disclose the interruption: %q", r.GradeReason)
	}
	if !strings.Contains(r.GradeReason, "2 of 254") && !strings.Contains(r.GradeReason, "1 of 254") {
		t.Errorf("reason does not state coverage: %q", r.GradeReason)
	}
	if !strings.Contains(r.GradeReason, "floor") {
		t.Errorf("reason should say the grade is a floor, not a verdict: %q", r.GradeReason)
	}
}

// TestInterruptedCoverageCountsAreHonest: the targets we never dialed are not
// recorded as unreachable. "We stopped" is a fact about us; "it did not
// answer" is a fact about the customer's host, and only one of them is true.
func TestInterruptedCoverageCountsAreHonest(t *testing.T) {
	r := partialResult(254, responded("host-a", "host-b"))
	if r.TargetsRequested != 254 {
		t.Errorf("TargetsRequested = %d, want 254", r.TargetsRequested)
	}
	if r.TargetsScanned != 2 {
		t.Errorf("TargetsScanned = %d, want 2", r.TargetsScanned)
	}
	if r.HostsUnanswered != 0 || r.HostsUnresolved != 0 {
		t.Errorf("unanswered=%d unresolved=%d: unprobed targets must not be reported as unreachable",
			r.HostsUnanswered, r.HostsUnresolved)
	}
	if len(r.Unreachable) != 0 {
		t.Errorf("Unreachable lists %d host(s) that were simply never probed", len(r.Unreachable))
	}
	if !r.Interrupted {
		t.Error("Interrupted = false on a partial result")
	}
}

// TestInterruptedExitCodeIsNeverZero: a pipeline must not go green on a run
// that did not finish, whatever it managed to see first.
func TestInterruptedExitCodeIsNeverZero(t *testing.T) {
	cases := [][]Finding{
		nil,
		{f("RG-RAY-001", Critical, "host-a", 8265)},
		{f("RG-TRITON-002", Low, "host-a", 8002)},
	}
	for i, findings := range cases {
		r := partialResult(254, responded("host-a"), findings...)
		if got := r.ExitCode(); got != ExitInterrupted {
			t.Errorf("case %d: exit code %d, want %d (128+SIGINT)", i, got, ExitInterrupted)
		}
	}
}

// TestCompletedScanKeepsItsRequestedCount guards the ordinary path: the two
// counts agree, so nothing in the report implies a coverage gap that is not
// there.
func TestCompletedScanKeepsItsRequestedCount(t *testing.T) {
	r := resultWithHosts(responded("host-a", "host-b", "host-c"))
	if r.TargetsRequested != r.TargetsScanned {
		t.Errorf("requested %d but scanned %d on a completed scan", r.TargetsRequested, r.TargetsScanned)
	}
	if r.Interrupted {
		t.Error("Interrupted = true on a completed scan")
	}
	if r.Grade != L1GradeCeiling || !r.Graded() {
		t.Errorf("completed clean scan graded %s; the interrupted gate must not catch it", r.Grade)
	}
}

// -----------------------------------------------------------------------------
// Degraded scans — the scanner's own probes failed
//
// Measured, not hypothetical: with the open-file limit at 128, a /24 of the
// demo cluster graded C with 3 findings where a healthy run graded F with 19,
// and the unauthenticated Ray dashboard was reported as an unidentified
// service on 8265. The report said nothing was wrong. That is the same family
// of harm as the false all-clear, arrived at from a different direction.
// -----------------------------------------------------------------------------

func TestDegradedScanNeverGradesClean(t *testing.T) {
	cases := []struct {
		name     string
		findings []Finding
	}{
		{"no findings at all", nil},
		{"only info", []Finding{f("RG-EXPOSURE-001", Info, "host-a", 8080)}},
		{"only low", []Finding{f("RG-TRITON-002", Low, "host-a", 8002)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := degradedResult(7, responded("host-a", "host-b"), tc.findings...)
			if r.Grade != GradeInconclusive {
				t.Errorf("grade %s: a scan whose probes failed has not looked everywhere it claims", r.Grade)
			}
			if !r.Degraded() {
				t.Error("Degraded() is false although probes failed")
			}
			if got := r.ExitCode(); got != 7 {
				t.Errorf("exit code %d, want 7: an unreliable run must not pass a pipeline", got)
			}
		})
	}
}

func TestDegradedScanStillReportsWhatItSaw(t *testing.T) {
	r := degradedResult(3, responded("host-a"), f("RG-RAY-001", Critical, "host-a", 8265))
	if r.Grade != "F" {
		t.Errorf("grade = %s, want F: what the scan did observe, it observed", r.Grade)
	}
	if got := r.ExitCode(); got != 6 {
		t.Errorf("exit code %d, want 6 (critical)", got)
	}
	for _, want := range []string{"floor", "3 probe(s) failed", "ulimit -Hn", "-concurrency"} {
		if !strings.Contains(r.GradeReason, want) {
			t.Errorf("grade reason does not mention %q: %q", want, r.GradeReason)
		}
	}
}

// TestProbeFailedHostsAreNotReportedAsSilent: the two look identical in an
// empty finding list and have opposite remedies. One is "ask the customer
// about that host", the other is "fix your own machine and re-run".
func TestProbeFailedHostsAreNotReportedAsSilent(t *testing.T) {
	start := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	hosts := []HostSummary{
		{Host: "host-a", State: HostResponded},
		{Host: "host-b", State: HostProbeFailed},
		{Host: "host-c", State: HostNoResponse},
		{Host: "host-d", State: HostUnresolved},
	}
	r := NewResult(Run{Start: start, End: start.Add(time.Second), Requested: len(hosts),
		Hosts: hosts, ProbeErrors: 4})

	if r.HostsProbeFailed != 1 {
		t.Errorf("HostsProbeFailed = %d, want 1", r.HostsProbeFailed)
	}
	if r.HostsUnanswered != 1 {
		t.Errorf("HostsUnanswered = %d, want 1: a probe failure is not a silent host", r.HostsUnanswered)
	}
	if r.HostsResponded != 1 || r.HostsUnresolved != 1 {
		t.Errorf("other states miscounted: %+v", r)
	}
	if len(r.Unreachable) != 3 {
		t.Errorf("Unreachable lists %d, want the 3 unassessed hosts", len(r.Unreachable))
	}
}

// TestInterruptionOutranksDegradationInTheExplanation: both can be true, and
// the operator who pressed Ctrl-C needs that said first - it is the thing they
// did, and it explains the probe failures that cancellation itself can cause.
func TestInterruptionOutranksDegradationInTheExplanation(t *testing.T) {
	start := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	r := NewResult(Run{Start: start, End: start.Add(time.Second), Requested: 254,
		Hosts: responded("host-a"), Interrupted: true, ProbeErrors: 2})
	if !strings.Contains(r.GradeReason, "stopped before it finished") {
		t.Errorf("reason leads with something other than the interruption: %q", r.GradeReason)
	}
	if r.ExitCode() != ExitInterrupted {
		t.Errorf("exit code %d, want %d", r.ExitCode(), ExitInterrupted)
	}
}

// TestL1CannotEarnAPlus is the guard for CLAUDE.md 10.0's tier scoping.
//
// A+ means "hardware attestation cryptographically verified, fabric isolation
// evidenced" - claims an agentless port-and-TLS scan cannot make. For as long
// as the grade and the credential are the same number, a clean L1 scan that
// printed A+ would put that meaning on a port scan, and the Phase-1 credential
// would sign it as "Issuable - Gold".
//
// The sweep is exhaustive over the severity combinations gradeFor branches on,
// rather than spot-checking the clean case, because the hazard is a future
// branch that returns A+ for some other reason.
func TestL1CannotEarnAPlus(t *testing.T) {
	sevs := []Severity{Critical, High, Medium, Low, Info}
	for mask := 0; mask < 1<<len(sevs); mask++ {
		var findings []Finding
		for i, sev := range sevs {
			if mask&(1<<i) != 0 {
				findings = append(findings, f("RG-TEST-001", sev, "h", 1))
			}
		}
		t0 := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
		for _, run := range []Run{
			{Start: t0, End: t0, Requested: 1, Hosts: responded("h"), Findings: findings},
			{Start: t0, End: t0, Requested: 1, Hosts: responded("h"), Findings: findings, Interrupted: true},
			{Start: t0, End: t0, Requested: 1, Hosts: responded("h"), Findings: findings, ProbeErrors: 1},
			{Start: t0, End: t0, Requested: 1, Findings: findings},
		} {
			r := NewResult(run)
			if r.Grade == GradeAPlus {
				t.Fatalf("L1 produced A+ for findings=%v interrupted=%v probeErrors=%d: "+
					"A+ claims attested hardware, which this tier never assesses",
					severitiesOf(findings), run.Interrupted, run.ProbeErrors)
			}
			if r.Score > L1CleanScore {
				t.Fatalf("L1 scored %d, above the ceiling %d: scores 95-100 are the A+ band",
					r.Score, L1CleanScore)
			}
		}
	}
}

func severitiesOf(findings []Finding) []Severity {
	out := make([]Severity, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.Severity)
	}
	return out
}

// TestCleanGradeStatesItsCeiling: the limit belongs with the grade, because the
// grade is what gets quoted out of the report.
func TestCleanGradeStatesItsCeiling(t *testing.T) {
	for _, r := range []ScanResult{
		resultWithHosts(responded("10.0.0.1")),
		resultWith(f("RG-EXPOSURE-001", Info, "h", 9000)),
	} {
		if !strings.Contains(r.GradeReason, "highest grade a Level 1 assessment can earn") {
			t.Errorf("a clean L1 grade must say it is the tier's ceiling, got %q", r.GradeReason)
		}
	}
}

// The tier travels with the result so a grade is never read without its scope.
func TestResultCarriesItsTier(t *testing.T) {
	if got := resultWithHosts(responded("10.0.0.1")).Tier; got != TierL1 {
		t.Errorf("Tier = %q, want %q", got, TierL1)
	}
}

// A name that resolves to several addresses is several machines. Probing one
// of them and reporting a clean result is the 2026-09-25 false all-clear in a
// new shape - the grade would describe one node of a fleet the operator named
// as a whole - so an unassessed sibling address gates clean grades exactly as
// an interrupted or degraded run does.
func TestAClearScanWithUnassessedAddressesCannotGradeClean(t *testing.T) {
	hosts := []HostSummary{
		{Host: "ray.customer.internal", State: HostResponded, Address: "10.0.0.5", AddressesFound: 3},
	}
	r := NewScanResult(time.Now(), time.Now().Add(time.Second), hosts, nil)

	if r.AddressesUnassessed != 2 {
		t.Errorf("AddressesUnassessed = %d, want 2 (3 found, 1 probed)", r.AddressesUnassessed)
	}
	if r.Grade != GradeInconclusive {
		t.Errorf("grade %q with 2 of 3 addresses never probed; want %q - a clean letter here "+
			"claims the whole name was assessed", r.Grade, GradeInconclusive)
	}
	if r.Graded() {
		t.Error("a scan that covered one address of three must not report a gradeable verdict")
	}
	// The reason has to name the host, the count and the address, because the
	// operator's next action is to pass the other addresses as targets.
	for _, want := range []string{"ray.customer.internal", "3 addresses", "10.0.0.5", "Pass the addresses"} {
		if !strings.Contains(r.GradeReason, want) {
			t.Errorf("grade reason does not mention %q: %s", want, r.GradeReason)
		}
	}
	if len(r.MultiAddress) != 1 || r.MultiAddress[0].Host != "ray.customer.internal" {
		t.Errorf("MultiAddress = %+v, want the one fanned-out name", r.MultiAddress)
	}
}

// An observed exposure stands whatever the coverage: it was seen. The grade is
// stated as a floor rather than withheld, which is the same asymmetry that
// governs interrupted and degraded runs.
func TestAnObservedFindingStillGradesWithUnassessedAddresses(t *testing.T) {
	hosts := []HostSummary{
		{Host: "ray.customer.internal", State: HostResponded, Address: "10.0.0.5", AddressesFound: 2},
	}
	findings := []Finding{{RuleID: "RG-RAY-001", Title: "Unauthenticated Ray dashboard / Jobs API exposed",
		Severity: Critical, Host: "ray.customer.internal", Port: 8265}}
	r := NewScanResult(time.Now(), time.Now().Add(time.Second), hosts, findings)

	if r.Grade != "F" {
		t.Errorf("grade %q; an observed critical is observed regardless of coverage, want F", r.Grade)
	}
	if !strings.Contains(r.GradeReason, "floor") {
		t.Errorf("a finding-driven grade under partial address coverage must be stated as a floor: %s",
			r.GradeReason)
	}
}

// One address is the ordinary case and must cost nothing: no disclosure, no
// gate, and a clean scan still reaches the tier ceiling.
func TestASingleAddressNameGradesNormally(t *testing.T) {
	hosts := []HostSummary{
		{Host: "ray.customer.internal", State: HostResponded, Address: "10.0.0.5", AddressesFound: 1},
	}
	r := NewScanResult(time.Now(), time.Now().Add(time.Second), hosts, nil)

	if r.AddressesUnassessed != 0 || len(r.MultiAddress) != 0 {
		t.Errorf("a name with one address has nothing unassessed: %d / %+v",
			r.AddressesUnassessed, r.MultiAddress)
	}
	if r.Grade != L1GradeCeiling {
		t.Errorf("grade %q, want %q - one address is full coverage of that name", r.Grade, L1GradeCeiling)
	}
	if got := r.Addresses["ray.customer.internal"]; got != "10.0.0.5" {
		t.Errorf("Addresses[name] = %q, want the address probed; a report that cannot name "+
			"the machine cannot be re-checked", got)
	}
}

// A scan given addresses carries no address map at all: there is nothing to
// disclose, and a /24 sweep must not grow 254 redundant entries.
func TestAddressTargetsCarryNoAddressMap(t *testing.T) {
	hosts := []HostSummary{
		{Host: "10.0.0.5", State: HostResponded},
		{Host: "10.0.0.6", State: HostResponded},
	}
	r := NewScanResult(time.Now(), time.Now().Add(time.Second), hosts, nil)
	if len(r.Addresses) != 0 {
		t.Errorf("Addresses = %+v, want empty for address targets", r.Addresses)
	}
	if r.Grade != L1GradeCeiling {
		t.Errorf("grade %q, want %q", r.Grade, L1GradeCeiling)
	}
}
