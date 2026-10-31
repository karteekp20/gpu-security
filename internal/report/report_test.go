package report

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"gpusecurity/internal/domain"
)

var update = flag.Bool("update", false, "rewrite the golden files")

func respondedHosts(hosts ...string) []domain.HostSummary {
	out := make([]domain.HostSummary, 0, len(hosts))
	for _, h := range hosts {
		out = append(out, domain.HostSummary{Host: h, State: domain.HostResponded})
	}
	return out
}

func fixture() domain.ScanResult {
	start := time.Date(2026, 9, 20, 14, 0, 0, 0, time.UTC)
	findings := []domain.Finding{
		{RuleID: "RG-OLLAMA-001", Title: "Unauthenticated Ollama API exposed", Severity: domain.Medium,
			Host: "10.0.0.6", Port: 11434, Service: "ollama",
			Detail:      "HTTP 200 without authentication on port 11434 (no TLS)",
			Remediation: "Restrict the Ollama API (11434) to localhost/trusted networks."},
		{RuleID: "RG-RAY-001", Title: "Unauthenticated Ray dashboard / Jobs API exposed", Severity: domain.Critical,
			Host: "10.0.0.5", Port: 8265, Service: "ray-dashboard",
			Detail:      "HTTP 200 without authentication on port 8265 (no TLS)",
			Remediation: "Enable Ray authentication or bind the dashboard to loopback/a private subnet; never expose port 8265 publicly.",
			CVEs:        []string{"CVE-2023-48022", "CVE-2025-62593"}},
		{RuleID: "RG-TLS-001", Title: "TLS certificate fails verification", Severity: domain.Medium,
			Host: "10.0.0.5", Port: 8888, Service: "tls",
			Detail:      "Certificate on port 8888 is self-signed (expires 2027-01-01)",
			Remediation: "Replace the certificate with one issued by a trusted CA, matching the service hostname and within its validity window."},
	}
	r := domain.NewScanResult(start, start.Add(12*time.Second), respondedHosts("10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.0.8"), findings)
	// The engagement label and the vantage are part of the artifact a buyer
	// reads, so they belong in the golden file rather than in a side test.
	r.Label = "Example Neocloud - cluster A - 2026-09-20"
	r.ScannedFrom = "assessor-laptop"
	return r
}

func cleanFixture() domain.ScanResult {
	start := time.Date(2026, 9, 20, 14, 0, 0, 0, time.UTC)
	return domain.NewScanResult(start, start.Add(3*time.Second), respondedHosts("10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.0.8"), nil)
}

func goldenCheck(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatalf("mkdir testdata: %v", err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatalf("writing golden %s: %v", name, err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading golden %s (run: go test ./internal/report -update): %v", name, err)
	}
	if !bytes.Equal(want, got) {
		t.Errorf("%s differs from the golden file; re-run with -update if the change is intended", name)
	}
}

func TestGoldenJSON(t *testing.T) {
	goldenCheck(t, "report.golden.json", MarshalJSON(fixture()))
}

func TestGoldenHTML(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderHTML(&buf, fixture()); err != nil {
		t.Fatalf("render: %v", err)
	}
	goldenCheck(t, "report.golden.html", buf.Bytes())
}

func TestGoldenCleanHTML(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderHTML(&buf, cleanFixture()); err != nil {
		t.Fatalf("render: %v", err)
	}
	goldenCheck(t, "clean.golden.html", buf.Bytes())
}

func renderString(t *testing.T, r domain.ScanResult) string {
	t.Helper()
	var buf bytes.Buffer
	if err := RenderHTML(&buf, r); err != nil {
		t.Fatalf("render: %v", err)
	}
	return buf.String()
}

// The report is handed to a security lead as a single file, possibly opened on
// an air-gapped workstation. It must not reference anything it does not carry.
func TestHTMLIsSelfContained(t *testing.T) {
	html := renderString(t, fixture())
	for _, pattern := range []string{`src=`, `href=`, `@import`, `url(`} {
		if strings.Contains(html, pattern) {
			t.Errorf("report references an external asset via %q", pattern)
		}
	}
}

func TestHTMLLeadsWithGradeAndReason(t *testing.T) {
	html := renderString(t, fixture())
	hero := html[:strings.Index(html, "Fix these first")]
	if !strings.Contains(hero, "remote code execution") {
		t.Error("the grade rationale should appear above the fold, before the findings list")
	}
	if !strings.Contains(hero, `class="grade g-F"`) {
		t.Error("expected an F grade badge in the hero block")
	}
}

func TestHTMLIncludesShadowRayContextOnlyWhenRelevant(t *testing.T) {
	withRay := renderString(t, fixture())
	if !strings.Contains(withRay, "ShadowRay") || !strings.Contains(withRay, "CVE-2023-48022") {
		t.Error("a Ray finding should carry the ShadowRay context section")
	}

	noRay := fixture()
	var kept []domain.Finding
	for _, f := range noRay.Findings {
		if !strings.HasPrefix(f.RuleID, "RG-RAY-") {
			kept = append(kept, f)
		}
	}
	noRay = domain.NewScanResult(noRay.StartedAt, noRay.CompletedAt, respondedHosts("10.0.0.5", "10.0.0.6"), kept)
	if strings.Contains(renderString(t, noRay), "ShadowRay") {
		t.Error("the ShadowRay section should not appear without a Ray finding")
	}
}

func TestHTMLGroupsFindingsByHost(t *testing.T) {
	html := renderString(t, fixture())
	if n := strings.Count(html, `<h3>`); n != 2 {
		t.Errorf("expected one heading per affected host (2), got %d", n)
	}
	// The worst-affected host must be grouped first.
	if strings.Index(html, ">10.0.0.5<") > strings.Index(html, ">10.0.0.6<") {
		t.Error("hosts should be ordered by their worst finding")
	}
}

func TestHTMLHasPrintRules(t *testing.T) {
	if !strings.Contains(renderString(t, fixture()), "@media print") {
		t.Error("the report must carry print rules; buyers print it to PDF")
	}
}

// Severity is colour-coded but never colour-alone (accessibility, and the
// report prints to greyscale).
func TestSeverityIsNotConveyedByColourAlone(t *testing.T) {
	html := renderString(t, fixture())
	if !regexp.MustCompile(`<span class="sev critical">critical</span>`).MatchString(html) {
		t.Error("severity should be spelled out as text next to its colour")
	}
}

func TestCleanScanReportsNoFindings(t *testing.T) {
	html := renderString(t, cleanFixture())
	if !strings.Contains(html, "No exposure findings") {
		t.Error("a clean scan should say so plainly")
	}
	if !strings.Contains(html, `class="grade g-A"`) {
		t.Error("a clean scan should render an A badge")
	}
	// A is the ceiling at L1, and the report has to say so where the grade is,
	// not in a footnote - the grade is the part that gets quoted.
	if !strings.Contains(html, "A is the ceiling at this tier") {
		t.Error("the report must state that A+ is unavailable at this tier")
	}
	if strings.Contains(html, `class="grade g-Aplus"`) {
		t.Error("a Level 1 scan rendered an A+ badge; A+ claims attested hardware")
	}
}

// gradeClass still has to handle A+ even though L1 never produces it: the grade
// exists for the attested tiers, and "+" is not valid in a CSS class name, so
// the mapping is covered directly rather than incidentally through a fixture.
func TestGradeClassIsCSSSafe(t *testing.T) {
	for grade, want := range map[domain.Grade]string{
		"A+": "Aplus", "A": "A", "B": "B", "C": "C", "F": "F",
		domain.GradeInconclusive: "NA",
	} {
		if got := gradeClass(grade); got != want {
			t.Errorf("gradeClass(%q) = %q, want %q", grade, got, want)
		}
	}
}

func TestPrintSummaryIncludesGradeAndFixList(t *testing.T) {
	var buf bytes.Buffer
	PrintSummary(&buf, fixture())
	out := buf.String()
	for _, want := range []string{"Grade: F", "remote code execution", "Fix these first", "RG-RAY-001"} {
		if !strings.Contains(out, want) {
			t.Errorf("terminal summary missing %q:\n%s", want, out)
		}
	}
	// The critical finding must be listed first, not in scan order.
	if strings.Index(out, "RG-RAY-001") > strings.Index(out, "RG-OLLAMA-001") {
		t.Error("the fix list should be ordered worst-first")
	}
}

func TestWriteEmitsBothArtifacts(t *testing.T) {
	dir := t.TempDir()
	if err := Write(dir, fixture()); err != nil {
		t.Fatalf("write: %v", err)
	}
	for _, name := range []string{"report.json", "report.html"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("expected %s to be written: %v", name, err)
		}
	}
}

// interruptedFixture is the same scan as fixture(), stopped after 4 of 254
// targets. It is a golden file because a partial report is an artifact a buyer
// may well read - the operator who stopped the scan is not always the person
// who opens the HTML afterwards.
func interruptedFixture() domain.ScanResult {
	full := fixture()
	r := domain.NewResult(domain.Run{Start: full.StartedAt, End: full.CompletedAt, Requested: 254,
		Hosts:    respondedHosts("10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.0.8"),
		Findings: full.Findings, Interrupted: true})
	r.Label = full.Label
	r.ScannedFrom = full.ScannedFrom
	return r
}

func TestGoldenInterruptedHTML(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderHTML(&buf, interruptedFixture()); err != nil {
		t.Fatalf("render: %v", err)
	}
	goldenCheck(t, "interrupted.golden.html", buf.Bytes())
}

// TestInterruptedHTMLSaysSoBeforeTheFindings: a reader who skims the top of
// the page must learn that it is partial there, not three sections down.
func TestInterruptedHTMLSaysSoBeforeTheFindings(t *testing.T) {
	html := renderString(t, interruptedFixture())
	banner := strings.Index(html, "Scan interrupted")
	if banner < 0 {
		t.Fatal("no interruption notice in the report")
	}
	if findings := strings.Index(html, "Fix these first"); banner > findings {
		t.Error("the interruption notice comes after the findings list")
	}
	if !strings.Contains(html, "4 of 254 target(s) were probed") {
		t.Error("the notice does not say how much of the scan ran")
	}
}

// TestInterruptedCleanScanShowsNoScore: a stopped scan that happened to see
// nothing has no score, and must not display one - a "0/100" would read as a
// catastrophic finding and a "100/100" as a pass. Neither is true.
func TestInterruptedCleanScanShowsNoScore(t *testing.T) {
	start := time.Date(2026, 9, 20, 14, 0, 0, 0, time.UTC)
	r := domain.NewResult(domain.Run{Start: start, End: start.Add(2 * time.Second),
		Requested: 254, Hosts: respondedHosts("10.0.0.5"), Interrupted: true})
	html := renderString(t, r)
	if strings.Contains(html, "Score ") {
		t.Error("a score is rendered for an interrupted scan with nothing to grade")
	}
	if !strings.Contains(html, "N/A") {
		t.Error("the grade is not N/A")
	}

	var buf bytes.Buffer
	PrintSummary(&buf, r)
	out := buf.String()
	if !strings.Contains(out, "INCOMPLETE") {
		t.Errorf("terminal summary does not say the scan was incomplete:\n%s", out)
	}
	if !strings.Contains(out, "1 of 254") {
		t.Errorf("terminal summary does not state coverage:\n%s", out)
	}
	if !strings.Contains(out, "Do not read this as a clean result") {
		t.Errorf("terminal summary does not warn against reading it as clean:\n%s", out)
	}
}

// degradedFixture is a run whose own probes failed part-way: the shape a scan
// takes when the machine it runs from is out of file descriptors.
func degradedFixture() domain.ScanResult {
	full := fixture()
	hosts := respondedHosts("10.0.0.5", "10.0.0.6")
	hosts = append(hosts, domain.HostSummary{Host: "10.0.0.7", State: domain.HostProbeFailed})
	r := domain.NewResult(domain.Run{Start: full.StartedAt, End: full.CompletedAt,
		Requested: 3, Hosts: hosts, Findings: full.Findings, ProbeErrors: 11})
	r.Label = full.Label
	r.ScannedFrom = full.ScannedFrom
	return r
}

func TestGoldenDegradedHTML(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderHTML(&buf, degradedFixture()); err != nil {
		t.Fatalf("render: %v", err)
	}
	goldenCheck(t, "degraded.golden.html", buf.Bytes())
}

// TestDegradedHTMLNamesTheCauseAndTheFix. The whole value of surfacing this is
// that the operator can act on it in one command; a banner that said only
// "results may be incomplete" would send them back to the customer instead of
// to their own shell.
func TestDegradedHTMLNamesTheCauseAndTheFix(t *testing.T) {
	html := renderString(t, degradedFixture())
	banner := strings.Index(html, "under-reports")
	if banner < 0 {
		t.Fatal("no degradation notice in the report")
	}
	if findings := strings.Index(html, "Fix these first"); banner > findings {
		t.Error("the degradation notice comes after the findings list")
	}
	for _, want := range []string{"11 probe(s) failed", "ulimit -Hn", "-concurrency",
		"not a finding about the targets"} {
		if !strings.Contains(html, want) {
			t.Errorf("the notice does not mention %q", want)
		}
	}
}

// TestProbeFailedHostIsExplainedCorrectly: listing it as "no response
// (firewalled, powered off...)" would point the operator at the customer's
// network for a problem on their own machine.
func TestProbeFailedHostIsExplainedCorrectly(t *testing.T) {
	html := renderString(t, degradedFixture())
	i := strings.Index(html, "10.0.0.7")
	if i < 0 {
		t.Fatal("the probe-failed host is not listed in the coverage section")
	}
	end := i + 220
	if end > len(html) {
		end = len(html)
	}
	entry := html[i:end]
	if !strings.Contains(entry, "scanner's own probes failed") {
		t.Errorf("the host is not explained as a scanner-side failure: %q", entry)
	}
	if strings.Contains(entry, "firewalled") {
		t.Errorf("the host is blamed on the customer's network: %q", entry)
	}
}

func TestPrintSummaryWarnsAboutProbeFailures(t *testing.T) {
	var buf bytes.Buffer
	PrintSummary(&buf, degradedFixture())
	out := buf.String()
	for _, want := range []string{"WARNING", "under-reports", "ulimit -Hn", "1 probe failures"} {
		if !strings.Contains(out, want) {
			t.Errorf("terminal summary does not mention %q:\n%s", want, out)
		}
	}
}

// multiAddressFixture is a scan of a name that fans out across three machines
// and a plain address beside it. One address per name was probed, which is
// the shape round-robin or headless-service DNS produces in any real cluster.
func multiAddressFixture() domain.ScanResult {
	full := fixture()
	start := full.StartedAt
	hosts := []domain.HostSummary{
		{Host: "ray.customer.internal", State: domain.HostResponded,
			Address: "10.0.0.5", AddressesFound: 3},
		{Host: "10.0.0.6", State: domain.HostResponded},
	}
	findings := []domain.Finding{full.Findings[0]}
	findings[0].Host = "ray.customer.internal"
	r := domain.NewResult(domain.Run{Start: start, End: full.CompletedAt,
		Requested: 2, Hosts: hosts, Findings: findings})
	r.Label = full.Label
	r.ScannedFrom = full.ScannedFrom
	return r
}

func TestGoldenMultiAddressHTML(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderHTML(&buf, multiAddressFixture()); err != nil {
		t.Fatalf("render: %v", err)
	}
	goldenCheck(t, "multiaddress.golden.html", buf.Bytes())
}

// The coverage gap has to be stated ABOVE the findings, for the same reason
// the degradation banner is: a reader who stops at the first table has to
// have been told that the table describes one of three machines.
func TestMultiAddressHTMLDisclosesTheGapBeforeTheFindings(t *testing.T) {
	html := renderString(t, multiAddressFixture())
	banner := strings.Index(html, "were not assessed")
	if banner < 0 {
		t.Fatal("no coverage-gap notice for a name that resolved to several addresses")
	}
	if findings := strings.Index(html, "Fix these first"); banner > findings {
		t.Error("the coverage gap is stated below the findings; a reader who stops at the " +
			"first table would not know this covers one machine of three")
	}
	for _, want := range []string{"ray.customer.internal", "10.0.0.5", "3 addresses"} {
		if !strings.Contains(html, want) {
			t.Errorf("the notice does not name %q", want)
		}
	}
}

// Every finding against a name has to say which machine answered, or it
// cannot be re-checked - and on a fanned-out name it does not even identify
// its own subject.
func TestFindingsAgainstANameRecordTheProbedAddress(t *testing.T) {
	html := renderString(t, multiAddressFixture())
	if !strings.Contains(html, "probed at 10.0.0.5") {
		t.Error("the host heading does not state the address its probes dialed")
	}
	// An address target has nothing to add, so it must not be repeated.
	if strings.Contains(html, "probed at 10.0.0.6") {
		t.Error("an address target was annotated with itself")
	}
}

// The text report is what an operator sees in the terminal, and it is where
// the remedy belongs: the gap is theirs to close by passing the addresses.
func TestTextReportWarnsAboutUnassessedAddresses(t *testing.T) {
	var buf bytes.Buffer
	PrintSummary(&buf, multiAddressFixture())
	out := buf.String()
	for _, want := range []string{
		"ray.customer.internal resolves to 3 addresses",
		"only 10.0.0.5 was assessed",
		"Pass them as targets",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the text report does not say %q:\n%s", want, out)
		}
	}
}
