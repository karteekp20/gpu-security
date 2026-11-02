package report

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
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
			// One asserted, one cited-but-unconfirmed, which is the shape the
			// real rule now produces and the case the golden file must show.
			CVEs: []string{"CVE-2023-48022"},
			UnconfirmedCVEs: []domain.UnconfirmedCVE{{
				ID: "CVE-2025-62593", FixedIn: "2.52.0",
				Why: "Fixed in Ray 2.52.0, and this scan did not determine your version.",
			}}},
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
	// The parameters are part of the same artifact and for the same reason:
	// "no response" is only interpretable alongside how long a host was given
	// to answer. The ordinary, unclamped case belongs in the reference report;
	// the clamped disclosure has its own test so the golden does not present
	// a constrained machine as typical.
	r.Params = &domain.ScanParams{
		ProbeTimeout: "4s",
		Concurrency:  32,
		Ports:        []int{8000, 8265, 8888, 11434},
		CIDR:         []string{"10.0.0.0/29"},
	}
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
	for _, pattern := range []string{`src=`, `href=`, `@import`} {
		if strings.Contains(html, pattern) {
			t.Errorf("report references an external asset via %q", pattern)
		}
	}
	// `url(` was a flat ban until the coverage bar needed `fill:url(#cov-hatch)`
	// to reference a pattern defined in the same document. The gate is kept
	// rather than dropped, narrowed to its actual intent: a fragment
	// reference resolves inside this file, anything else leaves it. Written as
	// "every url( is followed by #" so a future `url(https://fonts...)` still
	// fails, which a weakened substring check would have waved through.
	for i := 0; ; {
		j := strings.Index(html[i:], "url(")
		if j < 0 {
			break
		}
		i += j + len("url(")
		if i >= len(html) || html[i] != '#' {
			t.Errorf("report references an external asset via url(%.40s", html[i:])
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

func renderFixtureHTML(t *testing.T) string {
	t.Helper()
	var buf bytes.Buffer
	if err := RenderHTML(&buf, fixture()); err != nil {
		t.Fatalf("render: %v", err)
	}
	return buf.String()
}

// TestUnconfirmedCVEIsMarkedAndExplainedInHTML is the report half of the
// change that split asserted from unconfirmed CVEs. The pill alone is not
// enough: a reader scanning the findings table has to be able to tell which
// of the two a CVE is, and be told the check that settles it, without
// leaving the row.
func TestUnconfirmedCVEIsMarkedAndExplainedInHTML(t *testing.T) {
	html := renderFixtureHTML(t)

	if !strings.Contains(html, "CVE-2025-62593 &middot; unconfirmed") {
		t.Error("the unconfirmed CVE is not marked as such in the findings table; a bare " +
			"pill reads identically to an asserted CVE")
	}
	if !strings.Contains(html, "CVE-2025-62593 is not confirmed here (advisory says fixed in 2.52.0)") {
		t.Error("the row does not say why the CVE is unconfirmed, or does not name the " +
			"fixed version the advisory gives")
	}
	if !strings.Contains(html, "did not determine your version") {
		t.Error("the `why` text did not reach the HTML")
	}
	// The asserted one must NOT be dressed up as unconfirmed.
	if strings.Contains(html, "CVE-2023-48022 &middot; unconfirmed") {
		t.Error("CVE-2023-48022 is asserted - the advisory names no fixed version, so " +
			"reachability is the whole condition")
	}
	// Never colour alone (CLAUDE.md §7.6, and the report prints to greyscale).
	if !strings.Contains(html, ".pill.unconf{border-style:dashed") {
		t.Error("the unconfirmed pill has no non-colour treatment")
	}
}

// TestTheNarrativeDoesNotAssertTheVersionGatedCVE guards the prose, which is
// the part a buyer actually reads. It previously called CVE-2025-62593
// "version-specific" and then leaned on its CISA KEV listing in the same
// breath, which invites the reader to treat it as a finding.
func TestTheNarrativeDoesNotAssertTheVersionGatedCVE(t *testing.T) {
	html := renderFixtureHTML(t)
	i := strings.Index(html, "What we are not claiming")
	if i < 0 {
		t.Fatal("the narrative no longer separates what is asserted from what is not")
	}
	section := html[i:]
	for _, want := range []string{"2.52.0", "cves_unconfirmed", "DNS rebinding"} {
		if !strings.Contains(section, want) {
			t.Errorf("the narrative does not mention %q, so the reader cannot tell why "+
				"we decline to assert it", want)
		}
	}
}

// TestReportStatesTheTimeoutItMeasuredWith. The report's own coverage section
// says targets gave "no response". That is a claim about a duration, and
// without the duration a reader cannot tell a firewalled host from one that
// was 200ms slower than a 1s timeout - nor compare this report with the next
// one. G5's acceptance criterion is that a reader can reproduce the scan from
// the report alone.
func TestReportStatesTheTimeoutItMeasuredWith(t *testing.T) {
	html := renderFixtureHTML(t)

	for _, want := range []string{
		"-timeout 4s",
		"-concurrency 32",
		"8000, 8265, 8888, 11434",
		"10.0.0.0/29",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("the report does not state %q, so the scan cannot be reproduced from it", want)
		}
	}

	// The timeout has to be stated as what it means, not only as a flag: a
	// number in a parameter table is provenance, while "silent for 4s" is the
	// qualifier on every no-response line above it.
	if !strings.Contains(html, "silent for 4s") {
		t.Error("the report prints the timeout without saying what it means for the " +
			"no-response rows it qualifies")
	}
}

// TestClampedConcurrencyIsDisclosedInTheReport. The scanner clamps
// concurrency to what the local open-file limit sustains, and deliberately
// does NOT mark such a run degraded, because the clamp is what keeps the
// measurement correct. The cost of that choice is that the artifact has no
// other trace of it: a scan that took four minutes instead of seventeen
// seconds reads as the operator's own setting. This is the disclosure.
func TestClampedConcurrencyIsDisclosedInTheReport(t *testing.T) {
	r := fixture()
	r.Params = &domain.ScanParams{
		ProbeTimeout: "4s", Concurrency: 8, ConcurrencyRequested: 64,
		Ports: []int{8265},
	}
	var buf bytes.Buffer
	if err := RenderHTML(&buf, r); err != nil {
		t.Fatalf("render: %v", err)
	}
	html := buf.String()

	if !strings.Contains(html, "-concurrency 8") {
		t.Error("the report does not state the concurrency the scan actually ran at")
	}
	if !strings.Contains(html, "reduced from the 64 requested") {
		t.Error("the report states the clamped value without saying it was clamped; " +
			"a constrained machine then reads as a deliberate choice")
	}
	// And it must not read as a coverage problem, because it is not one.
	if !strings.Contains(html, "Coverage and findings are unaffected") {
		t.Error("the clamp disclosure does not say what it did and did not affect; an " +
			"unqualified notice invites the reader to discount the whole scan")
	}
}

// TestReportRendersWithoutParameters. Params is a pointer because absent is a
// real state: a result assembled from something that was not a scanner run has
// no flags to report, and the template must not invent defaults or fail.
func TestReportRendersWithoutParameters(t *testing.T) {
	r := cleanFixture()
	if r.Params != nil {
		t.Fatal("cleanFixture now carries parameters; this test no longer covers the nil case")
	}
	var buf bytes.Buffer
	if err := RenderHTML(&buf, r); err != nil {
		t.Fatalf("render: %v", err)
	}
	if strings.Contains(buf.String(), "-timeout") {
		t.Error("the report printed a timeout for a result that never recorded one")
	}
}

// The coverage bar is the only chart on the report. Its job is to make the
// number a reader skips impossible to skip: how much of what they asked for
// was actually looked at.
func TestCoverageBarShowsEveryStateATargetEndedIn(t *testing.T) {
	start := time.Date(2026, 9, 20, 14, 0, 0, 0, time.UTC)
	hosts := respondedHosts("10.0.0.5", "10.0.0.6")
	hosts = append(hosts,
		domain.HostSummary{Host: "10.0.0.7", State: domain.HostNoResponse},
		domain.HostSummary{Host: "10.0.0.8", State: domain.HostNoResponse},
		domain.HostSummary{Host: "10.0.0.9", State: domain.HostNoResponse},
		domain.HostSummary{Host: "ray.example.internal", State: domain.HostUnresolved},
		domain.HostSummary{Host: "10.0.0.11", State: domain.HostProbeFailed},
	)
	r := domain.NewResult(domain.Run{
		Start: start, End: start.Add(8 * time.Second),
		Requested: 10, Hosts: hosts, Interrupted: true, ProbeErrors: 1,
	})
	html := renderString(t, r)

	// Every count the bar encodes must also be readable as text: the chart is
	// never the only place a coverage fact appears (section 7.6, and the
	// report prints to greyscale).
	want := "10 targets requested: 2 responded, 3 no response, 1 unresolved, " +
		"1 probe failed, 3 not probed."
	if !strings.Contains(html, want) {
		t.Errorf("coverage sentence missing or wrong; want %q", want)
	}
	for _, class := range []string{"seg-ok", "seg-silent", "seg-unresolved", "seg-failed", "seg-notprobed"} {
		// `class="..."` rather than the bare name, because the stylesheet
		// carries a rule for every state whether or not it is drawn. Twice
		// each in the markup: once in the bar, once in the legend swatch.
		if n := strings.Count(html, `class="`+class+`"`); n != 2 {
			t.Errorf("segment %q appears %d time(s) in the markup, want 2 (bar + legend)", class, n)
		}
	}
	// This run was stopped, so the note must say the unreached targets were
	// never looked at - not that they "stayed silent", which is a claim about
	// them rather than about us.
	if !strings.Contains(html, "never reached were not assessed at all") {
		t.Error("an interrupted scan's coverage note must say the rest were never probed")
	}
}

// The ordinary partial case: the scan finished, and some hosts said nothing.
// This is the sentence the whole chart exists for.
func TestSilentHostsAreNotReportedAsCoverage(t *testing.T) {
	hosts := []domain.HostSummary{{Host: "10.0.0.5", State: domain.HostResponded}}
	for i := 6; i <= 9; i++ {
		hosts = append(hosts, domain.HostSummary{
			Host: "10.0.0." + strconv.Itoa(i), State: domain.HostNoResponse})
	}
	html := renderString(t, domain.NewResult(domain.Run{
		Requested: len(hosts), Hosts: hosts,
	}))
	if !strings.Contains(html, "5 targets requested: 1 responded, 4 no response.") {
		t.Error("the coverage sentence should state both counts")
	}
	if !strings.Contains(html, "missing information rather than a clean result") {
		t.Error("a scan with silent hosts must say the gap is not a pass")
	}
}

// A name resolving to several addresses is a coverage gap in a different unit
// from the bar's. Both names answered here, so the bar is a full green block -
// on a run graded N/A for exactly the coverage the bar cannot show. The note
// has to carry that, or the chart contradicts the grade beside it.
func TestFullTargetCoverageIsQualifiedWhenAddressesWereNotAssessed(t *testing.T) {
	r := multiAddressFixture()
	if r.AddressesUnassessed == 0 {
		t.Fatal("fixture no longer has unassessed addresses")
	}
	html := renderString(t, r)
	if strings.Contains(html, "the grade above covers all of them") {
		t.Error("a run with unassessed addresses must not claim the grade covers everything")
	}
	if !strings.Contains(html, "counts the targets you named, not the machines behind them") {
		t.Error("the coverage note must say what unit the bar is in")
	}
	if !strings.Contains(html, "behind those names were not assessed") {
		t.Error("the coverage note must state the unassessed addresses")
	}
}

// The three "not assessed" states are distinguished by texture as well as by
// fill. The report prints, and it prints to greyscale, where three fills that
// differ only in lightness are one indistinguishable grey band.
func TestCoverageStatesAreNotDistinguishedByColourAlone(t *testing.T) {
	html := renderString(t, domain.NewResult(domain.Run{
		Requested: 4,
		Hosts: []domain.HostSummary{
			{Host: "10.0.0.5", State: domain.HostResponded},
			{Host: "10.0.0.6", State: domain.HostNoResponse},
			{Host: "ray.example.internal", State: domain.HostUnresolved},
			{Host: "10.0.0.8", State: domain.HostProbeFailed},
		},
		ProbeErrors: 1,
	}))
	for _, id := range []string{"cov-hatch", "cov-vert", "cov-horz"} {
		// Defined once in <defs>, referenced once from the stylesheet.
		if n := strings.Count(html, id); n != 2 {
			t.Errorf("pattern %q appears %d time(s), want 2 (definition + reference)", id, n)
		}
	}
}

// A single probe-failed host in a /24 is 0.39% of the bar - two tenths of a
// user unit, which rounds to nothing. A coverage gap that renders as invisible
// is the defect this chart exists to prevent, so a present state is always
// drawn wide enough to see.
func TestASingleUnassessedHostIsStillVisibleOnTheBar(t *testing.T) {
	hosts := make([]domain.HostSummary, 0, 254)
	for i := 1; i <= 253; i++ {
		hosts = append(hosts, domain.HostSummary{
			Host: "10.0.0." + strconv.Itoa(i), State: domain.HostResponded})
	}
	hosts = append(hosts, domain.HostSummary{Host: "10.0.0.254", State: domain.HostProbeFailed})

	segs := coverageSegments(domain.NewResult(domain.Run{
		Requested: len(hosts), Hosts: hosts, ProbeErrors: 1,
	}))
	if len(segs) != 2 {
		t.Fatalf("expected responded + probe-failed, got %v", segs)
	}

	svg := string(coverageBarSVG(segs))
	m := regexp.MustCompile(`class="seg-failed" x="([0-9.]+)" y="0" width="([0-9.]+)"`).FindStringSubmatch(svg)
	if m == nil {
		t.Fatalf("no probe-failed segment in the bar: %s", svg)
	}
	w, err := strconv.ParseFloat(m[2], 64)
	if err != nil {
		t.Fatalf("parsing width %q: %v", m[2], err)
	}
	if w < minSegment {
		t.Errorf("1-of-254 segment rendered %v units wide, below the %d-unit floor", w, minSegment)
	}
	// The floor must not be bought by letting the bar overflow or underflow:
	// the last segment ends exactly at the right edge.
	x, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		t.Fatalf("parsing x %q: %v", m[1], err)
	}
	if got := x + w; got != float64(barWidth) {
		t.Errorf("bar ends at %v, want exactly %d", got, barWidth)
	}
}

// Full coverage is a claim worth printing. The section renders on every report
// so that a reader comparing two of them finds it in the same place, rather
// than learning that its absence was the good news.
func TestFullCoverageIsStatedPositively(t *testing.T) {
	html := renderString(t, cleanFixture())
	if !strings.Contains(html, "4 targets requested: 4 responded.") {
		t.Error("a fully covered scan should still state its coverage")
	}
	if !strings.Contains(html, "Every target in scope answered") {
		t.Error("full coverage should be stated as a positive claim")
	}
	for _, absent := range []string{"seg-silent", "seg-notprobed"} {
		if strings.Contains(html, `class="`+absent+`"`) {
			t.Errorf("state %q has no targets and should not be drawn", absent)
		}
	}
}

// A scan that reached nothing is the case the chart must not flatter: a full
// bar of "no response" alongside an N/A grade, said plainly.
func TestAnUnreachedScanDoesNotReadAsCoverage(t *testing.T) {
	start := time.Date(2026, 9, 20, 14, 0, 0, 0, time.UTC)
	hosts := []domain.HostSummary{
		{Host: "10.0.0.5", State: domain.HostNoResponse},
		{Host: "10.0.0.6", State: domain.HostNoResponse},
	}
	html := renderString(t, domain.NewResult(domain.Run{
		Start: start, End: start.Add(4 * time.Second), Requested: 2, Hosts: hosts,
	}))
	if !strings.Contains(html, "2 targets requested: 2 no response.") {
		t.Error("an unreached scan should state that nothing answered")
	}
	if !strings.Contains(html, "it records that we did not see them") {
		t.Error("an unreached scan's coverage note must deny it is a verdict")
	}
	if strings.Contains(html, `class="seg-ok"`) {
		t.Error("nothing responded, so there is no responded segment to draw")
	}
}

// A result that is not a scanner run - no targets, no hosts - has no coverage
// to draw, and an empty bar would be a chart asserting something about nothing.
func TestNoTargetsRendersNoCoverageSection(t *testing.T) {
	html := renderString(t, domain.NewResult(domain.Run{}))
	if strings.Contains(html, `class="covbar"`) {
		t.Error("a run with no targets should render no coverage bar")
	}
	if strings.Contains(html, "<h2>Coverage</h2>") {
		t.Error("the coverage section should be skipped when there is nothing to show")
	}
}

// The coverage bar is the one place in the report where we build markup
// ourselves and hand it to the template already trusted (template.HTML). That
// is safe only because nothing from the scan reaches it - the chart is a
// picture of counts. This test holds that premise down rather than leaving it
// to the comment beside the conversion, because the failure mode is a future
// change that adds a host name to a legend row and silently makes the
// annotation false.
func TestTheCoverageBarCarriesNoScannedInput(t *testing.T) {
	hostile := `<script>alert(1)</script>`
	r := domain.NewResult(domain.Run{
		Requested: 3,
		Hosts: []domain.HostSummary{
			{Host: hostile, State: domain.HostResponded},
			{Host: hostile + "-2", State: domain.HostNoResponse},
			{Host: hostile + "-3", State: domain.HostUnresolved},
		},
		Params: &domain.ScanParams{
			ProbeTimeout: hostile, Concurrency: 1,
			TargetsFile: hostile, CIDR: []string{hostile},
		},
	})
	r.Label = hostile
	r.ScannedFrom = hostile

	html := renderString(t, r)
	start := strings.Index(html, `<svg class="covbar"`)
	if start < 0 {
		t.Fatal("no coverage bar in the report")
	}
	svg := html[start : start+strings.Index(html[start:], "</svg>")]
	if strings.Contains(svg, "script") || strings.Contains(svg, hostile) {
		t.Errorf("scanned input reached the coverage bar: %s", svg)
	}
	// And the hostile strings that do belong on the report are escaped by the
	// template as usual, so this is a statement about the chart, not a claim
	// that the report drops them.
	if !strings.Contains(html, "&lt;script&gt;") {
		t.Error("expected the template to escape scanned input elsewhere on the page")
	}
}
