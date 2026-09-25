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
	return domain.NewScanResult(start, start.Add(12*time.Second), respondedHosts("10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.0.8"), findings)
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
	if !strings.Contains(html, `class="grade g-Aplus"`) {
		t.Error("a clean scan should render an A+ badge with a CSS-safe class name")
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
