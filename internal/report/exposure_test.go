package report

import (
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"gpusecurity/internal/domain"
)

// The host x port exposure strip (C2). The property that makes it worth
// drawing is that it shows hosts with NO findings, so these tests are mostly
// about the quiet rows and about the one thing this chart does that the
// coverage bar does not: put host names into generated markup.

func stripResult(hosts []domain.HostSummary, findings []domain.Finding, ports ...int) domain.ScanResult {
	start := time.Date(2026, 11, 5, 9, 0, 0, 0, time.UTC)
	return domain.NewResult(domain.Run{
		Start: start, End: start.Add(time.Second),
		Requested: len(hosts), Hosts: hosts, Findings: findings,
		Params: &domain.ScanParams{ProbeTimeout: "2s", Concurrency: 32, Ports: ports},
	})
}

// TestTheExposureStripEscapesHostNames is the guard that the coverage bar did
// not need. coverageBarSVG discharges its trusted-markup suppression by never
// handling a string from the scan; this chart's row labels ARE strings from the
// scan, so that argument does not transfer and escaping has to be real.
//
// A host name is operator-supplied (-targets, -targets-file) or resolver-
// supplied, and the report is a file a security lead opens in a browser.
func TestTheExposureStripEscapesHostNames(t *testing.T) {
	// Two payloads: one short enough to survive the label column whole, and
	// one long enough to be truncated, since truncation is where an escaping
	// scheme usually breaks (a cut landing inside an entity).
	short := `<b>pwn</b>`
	long := `<script>alert(1)</script>`
	r := stripResult(
		respondedHosts(short, long),
		[]domain.Finding{{
			RuleID: "RG-RAY-001", Title: "x", Severity: domain.Critical,
			Host: short, Port: 8265, Service: "ray-dashboard",
			Evidence: domain.Evidence{Level: domain.EvidenceObserved, Basis: domain.BasisServiceAPI},
		}},
		8265, 8888,
	)

	html := renderString(t, r)
	svg := extractSVG(t, html, `<svg class="expstrip"`)
	for _, live := range []string{"<script", "<b>", "</b>", "onload"} {
		if strings.Contains(svg, live) {
			t.Errorf("live markup %q inside the exposure strip: %s", live, svg)
		}
	}
	// It must still have drawn the labels, escaped - a test that passes
	// because the label was dropped proves nothing.
	if !strings.Contains(svg, "&lt;b&gt;pwn&lt;/b&gt;") {
		t.Error("the short host label never reached the strip escaped; this test is " +
			"not exercising what it claims to")
	}
	if !strings.Contains(svg, "&lt;/script&gt;") {
		t.Error("the truncated host label lost its escaping")
	}
}

// TestStripLabelTruncatesByRunes. The label column is a byte slice away from
// emitting invalid UTF-8 into an SVG document: an internationalized hostname
// cut at a byte offset splits a rune, and nothing is required to render the
// result. Cheap to get right, invisible when wrong until a customer has one.
func TestStripLabelTruncatesByRunes(t *testing.T) {
	// Deliberately all two-byte runes and no ASCII tail: the byte offset a
	// naive implementation cuts at is len-21, which for a 2n-byte string is
	// always odd and so always lands mid-rune. An earlier version of this
	// test appended ".internal", which made the offset even and let a byte
	// slice pass by luck.
	host := strings.Repeat("ü", 40)
	got := stripLabel(host)
	if !utf8ValidString(got) {
		t.Errorf("stripLabel produced invalid UTF-8: %q", got)
	}
	if n := len([]rune(got)); n != stripMaxLabel {
		t.Errorf("label is %d runes, want %d (the ellipsis plus %d kept)",
			n, stripMaxLabel, stripMaxLabel-1)
	}
	if !strings.HasPrefix(got, "…") {
		t.Errorf("a long label should be elided from the left, got %q", got)
	}
	// And a short label is returned whole.
	if got := stripLabel("10.0.0.5"); got != "10.0.0.5" {
		t.Errorf("stripLabel(%q) = %q, want it unchanged", "10.0.0.5", got)
	}
}

// TestTheExposureStripDrawsHostsWithNoFindings is C2's entire reason for
// existing. "Does this thing flag everything it touches?" cannot be answered
// from a findings list, because the hosts that came back clean are not in one.
func TestTheExposureStripDrawsHostsWithNoFindings(t *testing.T) {
	r := stripResult(
		respondedHosts("10.0.0.10", "10.0.0.40"),
		[]domain.Finding{{
			RuleID: "RG-RAY-001", Title: "x", Severity: domain.Critical,
			Host: "10.0.0.10", Port: 8265, Service: "ray-dashboard",
		}},
		8265, 8888,
	)

	strip := buildExposureStrip(r)
	if len(strip.Rows) != 2 {
		t.Fatalf("drew %d rows, want 2: the clean host must have a row of its own", len(strip.Rows))
	}
	if strip.Quiet != 1 {
		t.Errorf("Quiet = %d, want 1", strip.Quiet)
	}

	var quiet *stripRow
	for i := range strip.Rows {
		if strip.Rows[i].Host == "10.0.0.40" {
			quiet = &strip.Rows[i]
		}
	}
	if quiet == nil {
		t.Fatal("the host that answered and raised nothing is absent from the strip")
	}
	for ci, sev := range quiet.Cells {
		if sev != "" {
			t.Errorf("quiet host has severity %q in column %d", sev, ci)
		}
	}

	// And it must say so in words too, because the picture is not allowed to
	// be the only place a fact lives.
	html := renderString(t, r)
	if !strings.Contains(html, "raised no finding") {
		t.Error("the sentence above the strip does not state the quiet-host count")
	}
	if !strings.Contains(html, "not that the port is closed") {
		t.Error("the note does not disclaim the empty cells; a blank cell is not a closed port")
	}
}

// TestAPortlessFindingGetsItsOwnColumn. The bucket rule is the case: an object
// store is named by URL and its finding carries no port. Bucket hosts DO enter
// the result as responded hosts (cmd/ray-guard appends one per -buckets
// entry), so without a column for them a public bucket draws as a row of empty
// cells - a High finding rendered as a clean host, which is the one error this
// chart must never make.
func TestAPortlessFindingGetsItsOwnColumn(t *testing.T) {
	r := stripResult(
		respondedHosts("bucket.example.invalid"),
		[]domain.Finding{{
			RuleID: "RG-BUCKET-001", Title: "x", Severity: domain.High,
			Host: "bucket.example.invalid", Port: 0, Service: "bucket",
		}},
		8265,
	)

	strip := buildExposureStrip(r)
	if got := strip.Columns[len(strip.Columns)-1]; got != portlessColumn {
		t.Fatalf("last column = %q, want %q", got, portlessColumn)
	}
	if strip.Quiet != 0 {
		t.Fatalf("Quiet = %d, want 0: the bucket host has a High finding and must not "+
			"count as quiet", strip.Quiet)
	}
	row := strip.Rows[0]
	if row.Cells[len(row.Cells)-1] != domain.High {
		t.Errorf("the bucket finding is not drawn: cells = %v", row.Cells)
	}
}

// TestTheExposureStripBoundsItsRows. This is the first chart whose height
// grows with the scan, and the report is an email attachment. Truncation is
// fine; silent truncation is not.
func TestTheExposureStripBoundsItsRows(t *testing.T) {
	var hosts []domain.HostSummary
	var findings []domain.Finding
	for i := 0; i < maxStripRows+12; i++ {
		h := "10.0.0." + itoa(i)
		hosts = append(hosts, domain.HostSummary{Host: h, State: domain.HostResponded})
		// Give only the last few the worst severity, so the ranking has
		// something to do and we can prove it kept the right rows.
		sev := domain.Low
		if i >= maxStripRows+9 {
			sev = domain.Critical
		}
		findings = append(findings, domain.Finding{
			RuleID: "RG-TEST-001", Title: "x", Severity: sev,
			Host: h, Port: 8265, Service: "svc",
		})
	}
	r := stripResult(hosts, findings, 8265)

	strip := buildExposureStrip(r)
	if len(strip.Rows) != maxStripRows {
		t.Fatalf("drew %d rows, want the cap of %d", len(strip.Rows), maxStripRows)
	}
	if strip.Omitted != 12 {
		t.Errorf("Omitted = %d, want 12", strip.Omitted)
	}
	if strip.Rows[0].worst != domain.Critical {
		t.Errorf("worst row first = %q, want critical: over the cap the rows kept must "+
			"be the ones that matter", strip.Rows[0].worst)
	}

	html := renderString(t, r)
	if !strings.Contains(html, "most severe of") {
		t.Error("a truncated strip does not say it was truncated")
	}
}

// TestACellShowsTheWorstFindingOnThatPort. Two findings on one host and port
// is ordinary - a bad certificate and an obsolete protocol version travel
// together - and the cell has room for one mark.
func TestACellShowsTheWorstFindingOnThatPort(t *testing.T) {
	r := stripResult(
		respondedHosts("10.0.0.5"),
		[]domain.Finding{
			{RuleID: "RG-TLS-003", Title: "x", Severity: domain.Low,
				Host: "10.0.0.5", Port: 8265, Service: "tls"},
			{RuleID: "RG-RAY-001", Title: "x", Severity: domain.Critical,
				Host: "10.0.0.5", Port: 8265, Service: "ray-dashboard"},
			{RuleID: "RG-TLS-001", Title: "x", Severity: domain.Medium,
				Host: "10.0.0.5", Port: 8265, Service: "tls"},
		},
		8265,
	)
	strip := buildExposureStrip(r)
	if got := strip.Rows[0].Cells[0]; got != domain.Critical {
		t.Errorf("cell = %q, want critical: a cell understating its port would invert "+
			"the chart's whole purpose", got)
	}
}

// TestTheExposureStripIsAbsentWhenNothingAnswered. An inconclusive scan has no
// grid to draw, and an empty one would read as "we looked and found nothing".
func TestTheExposureStripIsAbsentWhenNothingAnswered(t *testing.T) {
	start := time.Date(2026, 11, 5, 9, 0, 0, 0, time.UTC)
	r := domain.NewResult(domain.Run{
		Start: start, End: start.Add(time.Second), Requested: 3,
		Hosts: []domain.HostSummary{
			{Host: "10.0.0.1", State: domain.HostNoResponse},
			{Host: "10.0.0.2", State: domain.HostUnresolved},
		},
	})
	if strip := buildExposureStrip(r); len(strip.Rows) != 0 {
		t.Fatalf("drew %d rows for a scan where nothing answered", len(strip.Rows))
	}
	if html := renderString(t, r); strings.Contains(html, "Exposure map") {
		t.Error("the exposure map section rendered on an inconclusive scan")
	}
}

// extractSVG pulls one SVG element out of the page so a test can assert about
// its contents without matching the rest of the report.
func extractSVG(t *testing.T, html, open string) string {
	t.Helper()
	i := strings.Index(html, open)
	if i < 0 {
		t.Fatalf("no element matching %q in the report", open)
	}
	rest := html[i:]
	end := strings.Index(rest, "</svg>")
	if end < 0 {
		t.Fatal("unterminated svg")
	}
	return rest[:end]
}

func utf8ValidString(s string) bool { return utf8.ValidString(s) }

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

// TestTheExposureStripPaletteIsMonotonicInGreyscale. The report prints, and it
// prints to greyscale. "Never colour alone" is satisfied by the severity
// letter in every cell, so the chart stays *correct* whatever the fills do -
// but tone is read before letters are, and a palette whose greyscale ordering
// disagrees with severity actively misleads at a glance.
//
// This was measured, not predicted. The first version reused the .sev pill
// colours, and on a printed page an Info cell came out as dark as a Critical
// one (luminance 102 against 96), on exactly the two hosts that are the
// demo's deliberate negative controls.
//
// Parsed out of the rendered page rather than from a Go table, so the test
// covers the stylesheet that actually ships.
func TestTheExposureStripPaletteIsMonotonicInGreyscale(t *testing.T) {
	html := renderString(t, fixture())

	lum := func(sev domain.Severity) float64 {
		re := regexp.MustCompile(`\.expstrip \.expcell\.` + string(sev) + `\{fill:#([0-9a-fA-F]{6})\}`)
		m := re.FindStringSubmatch(html)
		if m == nil {
			t.Fatalf("no fill declared for .expcell.%s", sev)
		}
		v, err := strconv.ParseUint(m[1], 16, 32)
		if err != nil {
			t.Fatalf("bad colour for %s: %v", sev, err)
		}
		r, g, b := float64((v>>16)&0xff), float64((v>>8)&0xff), float64(v&0xff)
		return 0.299*r + 0.587*g + 0.114*b
	}

	// Worst must be darkest, and every step lighter than the last.
	order := domain.SeverityOrder() // critical, high, medium, low, info
	prev := -1.0
	for _, sev := range order {
		l := lum(sev)
		if l <= prev {
			t.Errorf("%s has luminance %.0f, which is not lighter than the severity "+
				"above it (%.0f): printed, a less severe cell would look at least as "+
				"alarming as a worse one", sev, l, prev)
		}
		prev = l
	}

	// And the extremes must be far enough apart to survive a cheap printer.
	if spread := lum(domain.Info) - lum(domain.Critical); spread < 100 {
		t.Errorf("critical-to-info luminance spread is %.0f, too narrow to read as a "+
			"ramp on paper", spread)
	}
}
