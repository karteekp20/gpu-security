package report

import (
	"strings"
	"testing"
	"time"

	"gpusecurity/internal/domain"
)

// The grade band strip (C3).

func gradedResult(t *testing.T, sev domain.Severity) domain.ScanResult {
	t.Helper()
	start := time.Date(2026, 11, 5, 9, 0, 0, 0, time.UTC)
	return domain.NewScanResult(start, start.Add(time.Second),
		respondedHosts("10.0.0.5"),
		[]domain.Finding{{
			RuleID: "RG-TEST-001", Title: "x", Severity: sev,
			Host: "10.0.0.5", Port: 8265, Service: "svc",
		}})
}

// TestTheGradeBandStripFillsTheBandTheScanLandedIn, and only that one.
func TestTheGradeBandStripFillsTheBandTheScanLandedIn(t *testing.T) {
	for _, tc := range []struct {
		sev  domain.Severity
		want string
	}{
		{domain.Critical, "F"},
		{domain.High, "C"},
		{domain.Medium, "B"},
		{domain.Low, string(domain.L1GradeCeiling)},
	} {
		t.Run(tc.want, func(t *testing.T) {
			bands := buildGradeBands(gradedResult(t, tc.sev))
			if len(bands) == 0 {
				t.Fatal("no bands drawn for a graded run")
			}
			var got []string
			for _, b := range bands {
				if b.Achieved {
					got = append(got, b.Grade)
				}
			}
			if len(got) != 1 {
				t.Fatalf("%d bands marked achieved (%v), want exactly 1", len(got), got)
			}
			if got[0] != tc.want {
				t.Errorf("achieved band = %s, want %s", got[0], tc.want)
			}
		})
	}
}

// TestTheGradeBandStripDrawsTheTierCeiling. A scale that shows A+ as if it
// were available would reintroduce the exact confusion the 2026-10-31
// tier-scoped-grades decision removed: a reader comparing an A against a
// visible A+ concludes something was missed, when the truth is that this tier
// does not award it at all.
func TestTheGradeBandStripDrawsTheTierCeiling(t *testing.T) {
	r := gradedResult(t, domain.Low)
	bands := buildGradeBands(r)

	var unreachable []string
	for _, b := range bands {
		if b.Unreachable {
			unreachable = append(unreachable, b.Grade)
			if b.Achieved {
				t.Errorf("%s is marked both achieved and above the tier ceiling", b.Grade)
			}
		}
	}
	if len(unreachable) != 1 || unreachable[0] != string(domain.GradeAPlus) {
		t.Fatalf("bands above the ceiling = %v, want exactly [A+]", unreachable)
	}

	html := renderString(t, r)
	if !strings.Contains(html, "L3 only") {
		t.Error("the strip does not label the band this tier cannot award")
	}
	if !strings.Contains(html, "not available at Level 1") {
		t.Error("the sentence above the strip does not say the scale is not all available")
	}
}

// TestTheGradeBandStripIsAbsentWhenThereIsNoGrade. N/A is not a position on
// this scale. Drawing the scale with nothing filled invites the reader to
// supply a position, and the one they would supply is the left-hand end -
// rendering "we did not look" as "we looked and it was as bad as possible",
// which is the false-all-clear decision inverted.
func TestTheGradeBandStripIsAbsentWhenThereIsNoGrade(t *testing.T) {
	start := time.Date(2026, 11, 5, 9, 0, 0, 0, time.UTC)
	r := domain.NewResult(domain.Run{
		Start: start, End: start.Add(time.Second), Requested: 2,
		Hosts: []domain.HostSummary{{Host: "10.0.0.1", State: domain.HostNoResponse}},
	})
	if r.Graded() {
		t.Fatal("fixture is graded; this test needs an inconclusive run")
	}
	if bands := buildGradeBands(r); bands != nil {
		t.Errorf("drew %d bands for a run with no grade", len(bands))
	}
	// Checked against the element, not the word: the stylesheet names
	// .bandstrip on every page whether the chart is drawn or not.
	if html := renderString(t, r); strings.Contains(html, `<svg class="bandstrip"`) {
		t.Error("the grade band strip rendered on an inconclusive run")
	}
}

// TestTheGradeBandStripCarriesNoScannedInput. This chart's trusted-markup
// suppression is discharged the way the coverage bar's is - by never handling
// a string that came from the scan - rather than by escaping, so the premise
// needs holding down.
func TestTheGradeBandStripCarriesNoScannedInput(t *testing.T) {
	hostile := `<script>alert(1)</script>`
	start := time.Date(2026, 11, 5, 9, 0, 0, 0, time.UTC)
	r := domain.NewResult(domain.Run{
		Start: start, End: start.Add(time.Second), Requested: 1,
		Hosts: respondedHosts(hostile),
		Findings: []domain.Finding{{
			RuleID: hostile, Title: hostile, Severity: domain.Critical,
			Host: hostile, Port: 8265, Service: hostile, Remediation: hostile,
		}},
		Params: &domain.ScanParams{ProbeTimeout: hostile, Concurrency: 1, CIDR: []string{hostile}},
	})
	r.Label = hostile
	r.ScannedFrom = hostile

	svg := extractSVG(t, renderString(t, r), `<svg class="bandstrip"`)
	if strings.Contains(svg, "script") || strings.Contains(svg, hostile) {
		t.Errorf("scanned input reached the grade band strip: %s", svg)
	}
}

// TestTheGradeBandStripHasNoMarker. gradeFor returns a representative score
// per band - 40, 60, 78, 90, 94 - not a measurement, and §10.0 calls the
// thresholds provisional. A needle or a point marker would claim a precision
// that does not exist, on exactly the number a buyer is most likely to quote.
// The band is the finding; the integer inside it is an implementation detail.
func TestTheGradeBandStripHasNoMarker(t *testing.T) {
	svg := extractSVG(t, renderString(t, gradedResult(t, domain.Critical)), `<svg class="bandstrip"`)
	// The hatch texture for the unreachable band is made of <line>, so the
	// defs block is excluded: what must not exist is a mark on the SCALE.
	if i := strings.Index(svg, "</defs>"); i >= 0 {
		svg = svg[i:]
	}
	for _, marker := range []string{"<polygon", "<circle", "<marker", "<line"} {
		if strings.Contains(svg, marker) {
			t.Errorf("the band strip draws %q: a point marker implies the score is a "+
				"measurement rather than a band representative", marker)
		}
	}
	// The whole band is filled instead, and it says which one in words.
	if !strings.Contains(svg, "this scan") {
		t.Error("the achieved band is not labelled")
	}
}
