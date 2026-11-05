package report

import (
	"fmt"
	"html/template"
	"strings"

	"gpusecurity/internal/domain"
)

// The grade band strip - the third chart on this report.
//
// The grade is the most-read thing in the document and the least explained:
// "F" is an assertion until a reader can see what the alternatives were and
// where the ceiling is. This draws the §10.0 scale, fills the band this scan
// landed in, and marks the band this tier cannot award at all.
//
// It is NOT a gauge, and the distinction is load-bearing. gradeFor returns a
// representative score per band - 40, 60, 78, 90, 94 - not a measurement, so
// a needle at "40 of 100" would be precision we do not have, on a number the
// §10.0 table already calls provisional. The band is the finding; the point
// inside it is an artefact of having to return some integer. So the whole
// band is filled and there is no marker.
//
// Same constraints as the other two (docs/open-work.md): inline SVG built
// here, no library, nothing in colour alone - every band carries its letter
// and its range as text - and it has to print.

const (
	bandStripW = 600
	bandH      = 30
	bandLabelY = bandH + 15
	bandNoteY  = bandLabelY + 17
	// bandMinW keeps the narrowest band legible. A+ is 6 points of a 101-point
	// scale, which is 36 units here - enough, but the floor exists so a future
	// band edit cannot silently produce a sliver. Same reasoning as the
	// coverage bar's minSegment, and the same trade: small bands are drawn
	// slightly wide, and the exact range is printed under every one.
	bandMinW = 30
)

// gradeBandView is one band, ready to draw.
type gradeBandView struct {
	Grade    string
	Range    string
	Achieved bool
	// Unreachable marks a band above this tier's ceiling.
	Unreachable bool
	// Class is the fill for an achieved band, matching the grade colours the
	// hero block already uses. Only an achieved band is filled, so there is
	// no cross-band greyscale ordering to get wrong here - unlike the
	// exposure strip, where every cell competes with its neighbours.
	Class string
	// DarkInk is true where the fill is light enough that white text on it
	// prints badly.
	DarkInk bool
	width   float64
}

// buildGradeBands lays out the scale. It returns nil when there is no grade to
// place: an inconclusive run has no position on this scale at all, and drawing
// the scale with nothing filled invites the eye to supply a position - most
// likely the left-hand end, which would render "we did not look" as "we looked
// and it was as bad as possible".
func buildGradeBands(r domain.ScanResult) []gradeBandView {
	if !r.Graded() {
		return nil
	}
	achieved, ok := domain.BandFor(r.Score)
	if !ok {
		return nil
	}

	bands := domain.GradeBands()
	span := 0
	for _, b := range bands {
		span += b.High - b.Low + 1
	}
	if span <= 0 {
		return nil
	}

	// Reserve each band's floor, then share the rest in proportion to its
	// range, so the widths sum to the full strip and the F band is visibly
	// the widest - which it is, and which is part of what the picture says.
	free := float64(bandStripW - bandMinW*len(bands))
	out := make([]gradeBandView, 0, len(bands))
	for _, b := range bands {
		points := b.High - b.Low + 1
		v := gradeBandView{
			Grade:       string(b.Grade),
			Range:       fmt.Sprintf("%d–%d", b.Low, b.High),
			Achieved:    b.Grade == achieved.Grade,
			Unreachable: b.AboveL1Ceiling,
			width:       float64(bandMinW) + free*float64(points)/float64(span),
		}
		if v.Achieved {
			v.Class, v.DarkInk = gradeFill(b.Grade)
		}
		out = append(out, v)
	}
	return out
}

// gradeFill maps a grade to the class the hero block already uses for it, and
// says whether that fill needs dark ink. C and B are the light ones; white on
// them is the least legible mark available and prints worst.
func gradeFill(g domain.Grade) (string, bool) {
	switch g {
	case "F":
		return "band-F", false
	case "C":
		return "band-C", true
	case "B":
		return "band-B", true
	case domain.L1GradeCeiling:
		return "band-A", false
	case domain.GradeAPlus:
		return "band-Aplus", false
	}
	return "", false
}

// gradeBandSentence states the chart in words, as the other two charts do.
func gradeBandSentence(r domain.ScanResult, bands []gradeBandView) string {
	if len(bands) == 0 {
		return ""
	}
	var achieved, ceiling string
	for _, b := range bands {
		if b.Achieved {
			achieved = b.Grade
		}
		if b.Unreachable {
			ceiling = b.Grade
		}
	}
	s := fmt.Sprintf("This scan landed in the %s band.", achieved)
	if ceiling != "" {
		s += fmt.Sprintf(" The %s band is not available at Level 1 and is drawn here "+
			"so the scale is not mistaken for the whole range.", ceiling)
	}
	return s
}

// gradeBandSVG draws the scale.
//
// Nothing from the scan reaches this markup: the letters and ranges come from
// domain.GradeBands(), which is a fixed table, and the only computed values
// are widths. That is the same argument coverageBarSVG makes, and unlike the
// exposure strip it holds here - this chart never names a host.
func gradeBandSVG(bands []gradeBandView) template.HTML {
	if len(bands) == 0 {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, `<svg class="bandstrip" viewBox="0 0 %d %d" width="%d" height="%d" aria-hidden="true">`,
		bandStripW, bandNoteY+4, bandStripW, bandNoteY+4)

	// One hatch, for the band this tier cannot award. Emitted only when such
	// a band is drawn, so the markup carries no unused defs.
	for _, v := range bands {
		if v.Unreachable {
			b.WriteString(`<defs><pattern id="band-na" width="6" height="6" ` +
				`patternUnits="userSpaceOnUse" patternTransform="rotate(45)">` +
				`<line class="bandink" x1="0" y1="0" x2="0" y2="6" stroke-width="2"/></pattern></defs>`)
			break
		}
	}

	x := 0.0
	for i, v := range bands {
		w := v.width
		if i == len(bands)-1 {
			w = bandStripW - x
		}
		class := "band"
		switch {
		case v.Achieved:
			class += " achieved " + v.Class
		case v.Unreachable:
			class += " unreachable"
		}
		fmt.Fprintf(&b, `<rect class="%s" x="%s" y="0" width="%s" height="%d"/>`,
			class, svgNum(x), svgNum(w), bandH)

		ink := "bandletter"
		switch {
		case v.Achieved && v.DarkInk:
			ink += " dark"
		case v.Achieved:
			// white, the default
		case v.Unreachable:
			// On top of the hatch, so it needs a halo rather than a colour.
			ink += " onhatch"
		default:
			ink += " muted"
		}
		mid := x + w/2
		fmt.Fprintf(&b, `<text class="%s" x="%s" y="%d">%s</text>`,
			ink, svgNum(mid), bandH-10, v.Grade)
		fmt.Fprintf(&b, `<text class="bandrange" x="%s" y="%d">%s</text>`,
			svgNum(mid), bandLabelY, v.Range)
		if v.Achieved {
			fmt.Fprintf(&b, `<text class="bandyou" x="%s" y="%d">this scan</text>`,
				svgNum(mid), bandNoteY)
		}
		if v.Unreachable {
			fmt.Fprintf(&b, `<text class="bandna" x="%s" y="%d">L3 only</text>`,
				svgNum(mid), bandNoteY)
		}
		x += w
	}
	b.WriteString(`</svg>`)
	// #nosec G203 -- built here from domain.GradeBands(), a fixed table, plus
	// computed widths. No host name, label, or any other scanned string has a
	// path into this chart; TestTheGradeBandStripCarriesNoScannedInput holds
	// that down the same way the coverage bar's test does.
	return template.HTML(b.String())
}
