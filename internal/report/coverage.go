package report

import (
	"fmt"
	"html/template"
	"strconv"
	"strings"

	"gpusecurity/internal/domain"
)

// The coverage bar - the one chart on this report.
//
// Every other number in the report is about what we found. This one is about
// what we looked at, and it is the number a reader skips. A scan of 254
// targets where 15 answered is a statement about 15 machines; the grade says
// nothing whatever about the other 239, and silence reads as safety. The prose
// that says otherwise already exists, in a warning box the eye travels past on
// its way to the large letter.
//
// Deliberately spare, per the chart constraints in docs/open-work.md:
//   - Inline SVG built here, no library: go.mod has no require block, and a
//     chart dependency would cost the zero-dependency air-gap binary (P4).
//   - No trend line. This is one point in time; drift is Phase 2, and a line
//     through a single observation implies a measurement we did not make.
//   - No percentages. One probe-failed host in a /24 is 0.39%, which rounds to
//     "0%" - a coverage gap reported as zero is the exact defect this chart
//     exists to prevent. Counts are exact at every size.
//   - The sentence above the bar carries every number the bar encodes, so no
//     fact lives in colour alone (section 7.6) and the chart survives a
//     greyscale print, a mail client that strips SVG, and a screen reader.

// coverageSegment is one state a target ended the scan in.
type coverageSegment struct {
	// Class selects the segment's fill in the stylesheet, and is how the
	// tests identify a segment in the rendered markup.
	Class string
	Label string
	Count int
	// Pattern is the id of the texture this state is filled with, empty for
	// the solid one. Only the patterns a report actually uses are emitted, so
	// a fully covered scan carries no unused <defs> - and so a test that
	// claims the textures exist has to render a scan that needs them.
	Pattern string
}

// coverageSegments splits the run into the states a target can end in, in the
// order they render: what we assessed, then the ways we did not, then what we
// never got to. Empty states are dropped - a legend row reading "0 unresolved"
// is noise, and a zero-width segment is not a thing.
//
// "Not probed" is derived rather than counted because it is the one state with
// no host record at all: an interrupted run simply has targets that produced
// no observation. Leaving them out would draw a scan of 4 targets as complete
// coverage of 4, when the operator asked for 254 - which is the whole failure
// this chart is pointed at.
func coverageSegments(r domain.ScanResult) []coverageSegment {
	notProbed := r.TargetsRequested - r.TargetsScanned
	if notProbed < 0 {
		// Unreachable through domain.NewResult, where Requested is never
		// below len(Hosts). Clamped rather than trusted because a negative
		// width draws a segment running backwards across its neighbour,
		// which looks like data rather than like a bug.
		notProbed = 0
	}
	all := []coverageSegment{
		{"seg-ok", "responded", r.HostsResponded, ""},
		{"seg-silent", "no response", r.HostsUnanswered, "cov-hatch"},
		{"seg-unresolved", "unresolved", r.HostsUnresolved, "cov-vert"},
		{"seg-failed", "probe failed", r.HostsProbeFailed, "cov-horz"},
		{"seg-notprobed", "not probed", notProbed, ""},
	}
	out := make([]coverageSegment, 0, len(all))
	for _, s := range all {
		if s.Count > 0 {
			out = append(out, s)
		}
	}
	return out
}

// coverageSentence states the bar in words. This is not a caption: it is the
// chart's content in text, which is what makes the chart safe to add at all.
// Every count the bar encodes appears here, so the picture is never the only
// place a coverage fact is recorded.
func coverageSentence(r domain.ScanResult, segs []coverageSegment) string {
	if len(segs) == 0 {
		return ""
	}
	parts := make([]string, 0, len(segs))
	for _, s := range segs {
		parts = append(parts, fmt.Sprintf("%d %s", s.Count, s.Label))
	}
	return fmt.Sprintf("%s requested: %s.",
		plural(r.TargetsRequested, "target", "targets"), strings.Join(parts, ", "))
}

// coverageNote says what the bar means for the grade above it. It is prose
// rather than template branches because the cases are not alternatives: a
// multi-address name is a coverage gap in a different *unit* from the bar's,
// and it has to be stated alongside whichever target-level case applies.
//
// That unit mismatch is the trap. The bar counts targets, and a scan of two
// names where both answered draws as complete coverage - while the run is
// graded N/A precisely because the other addresses behind those names were
// never dialed. A chart claiming full coverage on a run withheld for
// incomplete coverage is the kind of contradiction a buyer reads first and
// asks about last. The addresses are not folded into the bar as a segment,
// because a bar whose total is sometimes targets and sometimes machines
// measures nothing.
func coverageNote(r domain.ScanResult) string {
	var note string
	switch {
	case r.TargetsRequested == 0:
		return ""
	case r.Inconclusive():
		note = "Nothing answered, so nothing above was assessed. The grade is not a " +
			"verdict on these targets; it records that we did not see them."
	case r.HostsResponded == r.TargetsRequested:
		note = "Every target in scope answered, so the grade above covers all of them."
		if r.AddressesUnassessed > 0 {
			// The second clause below supplies the qualification, so this
			// half must not also claim the grade covers everything.
			note = "Every target you named answered."
		}
	case r.Interrupted:
		note = fmt.Sprintf("The grade above describes only the %d that answered before the "+
			"scan was stopped. The targets it never reached were not assessed at all, so "+
			"nothing here is evidence about them.", r.HostsResponded)
	default:
		note = fmt.Sprintf("The grade above describes only the %d that responded. A target "+
			"that stayed silent was not assessed, which is missing information rather than "+
			"a clean result.", r.HostsResponded)
	}
	if r.AddressesUnassessed > 0 {
		note += fmt.Sprintf(" This bar counts the targets you named, not the machines behind "+
			"them: %s behind those names were not assessed, as noted above.",
			plural(r.AddressesUnassessed, "address", "addresses"))
	}
	return note
}

const (
	// barWidth and barHeight fix the SVG coordinate system only; the element
	// itself scales to the page width via the stylesheet.
	barWidth  = 600
	barHeight = 34
	// minSegment is the floor, in user units, below which a nonzero segment
	// stops being visible. One probe-failed host in a /24 is two tenths of a
	// unit at this scale - invisible, and precisely the fact worth seeing. So
	// every state present at all is drawn at least this wide, which overstates
	// the small ones. That is the right direction to be wrong about a gap in
	// coverage, and it is why there are no percentages on the bar: the widths
	// are legible, not measurable, and the counts beside them are exact.
	minSegment = 7
	legendTop  = barHeight + 16
	legendRow  = 20
)

// coveragePatterns give the three not-assessed states a texture as well as a
// fill. The report prints, and it prints to greyscale: three fills that differ
// only in lightness are one indistinguishable grey band on paper, which would
// leave the legend order as the only way to tell them apart. The solid state
// and the open one need no texture, so they have no entry here.
//
// Three line *directions* rather than three motifs, which is a correction
// rather than a preference: dots and cross-hatch were tried first and are
// indistinguishable at the sizes that matter. A single unassessed host is
// drawn at the minSegment floor and its legend swatch is 16 units wide, so a
// texture that only separates from its neighbour across a wide band separates
// nowhere useful - and the two states it failed to separate, "unresolved" and
// "probe failed", are precisely the two with different causes and different
// fixes (their DNS, our file-descriptor limit).
var coveragePatterns = map[string]string{
	"cov-hatch": `<pattern id="cov-hatch" width="6" height="6" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">` +
		`<line class="covink" x1="0" y1="0" x2="0" y2="6" stroke-width="2.5"/></pattern>`,
	"cov-vert": `<pattern id="cov-vert" width="5" height="5" patternUnits="userSpaceOnUse">` +
		`<line class="covink" x1="1" y1="0" x2="1" y2="5" stroke-width="2"/></pattern>`,
	"cov-horz": `<pattern id="cov-horz" width="4" height="4" patternUnits="userSpaceOnUse">` +
		`<line class="covink" x1="0" y1="1" x2="4" y2="1" stroke-width="1.6"/></pattern>`,
}

// coverageBarSVG renders the stacked bar and its legend as one self-contained
// SVG element.
//
// It returns template.HTML, so this function owns its own escaping. Nothing
// customer-controlled reaches it: the labels are fixed strings from the table
// above and the only values interpolated are integers and computed widths. A
// host name never appears on this chart - it is a picture of counts.
//
// aria-hidden, deliberately: coverageSentence states the same numbers
// immediately above, so announcing the legend too would read every count twice.
func coverageBarSVG(segs []coverageSegment) template.HTML {
	total := 0
	for _, s := range segs {
		total += s.Count
	}
	if len(segs) == 0 || total <= 0 {
		return ""
	}

	height := legendTop + legendRow*len(segs)
	var b strings.Builder
	fmt.Fprintf(&b, `<svg class="covbar" viewBox="0 0 %d %d" width="%d" height="%d" aria-hidden="true">`,
		barWidth, height, barWidth, height)
	if defs := coverageDefs(segs); defs != "" {
		b.WriteString(defs)
	}

	// Reserve every present segment's floor first, then share what is left in
	// proportion to the counts. The widths then sum to exactly barWidth and no
	// present state can round away, without the usual largest-remainder
	// bookkeeping.
	free := float64(barWidth - minSegment*len(segs))
	x := 0.0
	for i, s := range segs {
		w := float64(minSegment) + free*float64(s.Count)/float64(total)
		if i == len(segs)-1 {
			// Absorb float drift at the right edge rather than leaving a
			// hairline of background showing past the last segment.
			w = barWidth - x
		}
		fmt.Fprintf(&b, `<rect class="%s" x="%s" y="0" width="%s" height="%d"/>`,
			s.Class, svgNum(x), svgNum(w), barHeight)
		x += w
	}

	for i, s := range segs {
		y := legendTop + legendRow*i
		fmt.Fprintf(&b,
			`<rect class="%s" x="0" y="%d" width="16" height="11"/>`+
				`<text class="covnum" x="52" y="%d">%d</text>`+
				`<text class="covlab" x="60" y="%d">%s</text>`,
			s.Class, y, y+10, s.Count, y+10, s.Label)
	}
	b.WriteString(`</svg>`)
	// #nosec G203 -- this markup is built here, so escaping is this function's
	// job, and the way it discharges it is by never handling a string that
	// came from the scan. The only values interpolated are integers, computed
	// widths and the fixed labels in coverageSegments; a host name, a label or
	// a target path has no path into this chart, which is a picture of counts.
	// TestTheCoverageBarCarriesNoScannedInput holds that premise down.
	return template.HTML(b.String())
}

// coverageDefs emits only the textures the present segments reference, in the
// segments' own order so the markup is stable for the golden files.
func coverageDefs(segs []coverageSegment) string {
	var b strings.Builder
	for _, s := range segs {
		if def, ok := coveragePatterns[s.Pattern]; ok {
			b.WriteString(def)
		}
	}
	if b.Len() == 0 {
		return ""
	}
	return "<defs>" + b.String() + "</defs>"
}

func svgNum(v float64) string { return strconv.FormatFloat(v, 'f', 2, 64) }
