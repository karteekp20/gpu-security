package report

import (
	"fmt"
	"html/template"
	"sort"
	"strconv"
	"strings"

	"gpusecurity/internal/domain"
)

// The host x port exposure strip - the second chart on this report.
//
// The coverage bar answers "what did you look at?". This one answers the
// question a security lead is actually holding while they read the findings:
// *does this thing flag everything it touches?* A list of 21 findings cannot
// answer that, because the hosts that came back clean are not in it. The strip
// draws them, so the quiet rows sit in the same frame as the loud ones and the
// answer is visible rather than argued.
//
// That is why it draws every host that ANSWERED, not every host with a
// finding. A row of empty cells is the most valuable row on the chart; it is
// also why domain.ScanResult.Responded exists (2026-11-05).
//
// Same constraints as the coverage bar (docs/open-work.md):
//   - Inline SVG built here, no library (go.mod has no require block, P4).
//   - Never colour alone: every cell carries a severity letter, so the chart
//     survives a greyscale print and the legend is not load-bearing.
//   - No implied precision: a cell is the worst finding on that host and port,
//     and nothing is interpolated between cells.
//
// Unlike the coverage bar, this chart carries HOST NAMES into generated
// markup, so coverageBarSVG's "nothing from the scan reaches it" does not
// transfer and cannot be reused as the safety argument. Every host label is
// escaped here, and TestTheExposureStripEscapesHostNames holds it down.

const (
	// stripLabelCol is the width reserved for host labels, and stripMaxLabel
	// the number of characters that fits in it. A longer name is truncated in
	// the picture only - the findings tables below carry it in full, so the
	// chart never becomes the only place a host is named.
	stripLabelCol  = 150
	stripMaxLabel  = 22
	stripCellW     = 34
	stripCellH     = 17
	stripHeaderH   = 26
	stripLegendTop = 14
	// maxStripRows bounds the picture. This is the first chart on the report
	// whose height grows with the scan: a /24 where every host answers would
	// otherwise draw 254 rows into a file that is meant to be an email
	// attachment. When it binds, the rows kept are the ones with findings
	// (worst first) and the note states exactly what was left out - a
	// truncated chart that does not admit it is worse than no chart.
	maxStripRows = 40
	// portlessColumn is the label for findings that have no port: the bucket
	// rule is the case, since an object store is named by URL. Without a
	// column for them a public bucket would draw as a row of empty cells -
	// which is to say, as a clean host. That is the one error this chart must
	// not make.
	portlessColumn = "obj"
)

// stripRow is one responded host.
type stripRow struct {
	Host string
	// Cells is one entry per column, in column order. An empty severity means
	// no finding was raised there - which is NOT the same as the port being
	// closed, and the note below the chart says so.
	Cells []domain.Severity
	worst domain.Severity
	found int
}

// exposureStrip is the chart's data, computed before any markup.
type exposureStrip struct {
	// Columns are the ports, in ascending order, with the port-less column
	// last when any finding needs it.
	Columns []string
	Rows    []stripRow
	// Quiet is how many responded hosts raised no finding at all. Reported
	// even when such a host is not drawn, because it is the chart's point.
	Quiet int
	// Omitted is how many responded hosts the row cap left out.
	Omitted int
	// Responded is the total, so the note can state the fraction drawn.
	Responded int
}

// buildExposureStrip assembles the grid. It returns a zero strip when there is
// nothing worth drawing: no responded hosts, or no columns to draw them
// against.
func buildExposureStrip(r domain.ScanResult) exposureStrip {
	if len(r.Responded) == 0 {
		return exposureStrip{}
	}

	// Columns: the ports actually probed, which is a fact about the scan
	// rather than about the findings - a port that was probed and found
	// nothing is a column worth having, because an empty column is evidence
	// too. Falls back to the ports in the findings when the result carries no
	// parameters (a result not built by a scanner run).
	portSet := map[int]bool{}
	if r.Params != nil {
		for _, p := range r.Params.Ports {
			portSet[p] = true
		}
	}
	portless := false
	for _, f := range r.Findings {
		if f.Port == 0 {
			portless = true
			continue
		}
		portSet[f.Port] = true
	}
	ports := make([]int, 0, len(portSet))
	for p := range portSet {
		ports = append(ports, p)
	}
	sort.Ints(ports)

	columns := make([]string, 0, len(ports)+1)
	colIndex := make(map[int]int, len(ports))
	for i, p := range ports {
		colIndex[p] = i
		columns = append(columns, strconv.Itoa(p))
	}
	if portless {
		colIndex[0] = len(columns)
		columns = append(columns, portlessColumn)
	}
	if len(columns) == 0 {
		return exposureStrip{}
	}

	// Worst finding per host and column.
	worstAt := map[string]map[int]domain.Severity{}
	for _, f := range r.Findings {
		ci, ok := colIndex[f.Port]
		if !ok {
			continue
		}
		if worstAt[f.Host] == nil {
			worstAt[f.Host] = map[int]domain.Severity{}
		}
		if cur, seen := worstAt[f.Host][ci]; !seen ||
			domain.SeverityRank(f.Severity) < domain.SeverityRank(cur) {
			worstAt[f.Host][ci] = f.Severity
		}
	}

	rows := make([]stripRow, 0, len(r.Responded))
	quiet := 0
	for _, h := range r.Responded {
		row := stripRow{Host: h.Host, Cells: make([]domain.Severity, len(columns))}
		row.worst = domain.Severity("")
		worstRank := len(domain.SeverityOrder())
		for ci, sev := range worstAt[h.Host] {
			row.Cells[ci] = sev
			row.found++
			if rank := domain.SeverityRank(sev); rank < worstRank {
				worstRank, row.worst = rank, sev
			}
		}
		if row.found == 0 {
			quiet++
		}
		rows = append(rows, row)
	}

	s := exposureStrip{
		Columns: columns, Quiet: quiet, Responded: len(rows),
	}

	// Under the cap, draw every responded host in the order it was probed:
	// the subnet reads naturally and the quiet hosts stay interleaved with
	// the loud ones, which is the comparison the chart exists to make.
	// Over it, keep the worst rows - a reader who can only be shown 40 of 254
	// should be shown the 40 that matter - and say so underneath.
	if len(rows) > maxStripRows {
		ranked := append([]stripRow(nil), rows...)
		sort.SliceStable(ranked, func(i, j int) bool {
			ri := domain.SeverityRank(ranked[i].worst)
			rj := domain.SeverityRank(ranked[j].worst)
			if ri != rj {
				return ri < rj
			}
			return ranked[i].found > ranked[j].found
		})
		s.Omitted = len(rows) - maxStripRows
		rows = ranked[:maxStripRows]
	}
	s.Rows = rows
	return s
}

// exposureSentence states what the chart is, in words, above it. As with the
// coverage bar this is the chart's content in text rather than a caption: the
// counts here are what make the picture safe to add, and they are the facts a
// greyscale print or a stripped-SVG mail client must still carry.
func exposureSentence(s exposureStrip) string {
	if len(s.Rows) == 0 {
		return ""
	}
	out := fmt.Sprintf("%s answered, across %s probed.",
		plural(s.Responded, "host", "hosts"), plural(len(s.Columns), "port", "ports"))
	switch {
	case s.Quiet == s.Responded:
		out += " None of them raised a finding."
	case s.Quiet > 0:
		out += fmt.Sprintf(" %s raised no finding at all.", plural(s.Quiet, "host", "hosts"))
	default:
		out += " Every one of them raised at least one finding."
	}
	return out
}

// exposureNote says what the chart does and does not claim. Two things need
// saying and neither is obvious from the picture.
//
// An empty cell is the one that invites the wrong reading: it means no rule
// fired on that host and port, which is not the same as the port being shut.
// A port can be open, answer nothing we recognise, and raise no finding -
// RG-EXPOSURE-001 covers the case where it answers at all, but a filtered port
// on a responding host is simply blank here. Claiming "closed" would be
// inventing a negative we did not establish, which is the same error as
// reading a silent host as a clean one.
func exposureNote(s exposureStrip) string {
	if len(s.Rows) == 0 {
		return ""
	}
	note := "A blank cell means no finding was raised on that host and port - not that " +
		"the port is closed."
	if s.Quiet > 0 {
		note += " The rows with no marks at all are hosts that answered and raised nothing, " +
			"which is the control on whether this tool flags everything it touches."
	}
	if s.Omitted > 0 {
		note += fmt.Sprintf(" Showing the %d most severe of %d responding hosts; %s not drawn "+
			"here. Every finding is in the tables below regardless.",
			len(s.Rows), s.Responded, plural(s.Omitted, "host is", "hosts are"))
	}
	return note
}

// stripLabel shortens a host for the label column and escapes it. Truncation
// is from the left on a long name, keeping the end: the distinguishing part of
// "ray-head-07.cluster-a.internal" is not "ray-head".
//
// Truncation counts RUNES, not bytes. Slicing a byte offset out of the middle
// of a multi-byte rune yields invalid UTF-8, and this string is interpolated
// into an SVG document - an internationalized hostname would have produced a
// label that no XML parser is required to render. Cutting first and escaping
// second also means truncation can never land inside an HTML entity.
func stripLabel(host string) string {
	if r := []rune(host); len(r) > stripMaxLabel {
		host = "…" + string(r[len(r)-(stripMaxLabel-1):])
	}
	return template.HTMLEscapeString(host)
}

// markClass picks the letter colour. The cell palette is a luminance ramp
// (see the stylesheet), so the three lighter fills need dark ink and the two
// darker ones need white. Without this the "M" on the yellow cell is white on
// a light background, which is the least legible mark on the chart and prints
// worst of all.
func markClass(s domain.Severity) string {
	switch s {
	case domain.Medium, domain.Low, domain.Info:
		return "expmark dark"
	}
	return "expmark"
}

// severityLetter is the glyph in a cell. Letters rather than shapes because a
// reader guesses C/H/M/L without consulting a legend, and because a letter
// survives both a greyscale print and a 17-unit cell.
func severityLetter(s domain.Severity) string {
	switch s {
	case domain.Critical:
		return "C"
	case domain.High:
		return "H"
	case domain.Medium:
		return "M"
	case domain.Low:
		return "L"
	case domain.Info:
		return "i"
	}
	return ""
}

// exposureStripSVG renders the grid, its headers and its legend as one
// self-contained SVG element.
//
// Escaping is this function's own job, and unlike coverageBarSVG it cannot
// discharge it by never touching scanned input: host names are the row labels.
// Every label goes through stripLabel, which escapes; the port headers are
// integers formatted here; the letters come from the fixed table above.
func exposureStripSVG(s exposureStrip) template.HTML {
	if len(s.Rows) == 0 || len(s.Columns) == 0 {
		return ""
	}

	gridW := stripLabelCol + stripCellW*len(s.Columns)
	gridH := stripHeaderH + stripCellH*len(s.Rows)
	legendY := gridH + stripLegendTop + 10
	height := legendY + 6

	var b strings.Builder
	fmt.Fprintf(&b, `<svg class="expstrip" viewBox="0 0 %d %d" width="%d" height="%d" aria-hidden="true">`,
		gridW, height, gridW, height)

	// Port headers.
	for i, c := range s.Columns {
		x := stripLabelCol + stripCellW*i + stripCellW/2
		fmt.Fprintf(&b, `<text class="expport" x="%d" y="%d">%s</text>`,
			x, stripHeaderH-9, template.HTMLEscapeString(c))
	}

	// Rows.
	for ri, row := range s.Rows {
		y := stripHeaderH + stripCellH*ri
		fmt.Fprintf(&b, `<text class="exphost" x="0" y="%d">%s</text>`,
			y+stripCellH-5, stripLabel(row.Host))
		for ci, sev := range row.Cells {
			x := stripLabelCol + stripCellW*ci
			if sev == "" {
				fmt.Fprintf(&b, `<rect class="expcell empty" x="%d" y="%d" width="%d" height="%d"/>`,
					x+2, y+2, stripCellW-4, stripCellH-4)
				continue
			}
			fmt.Fprintf(&b,
				`<rect class="expcell %s" x="%d" y="%d" width="%d" height="%d"/>`+
					`<text class="%s" x="%d" y="%d">%s</text>`,
				sev, x+2, y+2, stripCellW-4, stripCellH-4,
				markClass(sev), x+stripCellW/2, y+stripCellH-6, severityLetter(sev))
		}
	}

	// Legend: only the severities actually drawn, so a clean strip carries no
	// key to findings it does not contain.
	present := map[domain.Severity]bool{}
	for _, row := range s.Rows {
		for _, sev := range row.Cells {
			if sev != "" {
				present[sev] = true
			}
		}
	}
	x := 0
	for _, sev := range domain.SeverityOrder() {
		if !present[sev] {
			continue
		}
		fmt.Fprintf(&b,
			`<rect class="expcell %s" x="%d" y="%d" width="14" height="11"/>`+
				`<text class="%s" x="%d" y="%d">%s</text>`+
				`<text class="explab" x="%d" y="%d">%s</text>`,
			sev, x, legendY-9, markClass(sev), x+7, legendY, severityLetter(sev),
			x+19, legendY, sev)
		x += 24 + 7*len(sev)
	}
	if s.Quiet > 0 {
		fmt.Fprintf(&b,
			`<rect class="expcell empty" x="%d" y="%d" width="14" height="11"/>`+
				`<text class="explab" x="%d" y="%d">no finding</text>`,
			x, legendY-9, x+19, legendY)
	}

	b.WriteString(`</svg>`)
	// #nosec G203 -- this markup is built here, so escaping is this function's
	// job. Unlike the coverage bar it does handle scanned input: host names
	// are the row labels, and they go through stripLabel, which escapes. The
	// port headers are integers formatted here and the cell letters come from
	// severityLetter's fixed table. TestTheExposureStripEscapesHostNames
	// renders a scan whose hosts are all script tags and holds this down.
	return template.HTML(b.String())
}
