// Package report renders a scan into the two artifacts an operator actually
// uses: machine-readable JSON, and a self-contained HTML page written to be
// read by a security lead who has 60 seconds.
//
// The HTML embeds its own styles and references no external asset, so it opens
// on an air-gapped workstation and mails as a single file. Output is
// golden-file tested because that diff is the artifact a buyer reads.
package report

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gpusecurity/internal/domain"
)

// maxFixFirst caps the "fix these first" list. A remediation list a security
// lead can act on this afternoon beats an exhaustive one they file away.
const maxFixFirst = 5

type sevCount struct {
	Severity domain.Severity
	Count    int
}

type hostGroup struct {
	Host string
	// Address is the address this host's probes dialed, set only when the
	// operator named a host rather than an address.
	Address  string
	Findings []domain.Finding
}

// maxUnreachableListed caps the coverage-gap list. A dark /24 produces 254
// entries, which would bury the report it is supposed to qualify.
const maxUnreachableListed = 10

type view struct {
	domain.ScanResult
	Started          string
	Duration         string
	SevCounts        []sevCount
	FixFirst         []domain.Finding
	Hosts            []hostGroup
	HasRayFinding    bool
	UnreachableShown []domain.HostSummary
	UnreachableExtra int
	// PortsProbed and ScopeGiven render ScanParams for a human. They are
	// precomputed rather than assembled in the template because both are
	// prose with plurals and both are asserted directly in tests.
	PortsProbed string
	ScopeGiven  string
	// The coverage bar. Segments drive both the chart and its presence - an
	// empty slice means there was nothing to draw and the section is skipped.
	CoverageSegments []coverageSegment
	CoverageSentence string
	CoverageNote     string
	CoverageBar      template.HTML
	// The host x port exposure strip. Rows drive its presence, same as the
	// coverage bar's segments: no responded hosts means no grid to draw.
	ExposureRows     int
	ExposureSentence string
	ExposureNote     string
	ExposureStrip    template.HTML
	// The grade band strip. Absent on an inconclusive run, which has no
	// position on the scale (see buildGradeBands).
	GradeBandSentence string
	GradeBandStrip    template.HTML
}

func newView(r domain.ScanResult) view {
	r.Findings = domain.SortFindings(r.Findings)

	var counts []sevCount
	for _, s := range domain.SeverityOrder() {
		if n := r.Summary[s]; n > 0 {
			counts = append(counts, sevCount{s, n})
		}
	}

	fixFirst := r.Findings
	if len(fixFirst) > maxFixFirst {
		fixFirst = fixFirst[:maxFixFirst]
	}

	var hosts []hostGroup
	index := map[string]int{}
	for _, f := range r.Findings {
		if i, ok := index[f.Host]; ok {
			hosts[i].Findings = append(hosts[i].Findings, f)
			continue
		}
		index[f.Host] = len(hosts)
		hosts = append(hosts, hostGroup{Host: f.Host, Address: r.Addresses[f.Host],
			Findings: []domain.Finding{f}})
	}

	hasRay := false
	for _, f := range r.Findings {
		if strings.HasPrefix(f.RuleID, "RG-RAY-") {
			hasRay = true
			break
		}
	}

	segs := coverageSegments(r)
	strip := buildExposureStrip(r)
	bands := buildGradeBands(r)

	shown := r.Unreachable
	extra := 0
	if len(shown) > maxUnreachableListed {
		extra = len(shown) - maxUnreachableListed
		shown = shown[:maxUnreachableListed]
	}

	return view{
		ScanResult:       r,
		Started:          r.StartedAt.UTC().Format("2006-01-02 15:04 UTC"),
		Duration:         formatDuration(r.CompletedAt.Sub(r.StartedAt)),
		SevCounts:        counts,
		FixFirst:         fixFirst,
		Hosts:            hosts,
		HasRayFinding:    hasRay,
		UnreachableShown: shown,
		UnreachableExtra: extra,
		PortsProbed:      portsProbed(r.Params),
		ScopeGiven:       scopeGiven(r.Params),
		CoverageSegments: segs,
		CoverageSentence: coverageSentence(r, segs),
		CoverageNote:     coverageNote(r),
		CoverageBar:      coverageBarSVG(segs),
		ExposureRows:     len(strip.Rows),
		ExposureSentence: exposureSentence(strip),
		ExposureNote:     exposureNote(strip),
		ExposureStrip:    exposureStripSVG(strip),

		GradeBandSentence: gradeBandSentence(r, bands),
		GradeBandStrip:    gradeBandSVG(bands),
	}
}

// portsProbed lists the ports dialed on every host. An operator checks this
// against the authorization they signed, which named ports.
func portsProbed(p *domain.ScanParams) string {
	if p == nil || len(p.Ports) == 0 {
		return ""
	}
	out := make([]string, 0, len(p.Ports))
	for _, port := range p.Ports {
		out = append(out, strconv.Itoa(port))
	}
	return strings.Join(out, ", ")
}

// scopeGiven states the scope the way it was typed, which is what the reader
// needs to retype it. The resolved target list is in report.json; the HTML
// caps the unassessed list at maxUnreachableListed, so on a dark /24 this
// sentence is the only place the HTML says what was in scope at all.
func scopeGiven(p *domain.ScanParams) string {
	if p == nil {
		return ""
	}
	var parts []string
	if len(p.CIDR) > 0 {
		parts = append(parts, "CIDR "+strings.Join(p.CIDR, ", "))
	}
	if p.NamedTargets > 0 {
		parts = append(parts, fmt.Sprintf("%s named on the command line",
			plural(p.NamedTargets, "host", "hosts")))
	}
	if p.TargetsFile != "" {
		parts = append(parts, "a target list at "+p.TargetsFile)
	}
	if p.Buckets > 0 {
		parts = append(parts, plural(p.Buckets, "bucket URL", "bucket URLs"))
	}
	return strings.Join(parts, "; ")
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

// Scan output is owner-only. A report lists exactly which of a client's
// services are exposed and unauthenticated - it is a map for anyone who wants
// in. World-readable is the wrong default for that on any shared machine; the
// operator can widen it deliberately if they want to share.
const (
	reportPerm = 0o600
	reportDir  = 0o700
)

// Write emits the machine-readable JSON and the standalone HTML report into
// outDir, creating it if needed. Both files are written owner-only.
func Write(outDir string, r domain.ScanResult) error {
	if err := os.MkdirAll(outDir, reportDir); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(outDir, "report.json"), MarshalJSON(r), reportPerm); err != nil {
		return err
	}
	// #nosec G304 -- outDir is the -out path the operator chose on their own
	// machine; writing where they asked is the feature.
	f, err := os.OpenFile(filepath.Join(outDir, "report.html"),
		os.O_WRONLY|os.O_CREATE|os.O_TRUNC, reportPerm)
	if err != nil {
		return err
	}
	if err := RenderHTML(f, r); err != nil {
		_ = f.Close()
		return err
	}
	// Close, not defer Close: it surfaces write errors that the Write calls
	// themselves can miss. The report is the deliverable, so a truncated one
	// must not be reported as success.
	return f.Close()
}

// MarshalJSON renders the machine-readable report.
func MarshalJSON(r domain.ScanResult) []byte {
	r.Findings = domain.SortFindings(r.Findings)
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		// ScanResult contains only JSON-safe types; this cannot fail in
		// practice, and a report is not worth aborting a scan over.
		return []byte("{}")
	}
	return append(b, '\n')
}

// RenderHTML writes the human-readable report.
func RenderHTML(w io.Writer, r domain.ScanResult) error {
	return htmlTmpl.Execute(w, newView(r))
}

func PrintSummary(w io.Writer, r domain.ScanResult) {
	v := newView(r)
	fmt.Fprintf(w, "\n=== GPU Risk & Isolation Report ===\n")
	if r.Label != "" {
		fmt.Fprintf(w, "%s\n", r.Label)
	}
	switch {
	case r.Inconclusive():
		fmt.Fprintf(w, "Grade: %s - INCONCLUSIVE\n", v.Grade)
	case !r.Graded() && r.Interrupted:
		fmt.Fprintf(w, "Grade: %s - INCOMPLETE (scan interrupted)\n", v.Grade)
	case !r.Graded():
		fmt.Fprintf(w, "Grade: %s - UNRELIABLE (%d probe(s) failed in the scanner)\n", v.Grade, r.ProbeErrors)
	default:
		fmt.Fprintf(w, "Grade: %s (score %d/100)\n", v.Grade, v.Score)
	}
	if v.GradeReason != "" {
		fmt.Fprintf(w, "%s\n", wrap(v.GradeReason, 76))
	}
	if r.Interrupted {
		fmt.Fprintf(w, "Targets scanned: %d of %d (INTERRUPTED)   Responded: %d   Hosts with findings: %d\n",
			v.TargetsScanned, v.TargetsRequested, v.HostsResponded, v.HostsWithFindings)
	} else {
		fmt.Fprintf(w, "Targets scanned: %d   Responded: %d   Hosts with findings: %d\n",
			v.TargetsScanned, v.HostsResponded, v.HostsWithFindings)
	}
	if v.HostsUnanswered > 0 || v.HostsUnresolved > 0 || v.HostsProbeFailed > 0 {
		fmt.Fprintf(w, "Not assessed: %d no response, %d unresolved, %d probe failures\n",
			v.HostsUnanswered, v.HostsUnresolved, v.HostsProbeFailed)
	}
	if r.Degraded() {
		fmt.Fprintf(w, "WARNING: %d probe(s) failed inside the scanner, so this scan under-reports.\n"+
			"         Lower -concurrency, or raise the hard limit (ulimit -Hn), then re-run.\n", r.ProbeErrors)
	}
	for _, h := range v.MultiAddress {
		fmt.Fprintf(w, "WARNING: %s resolves to %d addresses; only %s was assessed.\n"+
			"         The others are separate machines. Pass them as targets to cover them.\n",
			h.Host, h.AddressesFound, h.Address)
	}
	for _, c := range v.SevCounts {
		fmt.Fprintf(w, "  %-8s %d\n", c.Severity, c.Count)
	}
	if len(v.Findings) == 0 {
		switch {
		case r.Inconclusive():
			fmt.Fprintf(w, "\nNothing was assessed. Do not read this as a clean result.\n")
		case r.Interrupted:
			fmt.Fprintf(w, "\nNo findings on the %d target(s) probed before the scan was stopped.\n"+
				"The other %d were not assessed. Do not read this as a clean result.\n",
				v.TargetsScanned, v.TargetsRequested-v.TargetsScanned)
		case r.Degraded():
			fmt.Fprintf(w, "\nNo findings - but the scanner's own probes failed %d time(s), so this\n"+
				"is not a clean result. Fix the limit and re-run.\n", r.ProbeErrors)
		default:
			fmt.Fprintf(w, "\nNo exposure findings on the scanned targets.\n")
		}
		return
	}
	fmt.Fprintf(w, "\nFix these first:\n")
	for i, f := range v.FixFirst {
		fmt.Fprintf(w, "  %d. [%s] %s  %s:%d\n     %s\n", i+1, f.Severity, f.RuleID, f.Host, f.Port, f.Title)
	}
	if len(v.Findings) > len(v.FixFirst) {
		fmt.Fprintf(w, "  ... and %d more (see the full report)\n", len(v.Findings)-len(v.FixFirst))
	}
}

// formatDuration keeps a fast scan from reading as "0s", which makes the
// report look like it did not run.
func formatDuration(d time.Duration) string {
	switch {
	case d < time.Second:
		return d.Round(time.Millisecond).String()
	case d < time.Minute:
		return d.Round(100 * time.Millisecond).String()
	default:
		return d.Round(time.Second).String()
	}
}

func wrap(s string, width int) string {
	var b strings.Builder
	col := 0
	for _, word := range strings.Fields(s) {
		if col > 0 && col+1+len(word) > width {
			b.WriteByte('\n')
			col = 0
		} else if col > 0 {
			b.WriteByte(' ')
			col++
		}
		b.WriteString(word)
		col += len(word)
	}
	return b.String()
}

// gradeClass turns a grade into a CSS-safe suffix: "A+" -> "Aplus",
// "N/A" -> "NA".
func gradeClass(g domain.Grade) string {
	var b strings.Builder
	for _, r := range string(g) {
		switch {
		case r == '+':
			b.WriteString("plus")
		case (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
		}
	}
	return b.String()
}

// evidenceNote renders what a finding rests on as something a reader can act
// on, rather than as an enum. The phrasing carries the caveat with the claim,
// because the whole purpose of the field is that a security lead can tell
// which findings to spot-check first - and "service_api" does not say that.
//
// Kept to one line per finding: this report is an email attachment, and 21
// findings times a paragraph is a document nobody scrolls.
func evidenceNote(e domain.Evidence) string {
	// Escaped here rather than trusted. ProbedPath is already constrained to
	// the static check table upstream, but this function's output is marked as
	// trusted markup, so it must not depend on another package's invariant
	// holding - defence in depth is cheaper than a reasoned exemption.
	path := template.HTMLEscapeString(e.ProbedPath)
	switch e.Basis {
	case domain.BasisServiceAPI:
		if e.ProbedPath == "" {
			return "the service&rsquo;s own API answered an unauthenticated request."
		}
		return fmt.Sprintf("the service&rsquo;s own API answered (GET <code>%s</code>), "+
			"and a path that cannot exist did not.", path)
	case domain.BasisMetricsEndpoint:
		return fmt.Sprintf("a conventional metrics path answered (GET <code>%s</code>) &mdash; "+
			"exporters answer on any path, so this identifies the open endpoint more firmly "+
			"than it identifies the software behind it.", path)
	case domain.BasisGenericPath:
		return fmt.Sprintf("only the root page answered (GET <code>%s</code>) &mdash; any web "+
			"server answers that, so confirm the service name before acting on it. The "+
			"exposure is observed; the attribution is the weaker half.", path)
	case domain.BasisPortOnly:
		return "TCP reachability only &mdash; the port accepted a connection and nothing " +
			"identified what is behind it."
	case domain.BasisTransport:
		return "observed during the TLS handshake, not from any response."
	}
	return ""
}

// evidenceHTML is trusted markup: evidenceNote emits a fixed sentence per
// basis plus a ProbedPath that comes only from the static check table, never
// from a response or from operator input (domain.Evidence.ProbedPath, and
// TestProbedPathComesOnlyFromTheCheckTable on the scan side). The same
// discipline as the coverage bar: the suppression is discharged by a test
// rather than by this comment, see TestEvidenceNotesCarryNoScannedInput.
func evidenceHTML(e domain.Evidence) template.HTML {
	return template.HTML(evidenceNote(e)) //nolint:gosec // G203: see doc comment
}

var htmlTmpl = template.Must(template.New("r").Funcs(template.FuncMap{
	"gradeClass":   gradeClass,
	"evidenceHTML": evidenceHTML,
}).Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>GPU Risk &amp; Isolation Report</title>
<style>
:root{color-scheme:light dark;--fg:#111;--muted:#666;--bg:#fff;--card:#f6f7f9;--line:#e4e6eb;--accent:#c0392b}
@media(prefers-color-scheme:dark){:root{--fg:#e8e8ea;--muted:#9aa0a6;--bg:#0f1115;--card:#171a21;--line:#262a33}}
*{box-sizing:border-box}
body{font:15px/1.55 -apple-system,Segoe UI,Roboto,sans-serif;color:var(--fg);background:var(--bg);margin:0;padding:2rem 1.25rem;max-width:920px;margin-inline:auto}
h1{font-size:1.6rem;margin:0 0 .25rem}
h2{font-size:1.05rem;margin:2.25rem 0 .6rem;padding-bottom:.35rem;border-bottom:1px solid var(--line)}
h3{font-size:.95rem;margin:1.5rem 0 .4rem;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
p{margin:.5rem 0}
.sub{color:var(--muted);margin:0 0 1.5rem}
.label{font-size:1.05rem;font-weight:600;margin:.1rem 0 .35rem}
.hero{display:flex;gap:1.25rem;align-items:center;background:var(--card);border:1px solid var(--line);border-radius:.6rem;padding:1.1rem 1.25rem}
.grade{font-size:3rem;font-weight:700;line-height:1;min-width:3.2rem;text-align:center}
.g-Fplus,.g-F{color:#c0392b}.g-C{color:#e67e22}.g-B{color:#d4a017}.g-A,.g-Aplus{color:#2e7d32}
.g-NA{color:var(--muted);font-size:1.9rem}
.warn{background:var(--card);border-left:3px solid #e67e22;border-radius:0 .4rem .4rem 0;padding:.9rem 1.1rem;margin-top:1rem;font-size:.92rem}
.warn strong{color:#e67e22}
.warn ul{margin:.5rem 0 0;padding-left:1.2rem}
.warn code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.88em}
.hero .reason{margin:0 0 .4rem;font-weight:600}
.hero .facts{margin:0;color:var(--muted);font-size:.9rem}
.counts{margin:1rem 0 0;padding:0;list-style:none;display:flex;flex-wrap:wrap;gap:.4rem}
.counts li{background:var(--card);border:1px solid var(--line);border-radius:.3rem;padding:.15rem .5rem;font-size:.85rem}
ol.fix{padding-left:1.2rem}ol.fix li{margin:.55rem 0}
.wrapper{overflow-x:auto}
table{width:100%;border-collapse:collapse;margin-top:.5rem;min-width:36rem}
th,td{text-align:left;padding:.6rem .5rem;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600;font-size:.85rem}
table.params{min-width:0}table.params th{width:11rem;white-space:nowrap}
.covbar{display:block;width:100%;max-width:600px;height:auto;margin:.8rem 0 .4rem}
.covbar rect{stroke:var(--line);stroke-width:1}
.covbar .seg-ok{fill:#2e7d32}
.covbar .seg-silent{fill:url(#cov-hatch)}
.covbar .seg-unresolved{fill:url(#cov-vert)}
.covbar .seg-failed{fill:url(#cov-horz)}
.covbar .seg-notprobed{fill:none;stroke-dasharray:3 2}
.covbar .covink{stroke:var(--muted)}
.covbar text{font:11px -apple-system,Segoe UI,Roboto,sans-serif;fill:var(--fg)}
.covbar .covnum{font-weight:600;text-anchor:end}
.covbar .covlab{fill:var(--muted)}
.expstrip{display:block;width:100%;height:auto;margin:.8rem 0 .4rem;overflow:visible}
.expstrip text{font:11px -apple-system,Segoe UI,Roboto,sans-serif;fill:var(--fg)}
.expstrip .expport{font-size:10px;fill:var(--muted);text-anchor:middle}
.expstrip .exphost{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:10.5px}
.expstrip .explab{fill:var(--muted);font-size:10px}
.expstrip .expmark{font-size:10px;font-weight:700;text-anchor:middle;fill:#fff}
.expstrip .expmark.dark{fill:#111}
.expstrip rect.expcell{stroke:var(--line);stroke-width:1}
/* These fills are the strip's own, not the .sev pill colours, and the reason
   is the greyscale print. The pill palette's luminance does not track
   severity - measured off a rendered page, critical 96, info 102, low 130,
   high 147, medium 160 - so printed, an Info cell came out as dark as a
   Critical one and the chart's tone said the opposite of its letters. On the
   two hosts that are deliberate negative controls, that is the worst possible
   place to be wrong. This ramp is monotonic: darkest is worst, lightest is
   least. Hue still reads red/orange/yellow/blue/grey in colour.
   TestTheExposureStripPaletteIsMonotonicInGreyscale holds the ordering. */
.expstrip .expcell.critical{fill:#a32116}
.expstrip .expcell.high{fill:#d4621a}
.expstrip .expcell.medium{fill:#d4a017}
.expstrip .expcell.low{fill:#8fb8d8}
.expstrip .expcell.info{fill:#e2e2e2}
/* An empty cell is drawn, not omitted: the grid is what makes a quiet row
   legible as a row rather than as missing data. */
.expstrip .expcell.empty{fill:none}
.bandstrip{display:block;width:100%;max-width:600px;height:auto;margin:.8rem 0 .4rem}
.bandstrip text{font:11px -apple-system,Segoe UI,Roboto,sans-serif;text-anchor:middle}
.bandstrip rect.band{fill:none;stroke:var(--line);stroke-width:1}
/* Only the band a scan landed in is filled, so there is no cross-band
   greyscale ordering to get wrong - the position on the scale carries the
   meaning, and every band is labelled with its letter and its range. */
.bandstrip rect.band.achieved{stroke:var(--fg)}
.bandstrip rect.band.achieved.band-F{fill:#c0392b}
.bandstrip rect.band.achieved.band-C{fill:#e67e22}
.bandstrip rect.band.achieved.band-B{fill:#d4a017}
.bandstrip rect.band.achieved.band-A{fill:#2e7d32}
.bandstrip rect.band.achieved.band-Aplus{fill:#2e7d32}
.bandstrip rect.band.unreachable{fill:url(#band-na)}
.bandstrip .bandink{stroke:var(--muted)}
.bandstrip .bandletter{font-size:13px;font-weight:700;fill:#fff}
.bandstrip .bandletter.dark{fill:#111}
.bandstrip .bandletter.muted{fill:var(--muted)}
/* The letter on the hatched band sits on top of diagonal lines, so it gets a
   halo in the page background colour rather than competing with them. */
.bandstrip .bandletter.onhatch{fill:var(--fg);paint-order:stroke;stroke:var(--bg);stroke-width:3px;stroke-linejoin:round}
.bandstrip .bandrange{font-size:10px;fill:var(--muted)}
.bandstrip .bandyou{font-size:10px;font-weight:600;fill:var(--fg)}
.bandstrip .bandna{font-size:10px;fill:var(--muted);font-style:italic}
.sev{font-weight:600;font-size:.8rem;text-transform:uppercase;white-space:nowrap}
.sev.critical{color:#c0392b}.sev.high{color:#e67e22}.sev.medium{color:#d4a017}.sev.low{color:#3498db}.sev.info{color:var(--muted)}
.sev::before{content:"\25CF  ";font-size:.9em}
.pill{display:inline-block;background:var(--card);border:1px solid var(--line);border-radius:.3rem;padding:.05rem .4rem;font-size:.78rem;margin:.1rem .3rem .1rem 0;white-space:nowrap}
.ruleid{white-space:nowrap}
.pill.unconf{border-style:dashed;font-style:italic;color:var(--muted)}
.at{font-family:-apple-system,Segoe UI,Roboto,sans-serif;font-size:.78rem;font-weight:400;color:var(--muted)}
.rem{color:var(--muted);font-size:.9rem;display:block;margin-top:.25rem}
.note{background:var(--card);border-left:3px solid var(--accent);border-radius:0 .4rem .4rem 0;padding:.9rem 1.1rem;font-size:.92rem}
.foot{color:var(--muted);font-size:.8rem;margin-top:2.5rem;border-top:1px solid var(--line);padding-top:1rem}
@media print{
 :root{--fg:#000;--muted:#444;--bg:#fff;--card:#f4f4f4;--line:#ccc}
 body{padding:0;max-width:none;font-size:11pt}
 h2{page-break-after:avoid}
 tr,li,.note,.hero{page-break-inside:avoid}
 .hostgroup{page-break-inside:avoid}
}
</style></head><body>

<h1>GPU Risk &amp; Isolation Report</h1>
{{if .Label}}<p class="label">{{.Label}}</p>{{end}}
<p class="sub">AI infrastructure exposure assessment &middot; generated by ray-guard {{.ScannerVersion}} &middot; {{.Started}}{{if .ScannedFrom}} &middot; scanned from <code>{{.ScannedFrom}}</code>{{end}}</p>

<div class="hero">
  <div class="grade g-{{gradeClass .Grade}}">{{.Grade}}</div>
  <div>
    <p class="reason">{{.GradeReason}}</p>
    <p class="facts">Level 1 &middot; {{if .Graded}}Score {{.Score}}/100 &middot; {{end}}{{if .Interrupted}}{{.TargetsScanned}} of {{.TargetsRequested}} target(s) probed{{else}}{{.TargetsScanned}} target(s){{end}} in {{.Duration}} &middot; {{.HostsResponded}} responded &middot; {{.HostsWithFindings}} with findings</p>
  </div>
</div>
{{if .SevCounts}}<ul class="counts">{{range .SevCounts}}<li><span class="sev {{.Severity}}">{{.Severity}}</span> {{.Count}}</li>{{end}}</ul>{{end}}

{{if .Interrupted}}
<div class="warn">
<p><strong>Scan interrupted &mdash; this report is partial.</strong>
{{.TargetsScanned}} of {{.TargetsRequested}} target(s) were probed before the scan was stopped.
Anything listed below was observed and stands on its own, but no absence of a finding means
anything here: the targets that were not reached were not assessed at all, and are not listed.
Re-run the scan to completion before treating it as an assessment.</p>
</div>
{{end}}

{{if .Degraded}}
<div class="warn">
<p><strong>This scan under-reports &mdash; {{.ProbeErrors}} probe(s) failed inside the scanner.</strong>
Those probes never reached a conclusion, so services may be running on ports this report says
nothing about. This is a limit on the machine the scan ran from, not a finding about the targets:
almost always the open-file limit. Lower <code>-concurrency</code>, or raise the host's hard
limit (<code>ulimit -Hn</code> &mdash; raising the soft limit alone does nothing here), then
re-run. What is listed below was still observed; what is missing proves nothing.</p>
</div>
{{end}}

{{if .UnreachableShown}}
<div class="warn">
<p><strong>Coverage gap &mdash; {{len .Unreachable}} target(s) were not assessed.</strong>
{{if .Inconclusive}}Nothing responded, so this scan verified nothing. Do not read it as a clean
result.{{else}}The grade above covers only the targets that responded.{{end}}</p>
<ul>
{{range .UnreachableShown}}<li><code>{{.Host}}</code> &mdash; {{if eq .State "unresolved"}}name could not be resolved{{else if eq .State "probe-failed"}}not assessed: the scanner's own probes failed here (local resource limit){{else}}no response (firewalled, powered off, or unreachable from here){{end}}</li>
{{end}}{{if .UnreachableExtra}}<li>&hellip; and {{.UnreachableExtra}} more (see <code>report.json</code>)</li>{{end}}</ul>
</div>
{{end}}

{{if .MultiAddress}}
<div class="warn">
<p><strong>Coverage gap &mdash; {{.AddressesUnassessed}} address(es) behind the names you gave
were not assessed.</strong> A name that resolves to several addresses is several machines. One
address per name was probed, so the result below describes that machine and not the others.</p>
<ul>
{{range .MultiAddress}}<li><code>{{.Host}}</code> &mdash; resolves to {{.AddressesFound}} addresses; <code>{{.Address}}</code> was assessed, {{.UnassessedAddresses}} were not</li>
{{end}}</ul>
<p>To cover them all, pass the addresses themselves as targets. This also keeps the report
traceable: a finding against a name cannot be re-checked without knowing which machine answered.</p>
</div>
{{end}}

{{if .CoverageSegments}}
<h2>Coverage</h2>
<p class="facts">{{.CoverageSentence}}</p>
{{.CoverageBar}}
<p class="facts">{{.CoverageNote}}</p>
{{end}}

{{if .ExposureRows}}
<h2>Exposure map</h2>
<p class="facts">{{.ExposureSentence}}</p>
{{.ExposureStrip}}
<p class="facts">{{.ExposureNote}}</p>
{{end}}

{{if .FixFirst}}
<h2>Fix these first</h2>
<ol class="fix">
{{range .FixFirst}}<li><strong>{{.Title}}</strong> &mdash; {{.Host}}:{{.Port}} <span class="pill">{{.RuleID}}</span><span class="rem">{{.Remediation}}</span></li>
{{end}}</ol>
{{end}}

{{if .HasRayFinding}}
<h2>Why this matters</h2>
<div class="note">
<p><strong>What we observed.</strong> Ray&rsquo;s dashboard API answered an unauthenticated GET to
<code>/api/version</code> on the host(s) listed above. Ray has no per-route authentication, so an
API that answers us answers anyone who can reach that port.</p>
<p><strong>What that means.</strong> The same API serves <code>POST /api/jobs/</code>, which accepts
an entrypoint from any caller and runs it on the cluster with the Ray worker&rsquo;s permissions.
That is remote code execution by the software&rsquo;s own design, which is why
<strong>CVE-2023-48022</strong> is disputed rather than patched: there is no fixed version to
upgrade to, so reachability is the entire control, and that is the one CVE this assessment
asserts about your host &mdash; the condition it describes is the condition we observed.</p>
<p><strong>What we are not claiming.</strong> <strong>CVE-2025-62593</strong> is on CISA&rsquo;s
Known Exploited Vulnerabilities catalogue, and you will see it cited against Ray everywhere. We
list it as <em>unconfirmed</em> rather than as a finding, for two independent reasons: it is fixed
in Ray <strong>2.52.0</strong> and we did not determine your version, and its attack path is a
developer&rsquo;s browser plus DNS rebinding rather than the network reachability we measured. A
report that asserted it would be claiming something we did not look at. Every CVE we cite but
cannot assert is marked the same way, in the findings table and in the JSON
(<code>cves_unconfirmed</code>), with the check that would settle it.</p>
<p><strong>Why it is not theoretical.</strong> The <strong>ShadowRay</strong> campaign compromised
exposed Ray clusters to steal credentials and mine cryptocurrency on rented GPUs, and the clusters
were found by internet-wide scanning rather than by targeting.</p>
<p><strong>What we did not do.</strong> One benign GET, to a version endpoint. We did not submit a
job, did not list your jobs &mdash; that response carries each job&rsquo;s command line, so we do not
request it &mdash; and executed nothing. No response body was inspected, parsed, logged or stored.</p>
</div>
{{end}}

<h2>Findings</h2>
{{if .Hosts}}
{{range .Hosts}}
<div class="hostgroup">
<h3>{{.Host}}{{if .Address}} <span class="at">probed at {{.Address}}</span>{{end}}</h3>
<div class="wrapper">
<table><thead><tr><th>Severity</th><th>Rule</th><th>Finding</th><th>Port</th></tr></thead><tbody>
{{range .Findings}}<tr>
<td><span class="sev {{.Severity}}">{{.Severity}}</span></td>
<td><span class="ruleid">{{.RuleID}}</span>{{range .CVEs}}<br><span class="pill">{{.}}</span>{{end}}{{range .UnconfirmedCVEs}}<br><span class="pill unconf">{{.ID}} &middot; unconfirmed</span>{{end}}</td>
<td>{{.Title}}<span class="rem">{{.Detail}}</span>{{if .Evidence.Basis}}<span class="rem"><strong>Evidence:</strong> {{evidenceHTML .Evidence}}</span>{{end}}<span class="rem"><strong>Fix:</strong> {{.Remediation}}</span>{{range .UnconfirmedCVEs}}<span class="rem"><strong>{{.ID}} is not confirmed here{{if .FixedIn}} (advisory says fixed in {{.FixedIn}}){{end}}:</strong> {{.Why}}</span>{{end}}</td>
<td>{{.Port}}</td>
</tr>{{end}}
</tbody></table>
</div>
</div>
{{end}}
{{else if .Inconclusive}}<p>Nothing was assessed, so there is nothing to report. This is not a clean result.</p>
{{else}}<p>No exposure findings on the scanned targets.</p>{{end}}

<h2>How this grade was reached</h2>
{{if .GradeBandStrip}}
<p class="facts">{{.GradeBandSentence}}</p>
{{.GradeBandStrip}}
{{end}}
<p class="facts">The grade is driven by the <strong>single worst finding</strong>, not by an average
or a count &mdash; one critical exposure is one way in, and nine clean ports do not offset it. The
first row that matches decides the result:</p>
<table><thead><tr><th>If</th><th>Score</th><th>Grade</th></tr></thead><tbody>
<tr><td>any <span class="sev critical">critical</span> finding</td><td>40</td><td>F</td></tr>
<tr><td>else any <span class="sev high">high</span> finding</td><td>60</td><td>C</td></tr>
<tr><td>else any <span class="sev medium">medium</span> finding</td><td>78</td><td>B</td></tr>
<tr><td>else nothing responded, or the scan was stopped early, or our own probes failed</td><td>&mdash;</td><td>N/A</td></tr>
<tr><td>else any <span class="sev low">low</span> or <span class="sev info">info</span> finding</td><td>90</td><td>A</td></tr>
<tr><td>else no exposure observed</td><td>94</td><td>A</td></tr>
</tbody></table>
<p class="facts"><strong>A is the ceiling at this tier.</strong> A+ is reserved for an assessment
that cryptographically verifies hardware attestation and fabric isolation, which needs access
inside the hosts. A Level 1 scan cannot collect that evidence, so it does not award the grade that
claims it &mdash; a clean result here is an A, and that is the best this tier has.</p>
<p class="facts">Note the order: a finding we <em>did</em> observe stands even if the scan did not
finish, because an observed exposure is evidence either way. The reverse does not hold &mdash; an
incomplete or unreached scan can never earn a clean grade, because absence of coverage is not
absence of exposure.</p>

<h2>Scope &amp; method</h2>
<p class="facts">This is an agentless, read-only Level 1 assessment run from outside the hosts. It
observes which services are reachable, whether they require authentication, and their transport
posture. It does not install software, does not require credentials, and cannot assess
cross-tenant fabric isolation or hardware attestation &mdash; those need deeper tiers.</p>
<p class="facts">Every finding below is therefore recorded at evidence level
<strong>observed</strong>: seen from outside the host, once, at the time of the scan. Nothing here
claims a configuration was read, a signature verified, or hardware attested &mdash; those are
higher levels, and this tier cannot reach them. What does differ between findings is <em>how the
service was identified</em>, which each finding states on its own Evidence line: a service that
answered on its own API is a stronger identification than one identified only by a root page any
web server would answer.</p>
{{with .Params}}
<table class="params">
<tr><th>Probe timeout</th><td><code>-timeout {{.ProbeTimeout}}</code> &mdash; every port was given this long to answer and no longer, so &ldquo;no response&rdquo; above means &ldquo;silent for {{.ProbeTimeout}}&rdquo;.</td></tr>
<tr><th>Concurrency</th><td><code>-concurrency {{.Concurrency}}</code>{{if .ConcurrencyWasClamped}} &mdash; reduced from the {{.ConcurrencyRequested}} requested, because the open-file limit on the scanning machine could not sustain that many hosts at once. Coverage and findings are unaffected; the scan simply took longer.{{end}}</td></tr>
<tr><th>Ports probed</th><td>{{$.PortsProbed}}{{if .PortOverrides}} &mdash; overridden with <code>-ports {{.PortOverrides}}</code>{{end}}</td></tr>
{{if $.ScopeGiven}}<tr><th>Scope as given</th><td>{{$.ScopeGiven}}</td></tr>{{end}}
</table>
<p class="foot">Stated so this scan can be reproduced and so two reports can be compared. A
different timeout or port set is a different measurement, not a better or worse one.</p>
{{end}}
<p class="foot">Read-only assessment. Detection by observation, not exploitation. No customer
payload &mdash; no model weights, prompts, training data, inference content, or object contents
&mdash; was read, stored, or transmitted. Grade thresholds are provisional and will be revised as they are validated.</p>
</body></html>`))
