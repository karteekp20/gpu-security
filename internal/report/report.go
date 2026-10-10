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
	Host     string
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
		hosts = append(hosts, hostGroup{Host: f.Host, Findings: []domain.Finding{f}})
	}

	hasRay := false
	for _, f := range r.Findings {
		if strings.HasPrefix(f.RuleID, "RG-RAY-") {
			hasRay = true
			break
		}
	}

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
	}
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
	if r.Inconclusive() {
		fmt.Fprintf(w, "Grade: %s - INCONCLUSIVE\n", v.Grade)
	} else {
		fmt.Fprintf(w, "Grade: %s (score %d/100)\n", v.Grade, v.Score)
	}
	if v.GradeReason != "" {
		fmt.Fprintf(w, "%s\n", wrap(v.GradeReason, 76))
	}
	fmt.Fprintf(w, "Targets scanned: %d   Responded: %d   Hosts with findings: %d\n",
		v.TargetsScanned, v.HostsResponded, v.HostsWithFindings)
	if v.HostsUnanswered > 0 || v.HostsUnresolved > 0 {
		fmt.Fprintf(w, "Not assessed: %d no response, %d unresolved\n",
			v.HostsUnanswered, v.HostsUnresolved)
	}
	for _, c := range v.SevCounts {
		fmt.Fprintf(w, "  %-8s %d\n", c.Severity, c.Count)
	}
	if len(v.Findings) == 0 {
		if r.Inconclusive() {
			fmt.Fprintf(w, "\nNothing was assessed. Do not read this as a clean result.\n")
			return
		}
		fmt.Fprintf(w, "\nNo exposure findings on the scanned targets.\n")
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

var htmlTmpl = template.Must(template.New("r").Funcs(template.FuncMap{
	"gradeClass": gradeClass,
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
.sev{font-weight:600;font-size:.8rem;text-transform:uppercase;white-space:nowrap}
.sev.critical{color:#c0392b}.sev.high{color:#e67e22}.sev.medium{color:#d4a017}.sev.low{color:#3498db}.sev.info{color:var(--muted)}
.sev::before{content:"\25CF  ";font-size:.9em}
.pill{display:inline-block;background:var(--card);border:1px solid var(--line);border-radius:.3rem;padding:.05rem .4rem;font-size:.78rem;margin:.1rem .3rem .1rem 0;white-space:nowrap}
.ruleid{white-space:nowrap}
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
    <p class="facts">{{if not .Inconclusive}}Score {{.Score}}/100 &middot; {{end}}{{.TargetsScanned}} target(s) in {{.Duration}} &middot; {{.HostsResponded}} responded &middot; {{.HostsWithFindings}} with findings</p>
  </div>
</div>
{{if .SevCounts}}<ul class="counts">{{range .SevCounts}}<li><span class="sev {{.Severity}}">{{.Severity}}</span> {{.Count}}</li>{{end}}</ul>{{end}}

{{if .UnreachableShown}}
<div class="warn">
<p><strong>Coverage gap &mdash; {{len .Unreachable}} target(s) were not assessed.</strong>
{{if .Inconclusive}}Nothing responded, so this scan verified nothing. Do not read it as a clean
result.{{else}}The grade above covers only the targets that responded.{{end}}</p>
<ul>
{{range .UnreachableShown}}<li><code>{{.Host}}</code> &mdash; {{if eq .State "unresolved"}}name could not be resolved{{else}}no response (firewalled, powered off, or unreachable from here){{end}}</li>
{{end}}{{if .UnreachableExtra}}<li>&hellip; and {{.UnreachableExtra}} more (see <code>report.json</code>)</li>{{end}}</ul>
</div>
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
<p>An unauthenticated Ray dashboard is not a hardening gap &mdash; it is remote code execution.
Ray's Jobs API accepts job submissions from anyone who can reach it, and by design that means
arbitrary code runs on your cluster with the permissions of the Ray worker.</p>
<p>This is tracked as <strong>CVE-2023-48022</strong> and <strong>CVE-2025-62593</strong>, and it has been
exploited in the wild: the <strong>ShadowRay</strong> campaign compromised exposed Ray clusters to steal
credentials and mine cryptocurrency on rented GPUs. Exposed clusters were found by internet-wide
scanning, not by targeting.</p>
<p>The exposure above was confirmed by observation only &mdash; a single benign GET request. No
job was submitted and no code was executed against your infrastructure.</p>
</div>
{{end}}

<h2>Findings</h2>
{{if .Hosts}}
{{range .Hosts}}
<div class="hostgroup">
<h3>{{.Host}}</h3>
<div class="wrapper">
<table><thead><tr><th>Severity</th><th>Rule</th><th>Finding</th><th>Port</th></tr></thead><tbody>
{{range .Findings}}<tr>
<td><span class="sev {{.Severity}}">{{.Severity}}</span></td>
<td><span class="ruleid">{{.RuleID}}</span>{{range .CVEs}}<br><span class="pill">{{.}}</span>{{end}}</td>
<td>{{.Title}}<span class="rem">{{.Detail}}</span><span class="rem"><strong>Fix:</strong> {{.Remediation}}</span></td>
<td>{{.Port}}</td>
</tr>{{end}}
</tbody></table>
</div>
</div>
{{end}}
{{else if .Inconclusive}}<p>Nothing was assessed, so there is nothing to report. This is not a clean result.</p>
{{else}}<p>No exposure findings on the scanned targets.</p>{{end}}

<h2>Scope &amp; method</h2>
<p class="facts">This is an agentless, read-only Level 1 assessment run from outside the hosts. It
observes which services are reachable, whether they require authentication, and their transport
posture. It does not install software, does not require credentials, and cannot assess
cross-tenant fabric isolation or hardware attestation &mdash; those need deeper tiers.</p>

<p class="foot">Read-only assessment. Detection by observation, not exploitation. No customer
payload &mdash; no model weights, prompts, training data, inference content, or object contents
&mdash; was read, stored, or transmitted. Grade thresholds are provisional and will be revised as they are validated.</p>
</body></html>`))
