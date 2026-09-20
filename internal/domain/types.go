package domain

import (
	"sort"
	"time"
)

// Version is the ray-guard release version. Overridden at build time via
// -ldflags "-X gpusecurity/internal/domain.Version=..."
var Version = "0.2.0-dev"

type Severity string

const (
	Critical Severity = "critical"
	High     Severity = "high"
	Medium   Severity = "medium"
	Low      Severity = "low"
	Info     Severity = "info"
)

type Grade string

// PortState distinguishes a refused connection from a dropped one. A filtered
// port means a firewall answered for the host; a closed port means the host
// answered for itself. That difference changes what a finding means.
type PortState string

const (
	PortOpen     PortState = "open"
	PortClosed   PortState = "closed"
	PortFiltered PortState = "filtered"
)

// TLSState records transport posture as metadata only. It deliberately carries
// no certificate subject, issuer CN, serial, or chain material - only whether
// TLS is on, what is wrong with it, and when it expires (P3).
type TLSState struct {
	Enabled bool `json:"enabled"`
	// Issue is "" when the certificate verified cleanly. Otherwise one of
	// "self-signed", "expired", "not-yet-valid", "hostname-mismatch".
	Issue string `json:"issue,omitempty"`
	// NotAfter is a date (YYYY-MM-DD), not a timestamp - coarse on purpose.
	NotAfter string `json:"not_after,omitempty"`
}

// Observation is a benign, read-only fact discovered about a target.
// It never contains payload (metadata-only-guard skill / CLAUDE.md P3).
// Every field here is existence, exposure, configuration, or version state.
// No field may carry a response body, object key, or any customer content.
type Observation struct {
	Host       string
	Port       int
	Service    string
	State      PortState
	HTTPStatus int
	TLS        TLSState
	Unauth     bool
	Note       string
}

type Finding struct {
	RuleID      string   `json:"rule_id"`
	Title       string   `json:"title"`
	Severity    Severity `json:"severity"`
	Host        string   `json:"host"`
	Port        int      `json:"port"`
	Service     string   `json:"service"`
	Detail      string   `json:"detail"`
	Remediation string   `json:"remediation"`
	CVEs        []string `json:"cves,omitempty"`
}

type ScanResult struct {
	ScannerVersion    string           `json:"scanner_version"`
	StartedAt         time.Time        `json:"started_at"`
	CompletedAt       time.Time        `json:"completed_at"`
	TargetsScanned    int              `json:"targets_scanned"`
	HostsWithFindings int              `json:"hosts_with_findings"`
	Findings          []Finding        `json:"findings"`
	Summary           map[Severity]int `json:"summary"`
	Score             int              `json:"score"`
	Grade             Grade            `json:"grade"`
	GradeReason       string           `json:"grade_reason"`
}

func NewScanResult(start, end time.Time, targets int, findings []Finding) ScanResult {
	summary := map[Severity]int{}
	hosts := map[string]struct{}{}
	for _, f := range findings {
		summary[f.Severity]++
		hosts[f.Host] = struct{}{}
	}
	score, grade := gradeFor(summary)
	return ScanResult{
		ScannerVersion: Version,
		StartedAt:      start, CompletedAt: end, TargetsScanned: targets,
		HostsWithFindings: len(hosts),
		Findings:          findings, Summary: summary,
		Score: score, Grade: grade,
		GradeReason: gradeReason(grade, findings),
	}
}

// gradeFor is PROVISIONAL (CLAUDE.md 10.0) - validate thresholds with buyers.
func gradeFor(s map[Severity]int) (int, Grade) {
	switch {
	case s[Critical] > 0:
		return 40, "F"
	case s[High] > 0:
		return 60, "C"
	case s[Medium] > 0:
		return 78, "B"
	case s[Low] > 0 || s[Info] > 0:
		return 90, "A"
	default:
		return 100, "A+"
	}
}

// gradeReason states, in one plain sentence, which finding drove the grade.
// A grade a buyer cannot trace back to a specific cause is not persuasive.
func gradeReason(g Grade, findings []Finding) string {
	switch g {
	case "A+":
		return "No exposure was observed on the scanned targets."
	case "A":
		return "Only low-severity or informational exposure was observed."
	}
	worst := WorstFinding(findings)
	if worst == nil {
		return ""
	}
	switch g {
	case "F":
		return "A critical, remotely exploitable exposure is reachable: " + worst.Title +
			". This is remote code execution, not a misconfiguration."
	case "C":
		return "A high-severity exposure is reachable: " + worst.Title +
			". Tenant isolation cannot be assured while this is open."
	default:
		return "Non-critical drift was observed: " + worst.Title + "."
	}
}

var sevOrder = []Severity{Critical, High, Medium, Low, Info}

// SeverityRank orders severities worst-first. Unknown severities sort last.
func SeverityRank(s Severity) int {
	for i, v := range sevOrder {
		if v == s {
			return i
		}
	}
	return len(sevOrder)
}

// SeverityOrder returns severities worst-first.
func SeverityOrder() []Severity { return append([]Severity(nil), sevOrder...) }

// SortFindings returns a copy ordered worst-first, then by host and port, so
// report output is deterministic (required for golden-file tests).
func SortFindings(in []Finding) []Finding {
	out := append([]Finding(nil), in...)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if ra, rb := SeverityRank(a.Severity), SeverityRank(b.Severity); ra != rb {
			return ra < rb
		}
		if a.Host != b.Host {
			return a.Host < b.Host
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		return a.RuleID < b.RuleID
	})
	return out
}

// WorstFinding returns the highest-severity finding, or nil if there are none.
func WorstFinding(findings []Finding) *Finding {
	if len(findings) == 0 {
		return nil
	}
	sorted := SortFindings(findings)
	return &sorted[0]
}

// ExitCode maps the worst observed severity to a process exit code so a tenant
// can gate their own CI on it. 0 = clean; 1 = runtime error; 2 = usage error.
func (r ScanResult) ExitCode() int {
	switch {
	case r.Summary[Critical] > 0:
		return 6
	case r.Summary[High] > 0:
		return 5
	case r.Summary[Medium] > 0:
		return 4
	case r.Summary[Low] > 0 || r.Summary[Info] > 0:
		return 3
	default:
		return 0
	}
}
