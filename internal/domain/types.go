package domain

import "time"

type Severity string

const (
	Critical Severity = "critical"
	High     Severity = "high"
	Medium   Severity = "medium"
	Low      Severity = "low"
	Info     Severity = "info"
)

type Grade string

// Observation is a benign, read-only fact discovered about a target.
// It never contains payload (metadata-only-guard skill / CLAUDE.md P3).
type Observation struct {
	Host       string
	Port       int
	Service    string
	Open       bool
	HTTPStatus int
	TLS        bool
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
	StartedAt      time.Time        `json:"started_at"`
	CompletedAt    time.Time        `json:"completed_at"`
	TargetsScanned int              `json:"targets_scanned"`
	Findings       []Finding        `json:"findings"`
	Summary        map[Severity]int `json:"summary"`
	Score          int              `json:"score"`
	Grade          Grade            `json:"grade"`
}

func NewScanResult(start, end time.Time, targets int, findings []Finding) ScanResult {
	summary := map[Severity]int{}
	for _, f := range findings {
		summary[f.Severity]++
	}
	score, grade := gradeFor(summary)
	return ScanResult{
		StartedAt: start, CompletedAt: end, TargetsScanned: targets,
		Findings: findings, Summary: summary, Score: score, Grade: grade,
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
