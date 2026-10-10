// Package domain holds the types shared across the scanner: what was observed,
// what was concluded, and how the whole scan is scored.
//
// It imports nothing of ours and contains no I/O, which is what lets the
// Phase-1 collector reuse these types without dragging the scanner along.
// Every type here crosses the collection boundary, so none of them may grow a
// field capable of carrying customer payload - see test/metadata_only_test.go,
// which enforces that.
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

// HostState records whether we actually learned anything about a host.
//
// This distinction is load-bearing. "We scanned it and found nothing" and "we
// never reached it" produce the same empty finding list, and reporting both as
// a clean result is a false all-clear - the single most damaging thing a
// security scanner can say. A typo'd hostname must never grade A+.
type HostState string

const (
	// HostResponded means at least one port gave a definitive answer, open or
	// refused. The host is alive and an empty finding list is real evidence.
	HostResponded HostState = "responded"
	// HostNoResponse means every probe timed out. That may be a firewall doing
	// its job or a host that does not exist; we cannot tell, and must not
	// claim either.
	HostNoResponse HostState = "no-response"
	// HostUnresolved means DNS lookup failed - we never reached the network.
	HostUnresolved HostState = "unresolved"
)

// HostSummary is the per-target coverage record behind the scan's headline.
type HostSummary struct {
	Host  string    `json:"host"`
	State HostState `json:"state"`
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

// GradeInconclusive is used when no target responded, so there is no evidence
// to grade. It is deliberately not a passing grade.
const GradeInconclusive Grade = "N/A"

type ScanResult struct {
	ScannerVersion string `json:"scanner_version"`
	// Label is free text the operator supplies with -label: which engagement
	// this report belongs to. It is the one field here most likely to name a
	// customer, so it must never reach the anonymized benchmark snapshot (P9).
	Label string `json:"label,omitempty"`
	// ScannedFrom records the vantage - the host the scan ran from. "Three of
	// twelve didn't answer" means something different when the answer is "you
	// were on the wrong side of a firewall", and a report read a month later
	// has no other way to say where it was taken from.
	ScannedFrom       string           `json:"scanned_from,omitempty"`
	StartedAt         time.Time        `json:"started_at"`
	CompletedAt       time.Time        `json:"completed_at"`
	TargetsScanned    int              `json:"targets_scanned"`
	HostsResponded    int              `json:"hosts_responded"`
	HostsUnanswered   int              `json:"hosts_unanswered"`
	HostsUnresolved   int              `json:"hosts_unresolved"`
	Unreachable       []HostSummary    `json:"unreachable,omitempty"`
	HostsWithFindings int              `json:"hosts_with_findings"`
	Findings          []Finding        `json:"findings"`
	Summary           map[Severity]int `json:"summary"`
	Score             int              `json:"score"`
	Grade             Grade            `json:"grade"`
	GradeReason       string           `json:"grade_reason"`
}

// Inconclusive reports whether the scan reached anything at all. A scan that
// reached nothing proves nothing, however empty its finding list.
func (r ScanResult) Inconclusive() bool { return r.HostsResponded == 0 }

// PartialCoverage reports whether some targets answered and others did not -
// the grade is then real but covers less than the operator asked for.
func (r ScanResult) PartialCoverage() bool {
	return r.HostsResponded > 0 && (r.HostsUnanswered > 0 || r.HostsUnresolved > 0)
}

func NewScanResult(start, end time.Time, hosts []HostSummary, findings []Finding) ScanResult {
	summary := map[Severity]int{}
	affected := map[string]struct{}{}
	for _, f := range findings {
		summary[f.Severity]++
		affected[f.Host] = struct{}{}
	}

	r := ScanResult{
		ScannerVersion: Version,
		StartedAt:      start, CompletedAt: end,
		TargetsScanned:    len(hosts),
		HostsWithFindings: len(affected),
		Findings:          findings, Summary: summary,
	}
	for _, h := range hosts {
		switch h.State {
		case HostResponded:
			r.HostsResponded++
		case HostUnresolved:
			r.HostsUnresolved++
			r.Unreachable = append(r.Unreachable, h)
		default:
			r.HostsUnanswered++
			r.Unreachable = append(r.Unreachable, h)
		}
	}

	r.Score, r.Grade = gradeFor(summary, r.HostsResponded)
	r.GradeReason = gradeReason(r.Grade, findings, r)
	return r
}

// gradeFor is PROVISIONAL (CLAUDE.md 10.0) - validate thresholds with buyers.
//
// responded gates the clean grades: an empty finding list only means "clean"
// if we actually reached something.
func gradeFor(s map[Severity]int, responded int) (int, Grade) {
	switch {
	case s[Critical] > 0:
		return 40, "F"
	case s[High] > 0:
		return 60, "C"
	case s[Medium] > 0:
		return 78, "B"
	case s[Low] > 0 || s[Info] > 0:
		return 90, "A"
	case responded == 0:
		return 0, GradeInconclusive
	default:
		return 100, "A+"
	}
}

// gradeReason states, in one plain sentence, which finding drove the grade.
// A grade a buyer cannot trace back to a specific cause is not persuasive.
func gradeReason(g Grade, findings []Finding, r ScanResult) string {
	switch g {
	case GradeInconclusive:
		if r.TargetsScanned == 0 {
			return "No targets were scanned."
		}
		if r.HostsUnresolved == r.TargetsScanned {
			return "No result: none of the target names could be resolved. " +
				"Check the hostnames and your DNS - this is not a clean result."
		}
		return "No result: no target responded, so nothing was verified. " +
			"The hosts may be firewalled, powered off, or unreachable from here - " +
			"this is not a clean result."
	case "A+":
		s := "No exposure was observed on the scanned targets."
		if r.PartialCoverage() {
			s += " Note that some targets did not respond and were not assessed."
		}
		return s
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
// can gate their own CI on it. 0 = clean; 1 = runtime error; 2 = usage error;
// 7 = inconclusive.
//
// Inconclusive is deliberately non-zero. A pipeline whose scan target moved,
// or whose DNS changed, must fail loudly rather than pass green forever on a
// scan that reached nothing.
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
	case r.Inconclusive():
		return 7
	default:
		return 0
	}
}
