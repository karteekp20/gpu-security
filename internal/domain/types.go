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
	"fmt"
	"sort"
	"strings"
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
	// "self-signed", "expired", "not-yet-valid", "hostname-mismatch", or
	// "untrusted" for a verification error outside those four classes. The
	// list is the Rego input contract (policies/README.md), so a new class
	// belongs in both places.
	Issue string `json:"issue,omitempty"`
	// NotAfter is a date (YYYY-MM-DD), not a timestamp - coarse on purpose.
	NotAfter string `json:"not_after,omitempty"`
	// Version is the negotiated protocol version ("1.0" ... "1.3"), which is
	// posture rather than content. It is recorded because obsolete versions
	// are a finding in their own right, and because a scanner that cannot
	// speak to them cannot see what is behind them either.
	Version string `json:"version,omitempty"`
}

// ObsoleteTLS reports whether the negotiated version is below TLS 1.2, the
// floor every current compliance baseline expects (and the floor Go's own
// clients default to).
func (t TLSState) ObsoleteTLS() bool {
	return t.Version == "1.0" || t.Version == "1.1"
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
	// HostProbeFailed means our own probes failed - the scanner ran out of
	// file descriptors or ephemeral ports - so we never managed to ask. It is
	// deliberately distinct from HostNoResponse: "firewalled, powered off, or
	// unreachable" is a statement about the customer's host, and this is a
	// statement about the machine the scan ran from. The remedies differ too,
	// which is the practical reason an operator needs to see the difference.
	HostProbeFailed HostState = "probe-failed"
)

// HostSummary is the per-target coverage record behind the scan's headline.
type HostSummary struct {
	Host  string    `json:"host"`
	State HostState `json:"state"`
	// Address is the single address every probe for this host dialed. It is
	// set only when the operator named a host rather than an address, because
	// that is the only case where the report would otherwise not say which
	// machine was assessed: a report for "ray.customer.internal" that cannot
	// be traced back to an address cannot be re-checked, and on a cluster
	// behind round-robin DNS it does not even identify the host it describes.
	Address string `json:"address,omitempty"`
	// AddressesFound is how many addresses the name resolved to. More than
	// one means the name fans out across machines and this scan covered one
	// of them - see ScanResult.AddressesUnassessed, which gates clean grades.
	AddressesFound int `json:"addresses_found,omitempty"`
}

// UnassessedAddresses is how many of this host's addresses were never probed.
func (h HostSummary) UnassessedAddresses() int {
	if h.AddressesFound > 1 {
		return h.AddressesFound - 1
	}
	return 0
}

// Observation is a benign, read-only fact discovered about a target.
// It never contains payload (metadata-only-guard skill / CLAUDE.md P3).
// Every field here is existence, exposure, configuration, or version state.
// No field may carry a response body, object key, or any customer content.
// Observation is one benign fact about one port. The JSON tags are the input
// contract for the Rego rule library (/policies): the Phase-1 collector ships
// observations in this shape, joined with their host's state, and every
// verification sentinel reads these field names. Renaming one silently stops
// rules matching, so the names are part of the API, not a detail.
//
// Note carries a short scanner-authored string ("control/RPC port; speaks no
// HTTP"), never anything taken from a response body (P3).
type Observation struct {
	Host       string    `json:"host"`
	Port       int       `json:"port"`
	Service    string    `json:"service"`
	State      PortState `json:"state"`
	HTTPStatus int       `json:"http_status"`
	TLS        TLSState  `json:"tls"`
	Unauth     bool      `json:"unauth"`
	Note       string    `json:"note,omitempty"`
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

// GradeAPlus is defined but is NOT reachable from this scanner, and that is the
// point. CLAUDE.md 10.0 reserves A+ for a tier that cryptographically verifies
// hardware attestation and fabric isolation (L3). An agentless port-and-TLS
// scan cannot look at either, so a clean L1 run that printed A+ would be
// claiming a grade whose published meaning is "hardware attested" - and once
// the Phase-1 credential is issued off the grade, that same path would sign
// "Issuable - Gold" for hardware nobody examined.
//
// L1GradeCeiling is therefore what a clean L1 scan earns: the top of the A
// band, not a penalty. It is the highest grade available at this tier, and
// TestL1CannotEarnAPlus enforces that nothing reaches past it.
const (
	GradeAPlus     Grade = "A+"
	L1GradeCeiling Grade = "A"
)

// TierL1 names what this scanner assesses, and it travels in the report so a
// grade is never read without its scope. A grade means nothing on its own: "A
// at L1" and "A at L2" are different claims about different evidence, and a
// bare letter invites the reader to assume the stronger one.
const TierL1 = "L1"

// L1CleanScore is the score for an L1 scan with no findings: the top of
// CLAUDE.md 10.0's A band (85-94), not 100. 95-100 is the A+ band and belongs
// to the attested tiers.
const L1CleanScore = 94

type ScanResult struct {
	ScannerVersion string `json:"scanner_version"`
	// Tier is the assessment tier this result covers, always TierL1 from this
	// binary. It is emitted so no consumer - a report reader, the Phase-1
	// control plane, or a credential - can take the grade without its scope.
	Tier string `json:"tier"`
	// Label is free text the operator supplies with -label: which engagement
	// this report belongs to. It is the one field here most likely to name a
	// customer, so it must never reach the anonymized benchmark snapshot (P9).
	Label string `json:"label,omitempty"`
	// ScannedFrom records the vantage - the host the scan ran from. "Three of
	// twelve didn't answer" means something different when the answer is "you
	// were on the wrong side of a firewall", and a report read a month later
	// has no other way to say where it was taken from.
	ScannedFrom string    `json:"scanned_from,omitempty"`
	StartedAt   time.Time `json:"started_at"`
	CompletedAt time.Time `json:"completed_at"`
	// TargetsRequested is what the operator asked for; TargetsScanned is what
	// was actually attempted. They differ only when the scan was stopped early,
	// and the difference is the whole point: "41 of 254 probed" is a different
	// report from "41 probed".
	TargetsRequested int `json:"targets_requested"`
	TargetsScanned   int `json:"targets_scanned"`
	// Interrupted means the operator stopped the scan before it finished
	// (Ctrl-C). Findings already observed still stand - exposure is positive
	// evidence - but the absence of a finding proves nothing about a target
	// that was never probed, so an interrupted scan can never earn a clean
	// grade.
	Interrupted bool `json:"interrupted,omitempty"`
	// ProbeErrors counts probes that failed inside the scanner rather than
	// telling us anything about a target: the open-file or ephemeral-port
	// limit. Any non-zero value means the measurement itself is unreliable, so
	// it gates clean grades exactly as Interrupted does.
	ProbeErrors      int           `json:"probe_errors,omitempty"`
	HostsResponded   int           `json:"hosts_responded"`
	HostsUnanswered  int           `json:"hosts_unanswered"`
	HostsUnresolved  int           `json:"hosts_unresolved"`
	HostsProbeFailed int           `json:"hosts_probe_failed,omitempty"`
	Unreachable      []HostSummary `json:"unreachable,omitempty"`
	// AddressesUnassessed counts addresses behind the scanned names that were
	// never probed, and MultiAddress names the hosts they belong to. A name
	// with several addresses is several machines; probing one of them and
	// reporting a clean result is the false all-clear in a new shape, so a
	// non-zero count gates clean grades exactly as Interrupted does.
	AddressesUnassessed int           `json:"addresses_unassessed,omitempty"`
	MultiAddress        []HostSummary `json:"multi_address,omitempty"`
	// Addresses maps each named target to the address its probes dialed. It
	// holds only names, so a scan given addresses or a CIDR block carries
	// none. Without it a report for a name says nothing about which machine
	// it describes, and cannot be re-checked against that machine later.
	Addresses         map[string]string `json:"addresses,omitempty"`
	HostsWithFindings int               `json:"hosts_with_findings"`
	Findings          []Finding         `json:"findings"`
	Summary           map[Severity]int  `json:"summary"`
	Score             int               `json:"score"`
	Grade             Grade             `json:"grade"`
	GradeReason       string            `json:"grade_reason"`
}

// Inconclusive reports whether the scan reached anything at all. A scan that
// reached nothing proves nothing, however empty its finding list.
func (r ScanResult) Inconclusive() bool { return r.HostsResponded == 0 }

// Degraded reports whether the scanner's own probes failed during the run. A
// degraded scan may still have found real exposure - what it saw, it saw - but
// what it did not see proves nothing, because some of the looking failed.
func (r ScanResult) Degraded() bool { return r.ProbeErrors > 0 }

// Graded reports whether the run produced a gradeable verdict. It is false
// both when nothing responded and when an interrupted scan found nothing worth
// grading - in neither case is a score meaningful, and showing one anyway is
// how a non-result starts looking like a pass.
func (r ScanResult) Graded() bool { return r.Grade != GradeInconclusive }

// PartialCoverage reports whether some targets answered and others did not -
// the grade is then real but covers less than the operator asked for.
func (r ScanResult) PartialCoverage() bool {
	return r.HostsResponded > 0 && (r.HostsUnanswered > 0 || r.HostsUnresolved > 0)
}

// Run is one execution of the scanner as the scanner saw it: what it was asked
// to cover, what came back, and the two ways coverage can be less than it
// looks - the operator stopped it, or our own probes failed.
//
// Targets that were never probed belong in neither Hosts nor Unreachable:
// Requested is how their absence is accounted for. "We stopped" and "it did
// not answer" are different facts, and only one of them is about the customer.
type Run struct {
	Start, End time.Time
	// Requested is what the operator asked for: targets plus buckets.
	Requested   int
	Hosts       []HostSummary
	Findings    []Finding
	Interrupted bool
	ProbeErrors int
}

// NewScanResult records a run that finished and covered everything it was
// asked to. Anything less complete goes through NewResult with a Run.
func NewScanResult(start, end time.Time, hosts []HostSummary, findings []Finding) ScanResult {
	return NewResult(Run{Start: start, End: end, Requested: len(hosts), Hosts: hosts, Findings: findings})
}

// NewResult scores a run. A run that was interrupted, or during which the
// scanner's own probes failed, cannot reach a clean grade: see gradeFor.
func NewResult(run Run) ScanResult {
	start, end, requested := run.Start, run.End, run.Requested
	hosts, findings := run.Hosts, run.Findings
	summary := map[Severity]int{}
	affected := map[string]struct{}{}
	for _, f := range findings {
		summary[f.Severity]++
		affected[f.Host] = struct{}{}
	}

	r := ScanResult{
		ScannerVersion: Version,
		Tier:           TierL1,
		StartedAt:      start, CompletedAt: end,
		TargetsRequested:  requested,
		TargetsScanned:    len(hosts),
		Interrupted:       run.Interrupted,
		ProbeErrors:       run.ProbeErrors,
		HostsWithFindings: len(affected),
		Findings:          findings, Summary: summary,
	}
	for _, h := range hosts {
		if h.Address != "" {
			if r.Addresses == nil {
				r.Addresses = map[string]string{}
			}
			r.Addresses[h.Host] = h.Address
		}
		if n := h.UnassessedAddresses(); n > 0 {
			r.AddressesUnassessed += n
			r.MultiAddress = append(r.MultiAddress, h)
		}
		switch h.State {
		case HostResponded:
			r.HostsResponded++
		case HostUnresolved:
			r.HostsUnresolved++
			r.Unreachable = append(r.Unreachable, h)
		case HostProbeFailed:
			r.HostsProbeFailed++
			r.Unreachable = append(r.Unreachable, h)
		default:
			r.HostsUnanswered++
			r.Unreachable = append(r.Unreachable, h)
		}
	}

	complete := !run.Interrupted && run.ProbeErrors == 0 && r.AddressesUnassessed == 0
	r.Score, r.Grade = gradeFor(summary, r.HostsResponded, complete)
	r.GradeReason = gradeReason(r.Grade, findings, r)
	return r
}

// gradeFor is PROVISIONAL (CLAUDE.md 10.0) - validate thresholds with buyers.
//
// responded and complete both gate the clean grades, for the same reason: A and
// A+ are claims about what is *not* there, and absence of evidence is only
// evidence of absence if we looked. A finding-driven grade needs neither gate -
// an exposure we observed is observed whether or not the scan finished - so the
// two checks sit below the severity cases, not above them.
func gradeFor(s map[Severity]int, responded int, complete bool) (int, Grade) {
	switch {
	case s[Critical] > 0:
		return 40, "F"
	case s[High] > 0:
		return 60, "C"
	case s[Medium] > 0:
		return 78, "B"
	case responded == 0 || !complete:
		return 0, GradeInconclusive
	case s[Low] > 0 || s[Info] > 0:
		return 90, L1GradeCeiling
	default:
		// NOT A+. See GradeAPlus: that grade's published meaning is attested
		// hardware, which this tier does not assess.
		return L1CleanScore, L1GradeCeiling
	}
}

// codeExecutionRules are the rules where unauthenticated reachability IS code
// execution, by the software's own design rather than by a flaw we are
// guessing at. Both are verified against the real software in the integration
// suite: Ray's dashboard serves POST /api/jobs/, which runs a caller-supplied
// entrypoint, and TorchServe's management API registers a model from any URL
// the caller names (CVE-2023-43654).
//
// It is a named set rather than a severity test because the sentence is a
// strong claim. A future Critical that is not code execution must not inherit
// it by being Critical, which is what keying on severity would do.
var codeExecutionRules = map[string]bool{
	"RG-RAY-001":        true,
	"RG-TORCHSERVE-001": true,
}

// gradeReason states, in one plain sentence, which finding drove the grade.
// A grade a buyer cannot trace back to a specific cause is not persuasive.
func gradeReason(g Grade, findings []Finding, r ScanResult) string {
	if r.Interrupted {
		return interruptedReason(g, findings, r)
	}
	if r.Degraded() {
		return degradedReason(g, findings, r)
	}
	if r.AddressesUnassessed > 0 {
		return unassessedAddressReason(g, findings, r)
	}
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
	case L1GradeCeiling:
		var s string
		if len(findings) == 0 {
			s = "No exposure was observed on the scanned targets."
			if r.PartialCoverage() {
				s += " Note that some targets did not respond and were not assessed."
			}
		} else {
			s = "Only low-severity or informational exposure was observed."
		}
		// Stated with the grade rather than in a footnote, because the grade is
		// what gets quoted and the ceiling is what makes it honest.
		return s + " A is the highest grade a Level 1 assessment can earn: A+ " +
			"requires cryptographic hardware attestation and fabric-isolation " +
			"evidence, which this assessment does not collect."
	}
	worst := WorstFinding(findings)
	if worst == nil {
		return ""
	}
	switch g {
	case "F":
		s := "A critical exposure is reachable: " + worst.Title + "."
		if codeExecutionRules[worst.RuleID] {
			s += " Reaching it is sufficient to run code on it: remote code execution" +
				" by the software's own design, not a misconfiguration of yours."
		}
		return s
	case "C":
		return "A high-severity exposure is reachable: " + worst.Title +
			". Tenant isolation cannot be assured while this is open."
	default:
		return "Non-critical drift was observed: " + worst.Title + "."
	}
}

// interruptedReason says the one thing the reader of a partial report needs to
// know first: how much of it is missing. A grade driven by a finding is still
// stated - the exposure was observed - but it is stated with the coverage gap
// attached, because the honest reading of a stopped scan is "at least this
// bad", never "this bad".
func interruptedReason(g Grade, findings []Finding, r ScanResult) string {
	coverage := fmt.Sprintf("%d of %d targets were probed", r.TargetsScanned, r.TargetsRequested)
	if g == GradeInconclusive {
		return "No grade: the scan was stopped before it finished, so coverage is " +
			"incomplete and there is no basis for a clean result (" + coverage +
			"). Re-run it to completion."
	}
	worst := WorstFinding(findings)
	if worst == nil {
		return "The scan was stopped before it finished (" + coverage + ")."
	}
	return "The scan was stopped before it finished, so this is a floor and not " +
		"a verdict (" + coverage + "). What was observed: " + worst.Title +
		". Worse exposure may exist on the targets that were not probed."
}

// degradedReason explains a run whose own probes failed. The remedy is local
// and specific, so it is stated: this is almost always the open-file limit,
// and the operator can fix it in one command and re-run.
func degradedReason(g Grade, findings []Finding, r ScanResult) string {
	const remedy = "This is the scanner hitting a local limit, not a finding about the " +
		"targets: lower -concurrency, or raise the host's hard open-file limit " +
		"(ulimit -Hn; the soft limit is raised automatically), then re-run."
	count := fmt.Sprintf("%d probe(s) failed inside the scanner", r.ProbeErrors)
	if g == GradeInconclusive {
		return "No grade: " + count + ", so these results are unreliable. " + remedy
	}
	worst := WorstFinding(findings)
	if worst == nil {
		return count + ". " + remedy
	}
	return "Treat this as a floor, not a verdict: " + count + ", so exposure may have " +
		"been missed. What was observed: " + worst.Title + ". " + remedy
}

// unassessedAddressReason explains a run that covered one address of a name
// that has several. The remedy is the operator's and it is specific, so it is
// stated: pass the addresses, which is also the only way to keep the report
// traceable to particular machines.
//
// The gap is disclosed instead of graded because a note beside a 3rem letter
// loses to the letter - the same reasoning that made grades tier-scoped. "A,
// but we only looked at one of your three nodes" reads as A.
func unassessedAddressReason(g Grade, findings []Finding, r ScanResult) string {
	var names []string
	for _, h := range r.MultiAddress {
		names = append(names, fmt.Sprintf("%s resolves to %d addresses, %s was assessed",
			h.Host, h.AddressesFound, h.Address))
	}
	detail := strings.Join(names, "; ")
	const remedy = "Pass the addresses themselves as targets to cover them all."
	if g == GradeInconclusive {
		return "No grade: " + detail + ". A name that fans out across machines " +
			"was assessed on one of them, so there is no basis for a clean result. " +
			remedy
	}
	worst := WorstFinding(findings)
	if worst == nil {
		return detail + ". " + remedy
	}
	return "Treat this as a floor, not a verdict: " + detail +
		", so exposure on the others would not have been seen. What was observed: " +
		worst.Title + ". " + remedy
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

// ExitInterrupted follows the shell convention for a process stopped by
// SIGINT (128 + 2). It takes precedence over the severity codes: those answer
// "how bad is this cluster", and a run that did not finish has not earned an
// answer to that question. Any caller gating on 0 still fails, which is the
// property that matters.
const ExitInterrupted = 130

// ExitCode maps the worst observed severity to a process exit code so a tenant
// can gate their own CI on it. 0 = clean; 1 = runtime error; 2 = usage error;
// 7 = inconclusive; 130 = interrupted.
//
// Inconclusive is deliberately non-zero. A pipeline whose scan target moved,
// or whose DNS changed, must fail loudly rather than pass green forever on a
// scan that reached nothing.
func (r ScanResult) ExitCode() int {
	switch {
	case r.Interrupted:
		return ExitInterrupted
	case !r.Graded():
		// No grade, for any of the reasons there are: nothing responded, or
		// the measurement was unreliable. It sits above the severity codes
		// because those answer "how bad is this cluster" and read as a
		// complete verdict; a run with no grade has not earned one. Either way
		// a pipeline must not pass.
		return 7
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
