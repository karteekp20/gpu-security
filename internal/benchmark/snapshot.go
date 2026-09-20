// Package benchmark produces the anonymized scan snapshot that seeds the
// "State of Neocloud Security" index (CLAUDE.md P9).
//
// This package performs NO network I/O of any kind, by design. It writes a
// local file and nothing else. Sending that file is the operator's deliberate,
// manual choice, which keeps ray-guard air-gap-safe by construction (P4) and
// means the scanner has no phone-home surface to justify to a security lead.
package benchmark

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gpusecurity/internal/domain"
)

// Schema identifies the snapshot format so the index can version its parsers.
const Schema = "ray-guard.benchmark.v1"

// Record is one finding reduced to aggregate-safe metadata. There is
// deliberately no field for the host, the finding detail, or any response
// content - only which rule fired, on what kind of service, how bad it was.
type Record struct {
	HostID   string          `json:"host_id"` // salted hash, not the hostname
	RuleID   string          `json:"rule_id"`
	Service  string          `json:"service"`
	Port     int             `json:"port"`
	Severity domain.Severity `json:"severity"`
}

// Snapshot is the anonymized artifact written to disk.
type Snapshot struct {
	Schema            string         `json:"schema"`
	ScannerVersion    string         `json:"scanner_version"`
	ScannedAt         string         `json:"scanned_at"` // truncated to the hour
	TargetsScanned    int            `json:"targets_scanned"`
	HostsWithFindings int            `json:"hosts_with_findings"`
	Grade             domain.Grade   `json:"grade"`
	Score             int            `json:"score"`
	SeverityCounts    map[string]int `json:"severity_counts"`
	Findings          []Record       `json:"findings"`
	Notice            string         `json:"notice"`
}

const notice = "Anonymized aggregate metadata only. Host identifiers are salted hashes with a " +
	"single-use random salt and cannot be reversed or correlated across snapshots. " +
	"Contains no hostnames, IPs, finding details, credentials, or any customer content."

// Build reduces a scan result to anonymized metadata. A fresh random salt is
// generated per snapshot, so host identifiers are stable within one file and
// unlinkable across files.
func Build(r domain.ScanResult, now time.Time) (Snapshot, error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return Snapshot{}, fmt.Errorf("generating snapshot salt: %w", err)
	}

	counts := map[string]int{}
	for sev, n := range r.Summary {
		if n > 0 {
			counts[string(sev)] = n
		}
	}

	records := make([]Record, 0, len(r.Findings))
	for _, f := range domain.SortFindings(r.Findings) {
		records = append(records, Record{
			HostID:   hashHost(salt, f.Host),
			RuleID:   f.RuleID,
			Service:  f.Service,
			Port:     f.Port,
			Severity: f.Severity,
		})
	}

	return Snapshot{
		Schema:            Schema,
		ScannerVersion:    r.ScannerVersion,
		ScannedAt:         now.UTC().Truncate(time.Hour).Format(time.RFC3339),
		TargetsScanned:    r.TargetsScanned,
		HostsWithFindings: r.HostsWithFindings,
		Grade:             r.Grade,
		Score:             r.Score,
		SeverityCounts:    counts,
		Findings:          records,
		Notice:            notice,
	}, nil
}

func hashHost(salt []byte, host string) string {
	h := sha256.New()
	h.Write(salt)
	h.Write([]byte(host))
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// Write builds and writes the snapshot. It never transmits anything.
func Write(path string, r domain.ScanResult, now time.Time) error {
	snap, err := Build(r, now)
	if err != nil {
		return err
	}
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	b, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}
