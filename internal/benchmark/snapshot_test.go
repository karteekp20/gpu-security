package benchmark

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"gpusecurity/internal/domain"
)

// respondedHosts builds n targets that all answered, so these tests exercise
// anonymization rather than coverage handling.
func respondedHosts(n int) []domain.HostSummary {
	out := make([]domain.HostSummary, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, domain.HostSummary{
			Host:  fmt.Sprintf("gpu-node-%02d.internal.example.com", i),
			State: domain.HostResponded,
		})
	}
	return out
}

func sample() domain.ScanResult {
	findings := []domain.Finding{
		{RuleID: "RG-RAY-001", Title: "Unauthenticated Ray dashboard", Severity: domain.Critical,
			Host: "gpu-node-01.internal.example.com", Port: 8265, Service: "ray-dashboard",
			Detail:      "HTTP 200 without authentication on port 8265",
			Remediation: "Enable Ray authentication."},
		{RuleID: "RG-OLLAMA-001", Title: "Unauthenticated Ollama API", Severity: domain.Medium,
			Host: "gpu-node-01.internal.example.com", Port: 11434, Service: "ollama",
			Detail: "HTTP 200 without authentication on port 11434"},
	}
	start := time.Date(2026, 9, 20, 14, 37, 12, 0, time.UTC)
	return domain.NewScanResult(start, start.Add(9*time.Second), respondedHosts(3), findings)
}

func TestSnapshotOmitsRawHostnames(t *testing.T) {
	snap, err := Build(sample(), time.Now())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	b, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, forbidden := range []string{
		"gpu-node-01", "internal.example.com",
		"HTTP 200 without authentication", // finding detail
		"Enable Ray authentication",       // remediation text
	} {
		if strings.Contains(string(b), forbidden) {
			t.Errorf("snapshot leaked %q:\n%s", forbidden, b)
		}
	}
}

func TestSnapshotKeepsAggregateMetadata(t *testing.T) {
	snap, err := Build(sample(), time.Now())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if snap.Schema != Schema {
		t.Errorf("want schema %q, got %q", Schema, snap.Schema)
	}
	if snap.Grade != "F" || snap.SeverityCounts["critical"] != 1 {
		t.Errorf("aggregate posture should survive anonymization, got %+v", snap)
	}
	if len(snap.Findings) != 2 {
		t.Fatalf("want 2 records, got %d", len(snap.Findings))
	}
	if snap.Findings[0].RuleID != "RG-RAY-001" || snap.Findings[0].Port != 8265 {
		t.Errorf("rule ID and port are metadata and must be kept: %+v", snap.Findings[0])
	}
}

func TestSnapshotHostIDsStableWithinButNotAcrossSnapshots(t *testing.T) {
	r := sample()
	a, err := Build(r, time.Now())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if a.Findings[0].HostID != a.Findings[1].HostID {
		t.Error("the same host must hash identically within one snapshot")
	}

	b, err := Build(r, time.Now())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if a.Findings[0].HostID == b.Findings[0].HostID {
		t.Error("a single-use salt must make host IDs unlinkable across snapshots")
	}
}

func TestSnapshotTimestampIsCoarse(t *testing.T) {
	snap, err := Build(sample(), time.Date(2026, 9, 20, 14, 37, 12, 0, time.UTC))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if snap.ScannedAt != "2026-09-20T14:00:00Z" {
		t.Errorf("timestamp should be truncated to the hour, got %q", snap.ScannedAt)
	}
}

func TestWriteCreatesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "snapshot.json")
	if err := Write(path, sample(), time.Now()); err != nil {
		t.Fatalf("write: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	var snap Snapshot
	if err := json.Unmarshal(b, &snap); err != nil {
		t.Fatalf("snapshot is not valid JSON: %v", err)
	}
	if snap.Notice == "" {
		t.Error("the snapshot should state in-band what it does and does not contain")
	}
}

func TestEmptyScanProducesCleanSnapshot(t *testing.T) {
	start := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	snap, err := Build(domain.NewScanResult(start, start, respondedHosts(5), nil), time.Now())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if snap.Grade != domain.L1GradeCeiling || len(snap.Findings) != 0 {
		t.Errorf("a clean scan should snapshot as the L1 ceiling with no records, got %+v", snap)
	}
}

// TestEngagementLabelNeverReachesTheSnapshot is the P9 guard that matters
// most. -label is free text an operator types to say which engagement a
// report belongs to, so in practice it contains a customer's name - and the
// snapshot is the one artifact designed to be shared with us and published as
// an aggregate index. The label must not be in it, and neither must the host
// the scan ran from.
func TestEngagementLabelNeverReachesTheSnapshot(t *testing.T) {
	start := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	r := domain.NewScanResult(start, start.Add(time.Second), respondedHosts(3),
		[]domain.Finding{{
			RuleID: "RG-RAY-001", Title: "Unauthenticated Ray dashboard / Jobs API exposed",
			Severity: domain.Critical, Host: "10.1.2.3", Port: 8265, Service: "ray-dashboard",
		}})
	const client = "ACME-CONFIDENTIAL-CLIENT-NAME"
	const vantage = "assessor-laptop-7"
	r.Label = client + " - cluster A"
	r.ScannedFrom = vantage

	snap, err := Build(r, time.Now())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	b, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for what, needle := range map[string]string{
		"the engagement label": client,
		"the scanning host":    vantage,
	} {
		if bytes.Contains(b, []byte(needle)) {
			t.Errorf("P9 VIOLATION: the snapshot carries %s", what)
		}
	}

	// And structurally, so this cannot be reintroduced by a field rather than
	// by a value.
	rt := reflect.TypeOf(Snapshot{})
	for i := 0; i < rt.NumField(); i++ {
		switch name := strings.ToLower(rt.Field(i).Name); {
		case strings.Contains(name, "label"),
			strings.Contains(name, "from"),
			strings.Contains(name, "hostname"):
			t.Errorf("Snapshot.%s: the snapshot must not have a field for the label or the vantage",
				rt.Field(i).Name)
		}
	}
}

// TestInterruptedScanIsMarkedInTheSnapshot. The index aggregates these files
// into a published claim about how exposed the industry is; a scan that
// stopped after 4 of 254 targets contributes findings from 4 hosts and
// silence from 250. Averaging that in would report the industry as healthier
// than it is, so the flag has to travel with the data.
func TestInterruptedScanIsMarkedInTheSnapshot(t *testing.T) {
	start := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	r := domain.NewResult(domain.Run{Start: start, End: start.Add(time.Second),
		Requested: 254, Hosts: respondedHosts(4), Interrupted: true})

	snap, err := Build(r, time.Now())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if !snap.Interrupted {
		t.Error("Interrupted is false for a partial scan; the index cannot exclude it")
	}
	if snap.TargetsScanned != 4 {
		t.Errorf("TargetsScanned = %d, want the 4 actually probed", snap.TargetsScanned)
	}
	if snap.Grade != domain.GradeInconclusive {
		t.Errorf("grade %s: a partial scan must not contribute a clean grade to the index", snap.Grade)
	}

	complete, err := Build(domain.NewScanResult(start, start.Add(time.Second), respondedHosts(4), nil), time.Now())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if complete.Interrupted {
		t.Error("Interrupted is true for a completed scan")
	}
}

// TestDegradedScanIsMarkedInTheSnapshot. Same argument as Interrupted: a run
// whose own probes failed contributes a finding count that is a floor, and an
// index that averages floors in reports the industry as healthier than it is.
func TestDegradedScanIsMarkedInTheSnapshot(t *testing.T) {
	start := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	r := domain.NewResult(domain.Run{Start: start, End: start.Add(time.Second),
		Requested: 4, Hosts: respondedHosts(4), ProbeErrors: 9})

	snap, err := Build(r, time.Now())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if !snap.Degraded {
		t.Error("Degraded is false for a run whose probes failed; the index cannot exclude it")
	}
	if snap.Grade != domain.GradeInconclusive {
		t.Errorf("grade %s: an unreliable run must not contribute a clean grade", snap.Grade)
	}

	clean, err := Build(domain.NewScanResult(start, start.Add(time.Second), respondedHosts(4), nil), time.Now())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if clean.Degraded {
		t.Error("Degraded is true for a run whose probes all completed")
	}
}

// The resolved address is the same class of fact as the hostname, and the
// snapshot has never carried hostnames - only a salted hash (Record.HostID).
// It is worth its own guard because the address arrives by a new route: the
// scanner now records which machine each named target was probed at, so
// ScanResult carries an address map and a MultiAddress list that the snapshot
// is built from. An internal address identifies a customer's network as
// surely as its name does.
func TestResolvedAddressesNeverReachTheSnapshot(t *testing.T) {
	start := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	const addr = "10.77.88.99"
	hosts := []domain.HostSummary{
		{Host: "ray.acme-confidential.internal", State: domain.HostResponded,
			Address: addr, AddressesFound: 3},
	}
	r := domain.NewScanResult(start, start.Add(time.Second), hosts,
		[]domain.Finding{{
			RuleID: "RG-RAY-001", Title: "Unauthenticated Ray dashboard / Jobs API exposed",
			Severity: domain.Critical, Host: "ray.acme-confidential.internal",
			Port: 8265, Service: "ray-dashboard",
		}})
	if r.Addresses[hosts[0].Host] != addr {
		t.Fatalf("precondition: the scan result should carry the probed address, got %+v", r.Addresses)
	}

	snap, err := Build(r, time.Now())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	b, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for what, needle := range map[string]string{
		"a resolved address": addr,
		"a target hostname":  "acme-confidential",
	} {
		if bytes.Contains(b, []byte(needle)) {
			t.Errorf("P9 VIOLATION: the snapshot carries %s", what)
		}
	}

	// Structurally too, on both the snapshot and its findings: a field is the
	// way this would come back.
	for _, rt := range []reflect.Type{reflect.TypeOf(Snapshot{}), reflect.TypeOf(Record{})} {
		for i := 0; i < rt.NumField(); i++ {
			switch name := strings.ToLower(rt.Field(i).Name); {
			case strings.Contains(name, "address"), strings.Contains(name, "addr"),
				strings.Contains(name, "ip"):
				t.Errorf("%s.%s: the snapshot must not have a field for an address",
					rt.Name(), rt.Field(i).Name)
			}
		}
	}
}

// TestSnapshotHasNoFieldForTheScopeOrTheTargetList. The scan parameters now
// travel on the report, and one of them - the target specification - is a fact
// about the customer, not about us: a /16 says how their estate is laid out,
// and a -targets-file path under ~/assessments/ names the client in the path
// itself. The snapshot is the one artifact designed to leave the operator's
// machine and be published as an aggregate (P9), so the whole ScanParams
// struct must never be copied into it wholesale, however convenient that is.
//
// Asserted by value and structurally, the same way the label and the vantage
// are: a value test catches a copy, a structural test catches a field added by
// someone who then has nowhere to put it.
func TestSnapshotHasNoFieldForTheScopeOrTheTargetList(t *testing.T) {
	start := time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC)
	r := domain.NewResult(domain.Run{
		Start: start, End: start.Add(time.Second),
		Requested: 254, Hosts: respondedHosts(3),
		Params: &domain.ScanParams{
			ProbeTimeout: "4s",
			Concurrency:  32,
			Ports:        []int{8265, 8888},
			CIDR:         []string{"10.11.12.0/24"},
			TargetsFile:  "/home/op/assessments/acme-corp/hosts.txt",
			NamedTargets: 2,
		},
	})

	snap, err := Build(r, time.Now())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	b, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, leak := range []string{"10.11.12.0/24", "acme-corp", "hosts.txt", "assessments"} {
		if strings.Contains(string(b), leak) {
			t.Errorf("P9 VIOLATION: the snapshot carries %q from the scan parameters", leak)
		}
	}

	// The timeout, by contrast, is deliberately present: without it the index
	// would pool "silent" hosts measured at different sensitivities.
	if snap.ProbeTimeout != "4s" {
		t.Errorf("ProbeTimeout = %q, want \"4s\": the index cannot compare exposure rates "+
			"across snapshots without knowing how long a host was given to answer", snap.ProbeTimeout)
	}

	rt := reflect.TypeOf(Snapshot{})
	for i := 0; i < rt.NumField(); i++ {
		switch name := strings.ToLower(rt.Field(i).Name); {
		case strings.Contains(name, "cidr"),
			strings.Contains(name, "target") && !strings.Contains(name, "targetsscanned"),
			strings.Contains(name, "scope"),
			strings.Contains(name, "params"),
			strings.Contains(name, "file"):
			t.Errorf("Snapshot.%s: the snapshot must not have a field for the scope, "+
				"the target list, or the parameters as a whole", rt.Field(i).Name)
		}
	}
}

// TestSnapshotOfAResultWithNoParametersIsStillValid. Params is a pointer
// because absent is a real state - a result built by anything other than a
// scanner run has no flags to report - and the snapshot path must not panic on
// one.
func TestSnapshotOfAResultWithNoParametersIsStillValid(t *testing.T) {
	start := time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC)
	r := domain.NewScanResult(start, start.Add(time.Second), respondedHosts(2), nil)
	if r.Params != nil {
		t.Fatal("NewScanResult set Params; this test no longer covers the nil case")
	}
	snap, err := Build(r, time.Now())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if snap.ProbeTimeout != "" {
		t.Errorf("ProbeTimeout = %q, want empty: inventing a default would report a "+
			"measurement setting that was never used", snap.ProbeTimeout)
	}
}

// TestSnapshotCarriesNoRespondedHostIdentity guards the route opened by
// domain.ScanResult.Responded (2026-11-05). That field exists so the report can
// name the hosts that answered cleanly, which is the one list on a result made
// entirely of hostnames that raise no finding - so copying it here would
// publish a customer's inventory while looking like a coverage improvement,
// and the existing structural guard does not cover it: it bars fields named
// for the scope, the target list and the parameters, none of which match
// "Responded".
//
// Both halves, as with the scope guard: by value, and structurally so a future
// field cannot reintroduce it. HostID stays the one identity in a snapshot,
// and it is a salted hash.
func TestSnapshotCarriesNoRespondedHostIdentity(t *testing.T) {
	start := time.Date(2026, 11, 5, 9, 0, 0, 0, time.UTC)
	r := domain.NewResult(domain.Run{
		Start: start, End: start.Add(time.Second),
		Requested: 3, Hosts: respondedHosts(3),
	})
	if len(r.Responded) != 3 {
		t.Fatalf("Responded = %d hosts, want 3: this test is not exercising the field "+
			"it was written for", len(r.Responded))
	}

	snap, err := Build(r, time.Now())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	b, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, leak := range []string{"gpu-node", "internal.example.com", "responded\":[", "\"host\":"} {
		if strings.Contains(string(b), leak) {
			t.Errorf("P9 VIOLATION: the snapshot carries %q; the responded host list "+
				"must not travel", leak)
		}
	}

	// Structural: no field may hold host identity. The counts are fine - they
	// are what the index is for - so an integer field named for hosts passes
	// and a list of them does not.
	rt := reflect.TypeOf(Snapshot{})
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		name := strings.ToLower(f.Name)
		identityish := strings.Contains(name, "host") ||
			strings.Contains(name, "responded") ||
			strings.Contains(name, "unreachable") ||
			strings.Contains(name, "address")
		if !identityish {
			continue
		}
		switch f.Type.Kind() {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
			reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			// A count. This is the whole point of the index.
		default:
			t.Errorf("Snapshot.%s is %s, not a count: a snapshot may carry how many "+
				"hosts did something, never which ones", f.Name, f.Type)
		}
	}
}
