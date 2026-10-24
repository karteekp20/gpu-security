package main

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"gpusecurity/internal/domain"
	"gpusecurity/internal/scan"
)

// TestEnsureWritableCreatesNestedDir covers the ordinary case: -out names a
// directory that does not exist yet.
func TestEnsureWritableCreatesNestedDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "assessments", "client-2026-10-10")
	if err := ensureWritable(dir); err != nil {
		t.Fatalf("ensureWritable(%q) = %v, want nil", dir, err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("created %v, want 0700: a report names a client's exposed services", perm)
	}
}

// TestEnsureWritableLeavesNothingBehind: the check must not leave its probe
// file in a directory an operator is about to hand to a client.
func TestEnsureWritableLeavesNothingBehind(t *testing.T) {
	dir := t.TempDir()
	if err := ensureWritable(dir); err != nil {
		t.Fatalf("ensureWritable: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("left %d file(s) behind: %v", len(entries), entries)
	}
}

// TestEnsureWritableRejectsUnwritableParent is the case that matters: it must
// fail BEFORE a scan runs, not after one has been thrown away.
func TestEnsureWritableRejectsUnwritableParent(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root; permission bits do not apply")
	}
	parent := filepath.Join(t.TempDir(), "readonly")
	if err := os.Mkdir(parent, 0o500); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	err := ensureWritable(filepath.Join(parent, "report"))
	if err == nil {
		t.Fatal("ensureWritable succeeded under a read-only parent, want an error")
	}
	if !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("error was %q, want it to name the permission problem", err)
	}
}

// TestEnsureWritableRejectsAFileAsDir guards the `-out ./report.html` typo,
// where the operator names a file where a directory is expected.
func TestEnsureWritableRejectsAFileAsDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.html")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("writefile: %v", err)
	}
	if err := ensureWritable(path); err == nil {
		t.Error("ensureWritable accepted a regular file as -out, want an error")
	}
}

// -----------------------------------------------------------------------------
// Interruption
//
// Ctrl-C has to do two things: stop probing a customer's network promptly, and
// leave behind a report that describes only what was actually looked at.
// -----------------------------------------------------------------------------

// TestProbeAllRecordsNothingItAbandoned is the honesty case. A probe killed
// mid-flight reports "no response" - and the resolver fails on a dead context
// too, which reports "unresolved". Either one would put a host on a customer's
// report as unreachable when the only thing that happened is that we stopped.
func TestProbeAllRecordsNothingItAbandoned(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	scanner := scan.New(50 * time.Millisecond)
	obs, hosts, interrupted := probeAll(ctx, scanner,
		[]string{"127.0.0.1", "localhost"}, []string{"https://example.invalid/bucket"}, 4)

	if !interrupted {
		t.Error("interrupted = false after scanning under a cancelled context")
	}
	if len(hosts) != 0 {
		t.Errorf("recorded %d host(s) that were never really probed: %+v", len(hosts), hosts)
	}
	if len(obs) != 0 {
		t.Errorf("recorded %d observation(s) from abandoned probes", len(obs))
	}
}

// TestProbeAllStopsDispatchingOnInterrupt: the remaining targets must not be
// dialed at all. Finishing the sweep after a Ctrl-C is the behaviour that
// breaks an authorization window - the operator said stop.
func TestProbeAllStopsDispatchingOnInterrupt(t *testing.T) {
	var dialed int64
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt64(&dialed, 1)
			// Stand in for the operator's Ctrl-C, landing deterministically
			// while the first target is being probed.
			cancel()
			w.WriteHeader(http.StatusOK)
		}),
		ReadHeaderTimeout: time.Second,
	}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()

	port := ln.Addr().(*net.TCPAddr).Port
	scanner := scan.NewWithChecks(2*time.Second, []scan.Check{{Service: "ray-dashboard", Port: port, Scheme: "http", Path: "/"}})

	// concurrency 1 serializes dispatch, so "the first target is probed and
	// the rest are not" is a deterministic assertion rather than a race.
	_, hosts, interrupted := probeAll(ctx, scanner,
		[]string{"127.0.0.1", "127.0.0.2", "127.0.0.3", "127.0.0.4"}, nil, 1)

	if !interrupted {
		t.Fatal("interrupted = false although the scan was cancelled mid-flight")
	}
	if len(hosts) != 1 {
		t.Errorf("recorded %d host(s), want 1: dispatch continued past the interrupt (%+v)", len(hosts), hosts)
	}
	if len(hosts) == 1 && hosts[0].Host != "127.0.0.1" {
		t.Errorf("recorded %q, want the one target that was actually probed", hosts[0].Host)
	}
	if n := atomic.LoadInt64(&dialed); n != 1 {
		t.Errorf("the probe ran %d times after the interrupt, want 1", n)
	}
}

// TestProbeAllCompletesNormally: the interrupt plumbing must not change the
// ordinary path. A loopback host refuses the connection, which is an answer.
func TestProbeAllCompletesNormally(t *testing.T) {
	scanner := scan.NewWithChecks(2*time.Second,
		[]scan.Check{{Service: "ray-dashboard", Port: 59231, Scheme: "http", Path: "/"}})
	_, hosts, interrupted := probeAll(context.Background(), scanner, []string{"127.0.0.1"}, nil, 4)
	if interrupted {
		t.Error("interrupted = true on a scan nobody interrupted")
	}
	if len(hosts) != 1 || hosts[0].State != domain.HostResponded {
		t.Errorf("hosts = %+v, want one responded host (a refused port is an answer)", hosts)
	}
}
