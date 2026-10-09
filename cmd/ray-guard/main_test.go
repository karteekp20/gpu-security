package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
