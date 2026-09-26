// Package test holds the metadata-only enforcement suite (CLAUDE.md P3).
//
// P3 is the guarantee the product is sold on: we never read, store, or
// transmit customer model weights, prompts, training data, inference
// payloads, or object contents. A single violation is existential, so the
// guarantee is enforced here as a build-blocking test rather than as a
// convention in code comments.
//
// These tests approach it from two directions:
//
//  1. Structurally - no type that crosses the collection boundary may grow a
//     field capable of carrying payload. This catches the problem at the
//     moment someone adds the field.
//  2. Behaviourally - scan a server that serves a recognizable sentinel
//     payload, then assert the sentinel appears in none of our outputs.
//
// When you add a field to a collector, parser, or output type, add a case
// here. If you cannot tell whether a value is metadata or payload, it is
// payload.
package test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"gpusecurity/internal/benchmark"
	"gpusecurity/internal/domain"
	"gpusecurity/internal/report"
	"gpusecurity/internal/scan"
)

// -----------------------------------------------------------------------------
// 1. Structural guard
// -----------------------------------------------------------------------------

// forbiddenFieldNames are substrings that indicate a field is carrying
// content rather than metadata. Matching is case-insensitive.
var forbiddenFieldNames = []string{
	"body", "payload", "content", "prompt", "weight", "dataset",
	"objectkey", "keys", "secret", "token", "credential", "response",
}

// TestBoundaryTypesCannotCarryPayload walks every type that crosses the
// collection boundary and fails if a field could hold customer content.
func TestBoundaryTypesCannotCarryPayload(t *testing.T) {
	types := []any{
		domain.Observation{},
		domain.Finding{},
		domain.ScanResult{},
		domain.TLSState{},
		benchmark.Snapshot{},
		benchmark.Record{},
	}
	for _, v := range types {
		rt := reflect.TypeOf(v)
		t.Run(rt.Name(), func(t *testing.T) {
			assertNoPayloadFields(t, rt, rt.Name(), map[reflect.Type]bool{})
		})
	}
}

func assertNoPayloadFields(t *testing.T, rt reflect.Type, path string, seen map[reflect.Type]bool) {
	t.Helper()
	if seen[rt] {
		return
	}
	seen[rt] = true

	switch rt.Kind() {
	case reflect.Ptr, reflect.Slice, reflect.Array:
		if rt.Kind() == reflect.Slice && rt.Elem().Kind() == reflect.Uint8 {
			t.Errorf("%s is a []byte: raw bytes are how payload enters a system", path)
			return
		}
		assertNoPayloadFields(t, rt.Elem(), path+"[]", seen)
		return
	case reflect.Map:
		assertNoPayloadFields(t, rt.Elem(), path+"{}", seen)
		return
	case reflect.Interface:
		t.Errorf("%s is an interface: it can carry anything, including payload", path)
		return
	case reflect.Chan, reflect.Func, reflect.UnsafePointer:
		t.Errorf("%s has kind %s, which has no place in a boundary type", path, rt.Kind())
		return
	case reflect.Struct:
	default:
		return
	}

	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		fieldPath := path + "." + f.Name
		lower := strings.ToLower(f.Name)
		for _, bad := range forbiddenFieldNames {
			if strings.Contains(lower, bad) {
				t.Errorf("%s: field name contains %q, which suggests it carries content rather than metadata (P3)", fieldPath, bad)
			}
		}
		assertNoPayloadFields(t, f.Type, fieldPath, seen)
	}
}

// -----------------------------------------------------------------------------
// 2. Behavioural guard: end-to-end sentinel
// -----------------------------------------------------------------------------

// sentinels stand in for the things we promise never to touch. Each is
// distinctive enough that a substring match is conclusive.
var sentinels = map[string]string{
	"inference output": "SENTINEL_INFERENCE_OUTPUT_9c1f",
	"prompt text":      "SENTINEL_USER_PROMPT_4a77",
	"model weights":    "SENTINEL_MODEL_WEIGHTS_be02",
	"object key":       "SENTINEL_BUCKET_OBJECT_KEY_d310",
	"response header":  "SENTINEL_HEADER_VALUE_77ab",
}

// payloadServer answers like a chatty, unauthenticated AI service: every
// response body and several headers are stuffed with sentinel content.
func payloadServer(t *testing.T) (host string, port int) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Model-Name", sentinels["response header"])
		w.Header().Set("Server", sentinels["response header"])
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"prompt":%q,"completion":%q,"weights":%q,"keys":[%q]}`,
			sentinels["prompt text"], sentinels["inference output"],
			sentinels["model weights"], sentinels["object key"])
		// Follow with a large body so a naive implementation that buffers
		// "just a bit more" is caught too.
		_, _ = io.WriteString(w, strings.Repeat(sentinels["inference output"], 4096))
	}))
	t.Cleanup(srv.Close)
	h, p, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("splitting server address: %v", err)
	}
	n, _ := strconv.Atoi(p)
	return h, n
}

// TestNoPayloadReachesAnyOutput is the core P3 test: scan a server that
// serves payload, then assert none of it appears in anything we emit.
func TestNoPayloadReachesAnyOutput(t *testing.T) {
	host, port := payloadServer(t)

	scanner := scan.NewWithChecks(3*time.Second, []scan.Check{
		{Service: "ray-dashboard", Port: port, Scheme: "http", Path: "/"},
		{Service: "vllm", Port: port, Scheme: "http", Path: "/v1/models"},
	})
	hostScan := scanner.ProbeHost(context.Background(), host)
	obs := hostScan.Observations
	if len(obs) == 0 {
		t.Fatal("precondition failed: the scan found nothing, so this test would pass vacuously")
	}
	findings := scan.Detect(obs)
	if len(findings) == 0 {
		t.Fatal("precondition failed: no findings, so this test would pass vacuously")
	}
	result := domain.NewScanResult(time.Now().Add(-time.Second), time.Now(),
		[]domain.HostSummary{hostScan.Summary()}, findings)

	dir := t.TempDir()
	if err := report.Write(dir, result); err != nil {
		t.Fatalf("writing report: %v", err)
	}
	snapshotPath := filepath.Join(dir, "snapshot.json")
	if err := benchmark.Write(snapshotPath, result, time.Now()); err != nil {
		t.Fatalf("writing snapshot: %v", err)
	}
	var terminal bytes.Buffer
	report.PrintSummary(&terminal, result)

	outputs := map[string][]byte{
		"report.json":   mustRead(t, filepath.Join(dir, "report.json")),
		"report.html":   mustRead(t, filepath.Join(dir, "report.html")),
		"snapshot.json": mustRead(t, snapshotPath),
		"terminal":      terminal.Bytes(),
		// The in-memory structures themselves, not just the serialized form.
		"observations": []byte(fmt.Sprintf("%#v", obs)),
		"findings":     []byte(fmt.Sprintf("%#v", findings)),
	}

	for name, out := range outputs {
		for kind, sentinel := range sentinels {
			if bytes.Contains(out, []byte(sentinel)) {
				t.Errorf("P3 VIOLATION: %s contains %s from the scanned service", name, kind)
			}
		}
	}
}

// TestBucketProbeNeverReadsObjectKeys covers the object-storage path, where
// the temptation to parse the listing to "enrich" the finding is strongest.
// Object keys are customer data; the status code alone proves public access.
func TestBucketProbeNeverReadsObjectKeys(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `<ListBucketResult><Contents><Key>%s</Key></Contents></ListBucketResult>`,
			sentinels["object key"])
	}))
	defer srv.Close()

	scanner := scan.New(3 * time.Second)
	obs, err := scanner.ProbeBucket(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("bucket probe: %v", err)
	}
	if !obs.Unauth {
		t.Fatal("precondition failed: the public bucket was not detected")
	}
	findings := scan.Detect([]domain.Observation{obs})
	if len(findings) != 1 {
		t.Fatalf("expected one bucket finding, got %d", len(findings))
	}
	rendered := fmt.Sprintf("%#v%#v", obs, findings)
	if strings.Contains(rendered, sentinels["object key"]) {
		t.Error("P3 VIOLATION: a bucket object key reached the finding")
	}
}

// -----------------------------------------------------------------------------
// 3. Request-shape guard
// -----------------------------------------------------------------------------

// TestProbesAreBenignAndReadOnly asserts the scanner only ever issues GET
// requests with no body. Anything else is a step toward exploitation, and
// detection-by-exploitation is prohibited.
func TestProbesAreBenignAndReadOnly(t *testing.T) {
	var mu sync.Mutex
	var methods []string
	var bodySizes []int64

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		mu.Lock()
		methods = append(methods, r.Method)
		bodySizes = append(bodySizes, n)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	host, portStr, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	scanner := scan.NewWithChecks(3*time.Second, []scan.Check{
		{Service: "ray-dashboard", Port: port, Scheme: "http", Path: "/"},
		{Service: "jupyter", Port: port, Scheme: "http", Path: "/api"},
	})
	scanner.ProbeHost(context.Background(), host)
	if _, err := scanner.ProbeBucket(context.Background(), srv.URL); err != nil {
		t.Fatalf("bucket probe: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(methods) == 0 {
		t.Fatal("precondition failed: the server received no requests")
	}
	for i, m := range methods {
		if m != http.MethodGet {
			t.Errorf("request %d used %s; probes must be GET only", i, m)
		}
		if bodySizes[i] != 0 {
			t.Errorf("request %d carried a %d-byte body; probes must send nothing", i, bodySizes[i])
		}
	}
}

// TestDefaultProbePathsAreBenign guards the probe table itself. A path that
// takes parameters, traverses directories, or names an execution endpoint is
// how a posture scanner turns into an exploit tool.
func TestDefaultProbePathsAreBenign(t *testing.T) {
	// Known-good, side-effect-free health/info endpoints.
	allowed := map[string]bool{
		"":                 true,
		"/":                true,
		"/api":             true,
		"/api/tags":        true,
		"/metrics":         true,
		"/v1/models":       true,
		"/v2/health/ready": true,
	}
	forbiddenSubstrings := []string{
		"..", "?", "&", ";", "submit", "exec", "eval", "shell", "cmd",
		"upload", "delete", "job", "kill", "run",
	}

	for _, c := range scan.DefaultChecks() {
		if c.Scheme == "tcp" {
			if c.Path != "" {
				t.Errorf("%s: a reachability-only check must not carry a path", c.Service)
			}
			continue
		}
		if !allowed[c.Path] {
			t.Errorf("%s probes %q, which is not on the benign-path allowlist; add it deliberately or use a health endpoint",
				c.Service, c.Path)
		}
		lower := strings.ToLower(c.Path)
		for _, bad := range forbiddenSubstrings {
			if strings.Contains(lower, bad) {
				t.Errorf("%s probes %q, which contains %q: that is exploitation, not observation",
					c.Service, c.Path, bad)
			}
		}
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return b
}
