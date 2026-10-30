package scan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"gpusecurity/internal/domain"
)

// The corpus is the shared truth for the differential test between the two
// implementations of the L1 rule set.
//
// Structural parity (rule_parity_test.go) proves the Go and Rego sides agree
// on IDs, severities and remediation text. That is not the same as agreeing on
// BEHAVIOUR, and metadata parity with divergent behaviour is the worst of both
// worlds: a report and a credential citing the same rule ID while disagreeing
// about whether it fired.
//
// So this test generates the corpus from the Go implementation - the one that
// ships and that customers' reports come from - and CI replays it through OPA
// (policies/tools/differential.py). The Go side is the reference because it is
// the side with real traffic behind it.
const corpusPath = "../../policies/testdata/corpus.json"

// corpusCase is one observation plus the rule IDs the shipping scanner raises
// for it. `input` is what a Rego rule sees, which is the observation joined
// with its host's state.
type corpusCase struct {
	Name   string          `json:"name"`
	Why    string          `json:"why,omitempty"`
	Input  json.RawMessage `json:"input"`
	Expect []string        `json:"expect_findings"`
}

// observationInput is domain.Observation plus host_state, which no Go code
// needs but every verification sentinel does.
type observationInput struct {
	domain.Observation
	HostState domain.HostState `json:"host_state"`
}

func mk(o domain.Observation, state domain.HostState) json.RawMessage {
	b, err := json.Marshal(observationInput{Observation: o, HostState: state})
	if err != nil {
		panic(err)
	}
	return b
}

func tcp(service string, port int) domain.Observation {
	return domain.Observation{
		Host: "10.0.0.5", Port: port, Service: service, State: domain.PortOpen,
		Note: "control/RPC port; speaks no HTTP",
	}
}

func http2xx(service string, port int) domain.Observation {
	return domain.Observation{
		Host: "10.0.0.5", Port: port, Service: service, State: domain.PortOpen,
		HTTPStatus: 200, Unauth: true,
	}
}

// corpus is deliberately hand-written rather than captured from a scan: the
// interesting cases are the ones a demo stack does not contain.
func corpus() []corpusCase {
	cases := []corpusCase{
		// One firing case per HTTP exposure rule.
		{Name: "ray dashboard exposed", Input: mk(http2xx("ray-dashboard", 8265), domain.HostResponded), Expect: []string{"RG-RAY-001"}},
		{Name: "vllm exposed", Input: mk(http2xx("vllm", 8000), domain.HostResponded), Expect: []string{"RG-VLLM-001"}},
		{Name: "triton exposed", Input: mk(http2xx("triton", 8000), domain.HostResponded), Expect: []string{"RG-TRITON-001"}},
		{Name: "triton metrics exposed", Input: mk(http2xx("triton-metrics", 8002), domain.HostResponded), Expect: []string{"RG-TRITON-002"}},
		{Name: "mlflow exposed", Input: mk(http2xx("mlflow", 5000), domain.HostResponded), Expect: []string{"RG-MLFLOW-001"}},
		{Name: "jupyter exposed", Input: mk(http2xx("jupyter", 8888), domain.HostResponded), Expect: []string{"RG-JUPYTER-001"}},
		{Name: "ollama exposed", Input: mk(http2xx("ollama", 11434), domain.HostResponded), Expect: []string{"RG-OLLAMA-001"}},
		{Name: "torchserve management exposed", Input: mk(http2xx("torchserve-mgmt", 8081), domain.HostResponded), Expect: []string{"RG-TORCHSERVE-001"}},
		{Name: "torchserve metrics exposed", Input: mk(http2xx("torchserve-metrics", 8082), domain.HostResponded), Expect: []string{"RG-TORCHSERVE-002"}},
		{Name: "sglang exposed", Input: mk(http2xx("sglang", 30000), domain.HostResponded), Expect: []string{"RG-SGLANG-001"}},
		{Name: "dcgm exporter exposed", Input: mk(http2xx("dcgm-exporter", 9400), domain.HostResponded), Expect: []string{"RG-DCGM-001"}},

		// Reachability-only rules: open, no HTTP.
		{Name: "ray client port reachable", Input: mk(tcp("ray-client", 10001), domain.HostResponded), Expect: []string{"RG-RAY-002"}},
		{Name: "triton grpc reachable", Input: mk(tcp("triton-grpc", 8001), domain.HostResponded), Expect: []string{"RG-TRITON-003"}},
		{Name: "slurmctld reachable", Input: mk(tcp("slurmctld", 6817), domain.HostResponded), Expect: []string{"RG-SLURM-001"}},

		// Unidentified port, including the wildcard case the scanner refuses
		// to attribute.
		{
			Name: "unidentified open port",
			Why:  "reported at Info and never guessed at",
			Input: mk(domain.Observation{
				Host: "10.0.0.5", Port: 8080, Service: ServiceUnknown, State: domain.PortOpen,
				Note: "port open, no HTTP response",
			}, domain.HostResponded),
			Expect: []string{"RG-EXPOSURE-001"},
		},
		{
			Name: "wildcard server that answers 2xx on any path",
			Why:  "must be Info, never the orchestrator that shares the port",
			Input: mk(domain.Observation{
				Host: "10.0.0.5", Port: 8265, Service: ServiceUnknown, State: domain.PortOpen,
				HTTPStatus: 200, Unauth: true,
				Note: "answers 2xx on any path, including one that cannot exist; no service could be identified",
			}, domain.HostResponded),
			Expect: []string{"RG-EXPOSURE-001"},
		},

		// Transport posture.
		{
			Name: "self-signed certificate",
			Input: mk(domain.Observation{
				Host: "10.0.0.5", Port: 8265, Service: ServiceTLS, State: domain.PortOpen,
				TLS: domain.TLSState{Enabled: true, Issue: "self-signed", NotAfter: "2027-01-01", Version: "1.3"},
			}, domain.HostResponded),
			Expect: []string{"RG-TLS-001"},
		},
		{
			Name: "obsolete TLS with a bad certificate raises BOTH",
			Why:  "separate fixes, and they travel together in the field",
			Input: mk(domain.Observation{
				Host: "10.0.0.5", Port: 8265, Service: ServiceTLS, State: domain.PortOpen,
				TLS: domain.TLSState{Enabled: true, Issue: "self-signed", Version: "1.0"},
			}, domain.HostResponded),
			Expect: []string{"RG-TLS-001", "RG-TLS-003"},
		},
		{
			Name: "obsolete TLS with a valid certificate",
			Input: mk(domain.Observation{
				Host: "10.0.0.5", Port: 8265, Service: ServiceTLS, State: domain.PortOpen,
				TLS: domain.TLSState{Enabled: true, Version: "1.1"},
			}, domain.HostResponded),
			Expect: []string{"RG-TLS-003"},
		},
		{
			Name: "clean TLS raises nothing",
			Input: mk(domain.Observation{
				Host: "10.0.0.5", Port: 8265, Service: ServiceTLS, State: domain.PortOpen,
				TLS: domain.TLSState{Enabled: true, Version: "1.3"},
			}, domain.HostResponded),
			Expect: nil,
		},
		{
			Name: "authenticated service over plaintext",
			Why:  "the good-news case that is still a finding: credentials in the clear",
			Input: mk(domain.Observation{
				Host: "10.0.0.5", Port: 8000, Service: "vllm", State: domain.PortOpen,
				HTTPStatus: 401, Note: "reachable but requires auth",
			}, domain.HostResponded),
			Expect: []string{"RG-TLS-002"},
		},
		{
			Name: "authenticated service over TLS raises nothing",
			Input: mk(domain.Observation{
				Host: "10.0.0.5", Port: 8000, Service: "vllm", State: domain.PortOpen,
				HTTPStatus: 403, TLS: domain.TLSState{Enabled: true, Version: "1.3"},
				Note: "reachable but requires auth",
			}, domain.HostResponded),
			Expect: nil,
		},

		// Buckets.
		{
			Name: "public bucket listing",
			Input: mk(domain.Observation{
				Host: "bucket.s3.amazonaws.com", Service: ServiceBucket, State: domain.PortOpen,
				HTTPStatus: 200, Unauth: true, TLS: domain.TLSState{Enabled: true},
			}, domain.HostResponded),
			Expect: []string{"RG-BUCKET-001"},
		},
		{
			Name: "restricted bucket raises nothing",
			Input: mk(domain.Observation{
				Host: "bucket.s3.amazonaws.com", Service: ServiceBucket, State: domain.PortOpen,
				HTTPStatus: 403, TLS: domain.TLSState{Enabled: true}, Note: "listing not public",
			}, domain.HostResponded),
			Expect: nil,
		},

		// Negative controls: the real demo stack's two quiet hosts.
		{
			Name: "token-protected TorchServe management API",
			Why:  "answers 400, so it is reported as unidentified rather than named - the real .42 host",
			Input: mk(domain.Observation{
				Host: "10.0.0.42", Port: 8081, Service: ServiceUnknown, State: domain.PortOpen,
				HTTPStatus: 400,
			}, domain.HostResponded),
			Expect: []string{"RG-EXPOSURE-001"},
		},
		{
			Name: "service that authenticates every path, over TLS",
			Input: mk(domain.Observation{
				Host: "10.0.0.40", Port: 8000, Service: "triton", State: domain.PortOpen,
				HTTPStatus: 401, TLS: domain.TLSState{Enabled: true, Version: "1.2"},
			}, domain.HostResponded),
			Expect: nil,
		},
	}
	return cases
}

// TestRegoCorpusIsCurrent regenerates the corpus from the shipping detector
// and fails if the checked-in file has drifted. Set RAY_GUARD_UPDATE_CORPUS=1
// to accept a deliberate change.
func TestRegoCorpusIsCurrent(t *testing.T) {
	cases := corpus()

	// Fill Expect from the shipping implementation rather than trusting what
	// is written above: the corpus records what the scanner DOES.
	for i := range cases {
		var o observationInput
		if err := json.Unmarshal(cases[i].Input, &o); err != nil {
			t.Fatalf("%s: corpus input is not an observation: %v", cases[i].Name, err)
		}
		var got []string
		for _, f := range Detect([]domain.Observation{o.Observation}) {
			got = append(got, f.RuleID)
		}
		sort.Strings(got)
		want := append([]string(nil), cases[i].Expect...)
		sort.Strings(want)
		if len(got) != len(want) {
			t.Errorf("%s: scanner raises %v, corpus says %v", cases[i].Name, got, want)
			continue
		}
		for j := range got {
			if got[j] != want[j] {
				t.Errorf("%s: scanner raises %v, corpus says %v", cases[i].Name, got, want)
				break
			}
		}
		cases[i].Expect = got
	}

	// Every rule must appear in at least one firing case, so a new rule
	// cannot be added without a differential case to go with it.
	covered := map[string]bool{}
	for _, c := range cases {
		for _, id := range c.Expect {
			covered[id] = true
		}
	}
	for id := range goRules() {
		if !covered[id] {
			t.Errorf("%s has no firing case in the Rego differential corpus; add one "+
				"so the two implementations are compared on it", id)
		}
	}

	out, err := json.MarshalIndent(struct {
		Comment string       `json:"_comment"`
		Cases   []corpusCase `json:"cases"`
	}{
		Comment: "Generated by internal/scan/rego_corpus_test.go from the shipping Go " +
			"detector. Replayed through OPA by policies/tools/differential.py in CI. " +
			"Do not hand-edit: run `go test ./internal/scan` with RAY_GUARD_UPDATE_CORPUS=1.",
		Cases: cases,
	}, "", "  ")
	if err != nil {
		t.Fatalf("marshalling corpus: %v", err)
	}
	out = append(out, '\n')

	existing, readErr := os.ReadFile(corpusPath)
	if os.Getenv("RAY_GUARD_UPDATE_CORPUS") == "1" {
		if err := os.MkdirAll(filepath.Dir(corpusPath), 0o755); err != nil {
			t.Fatalf("creating testdata dir: %v", err)
		}
		if err := os.WriteFile(corpusPath, out, 0o644); err != nil { // #nosec G306 -- test fixture, no secrets
			t.Fatalf("writing corpus: %v", err)
		}
		t.Logf("corpus updated: %d cases", len(cases))
		return
	}
	if readErr != nil {
		t.Fatalf("%s is missing; regenerate with RAY_GUARD_UPDATE_CORPUS=1", corpusPath)
	}
	if string(existing) != string(out) {
		t.Errorf("%s is stale. The shipping detector and the checked-in corpus disagree, "+
			"which means the Rego differential test is comparing against yesterday's "+
			"behaviour. Regenerate with RAY_GUARD_UPDATE_CORPUS=1 and review the diff.",
			corpusPath)
	}
}
