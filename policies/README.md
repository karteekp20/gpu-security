# policies/ — the Rego rule library

The L1 rule set as policy-as-code (CLAUDE.md §8). 19 rules, each with a
**verification sentinel**: not just a predicate that raises a finding, but a
deterministic predicate that proves the fix landed, so a finding can be
auto-closed *by us* rather than on a customer's word. That is what makes the
signed trust credential worth signing.

```
policies/
├── lib/evidence.rego          shared closure predicates (read this first)
├── orchestrator/              15 rules: Ray, vLLM, Triton, TorchServe,
│                              SGLang, Slurm, Jupyter, MLflow, Ollama,
│                              DCGM, unidentified ports
└── cloud/                     4 rules: TLS posture, public buckets
```

`fabric/`, `hardware/`, `attestation/` and `k8s/` are empty by design — those
rules need L2/L3 evidence that does not exist yet (CLAUDE.md §3).

## The rule this library is built around

**A verification sentinel must never be satisfiable by absence of evidence.**

The obvious closure for an exposure finding is "the port no longer answers".
That predicate is also satisfied by a host that was never reached: an
unresolvable name, a dark subnet, a scan run from the wrong side of a
firewall, a run that was interrupted. The scanner already refuses to grade
such a scan clean — a scan that reaches nothing grades `N/A`, never `A+`
(`docs/decision-log.md`, 2026-09-25). Here the same hazard is strictly worse,
because a closure feeds the credential: it would turn *"we could not look"*
into *"we attest it is fixed"*, cryptographically, over our name.

So every closure predicate in `lib/evidence.rego` requires `host_reached`
first, and **every rule's test file contains a case proving an unreached host
does not close the finding.** That case is mandatory — `make test` fails a
rule whose tests omit it.

## Input contract

A rule evaluates one observation, joined with the state of the host it came
from. The field names are `internal/domain.Observation`'s JSON tags plus
`host_state` from the host summary; the collector does the join.

```json
{
  "host": "10.0.0.5",
  "port": 8265,
  "service": "ray-dashboard",
  "state": "open",
  "http_status": 200,
  "unauth": true,
  "note": "",
  "tls": { "enabled": false, "issue": "", "not_after": "", "version": "" },
  "host_state": "responded"
}
```

| Field | Values | Meaning |
| :-- | :-- | :-- |
| `service` | see `lib.known_services`, plus `tls`, `bucket`, `unknown` | What the probe identified, or `unknown` — never guessed |
| `state` | `open` `closed` `filtered` | `closed` is a TCP RST (the host answered); `filtered` is silence |
| `http_status` | `0` or an HTTP code | `0` means no HTTP response to reason about |
| `unauth` | bool | The service answered 2xx without asking for credentials |
| `tls.issue` | `""` `self-signed` `expired` `not-yet-valid` `hostname-mismatch` | Failure class only — never subject, issuer, serial or chain bytes (P3) |
| `host_state` | `responded` `no-response` `unresolved` `probe-failed` | **Only `responded` permits a closure** |

Nothing in this contract can carry customer payload. That is enforced on the
Go side by `test/metadata_only_test.go`, which is why the rules reason over
status codes and transport posture and never over response content.

## Running it

```bash
make test            # structural: both halves present, metadata parses,
                     # a test per rule, no drift from detect.go. No opa needed.
make test-policies   # semantic: opa check --strict + opa test. Needs opa.
```

Both run in CI — the structural half inside the Go suite, the semantic half in
the `policy` job with OPA pinned to 1.22.0.

## Why the rules exist twice

`internal/scan/detect.go` is the Go implementation that ships inside the
static binary; this library is what the Phase-1 control plane evaluates. OPA
cannot go into the binary without costing the zero-dependency, air-gap
property that makes `ray-guard` handable to a security lead (CLAUDE.md §15,
P4), so the duplication is deliberate.

Duplication drifts, though, and the drift would be invisible until a
customer's report and their credential disagreed about a severity. So
`internal/scan/rule_parity_test.go` fails the build if the two sides disagree
on any rule ID, title, severity, remediation string or CVE list — and if
`lib.known_services` falls out of step with the scanner's service table. All
three mutations were checked by hand: drift a severity, delete a sentinel,
remove a dark-host test. Each turns the suite red.

## Conventions

- **Rego v1 syntax** (`import rego.v1`, `if` before every rule body). The §8
  worked example predates OPA 1.0; current OPA requires this form, so the
  library uses it and the skill's template should be read as pseudocode.
- `RG-<DOMAIN>-NNN` IDs are stable and never reused.
- `finding_metadata` is written as strict JSON inside the braces so the parity
  test can read it without an OPA dependency.
- Compliance mappings are **first-pass**. SOC 2 and ISO 27001 are the honest
  anchors (CLAUDE.md §11); they have not been reviewed by an auditor, and a
  buyer should be told that rather than shown a control number and left to
  assume.
- The library will be semver'd and shipped as a signed air-gap bundle
  (CLAUDE.md §13). Not built yet; `make airgap-bundle` says so.
