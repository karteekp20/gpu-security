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
| `tls.issue` | `""` `self-signed` `expired` `not-yet-valid` `hostname-mismatch` `untrusted` | Failure class only — never subject, issuer, serial or chain bytes (P3). `untrusted` is the scanner's fallback for a verification error outside the four named classes; rules test `issue != ""`, so it fires and never closes |
| `host_state` | `responded` `no-response` `unresolved` `probe-failed` | **Only `responded` permits a closure** |

Nothing in this contract can carry customer payload. That is enforced on the
Go side by `test/metadata_only_test.go`, which is why the rules reason over
status codes and transport posture and never over response content.

## How the control plane builds the verification input

A rule evaluates one observation, but **a fixed port produces no observation
at all** — the scanner stops at the TCP state and never probes it. So the
control plane synthesizes the verification input: for each open finding it
looks up that `host:port` in the newest scan and, when nothing was observed
there, builds

```json
{ "service": "<the finding's service>", "state": "closed" | "filtered",
  "http_status": 0, "tls": {"enabled": false}, "host_state": "<from the scan>" }
```

carrying the service forward from the finding. That is why every
`verification_condition` also binds its own service: a sentinel may only speak
about observations it applies to. Before that scoping existed, a Ray
observation returning 401 satisfied `RG-BUCKET-001`'s closure — "the
unauthenticated request was refused" is true of it and completely irrelevant.

## Running it

```bash
make test            # structural: both halves present, metadata parses, a
                     # test per rule, a dark-host case per rule, no drift
                     # from detect.go, state vocabulary pinned to the
                     # scanner's enums, both corpora current. No opa needed.
make test-policies   # semantic: opa check --strict, opa test, and the
                     # differential over both corpora. Needs opa.
```

Three gates, and they check different things:

| Gate | Proves | Where |
| :-- | :-- | :-- |
| `rule_parity_test.go` | the two sides agree on IDs, severities, remediation text, CVEs; every rule has both halves and a test; every state string the rules compare against is one the scanner emits | Go suite |
| `opa test` | the rules mean what their own tests say | `policy` job |
| `differential.py` → `corpus.json` | the rules **fire** on exactly what the shipping scanner fires on | `policy` job |
| `differential.py` → `closures.json` | every sentinel **closes** only on evidence, and closes when the evidence is there | `policy` job |

The differential is the gate that is easy to skip and expensive to omit:
metadata parity with divergent behaviour is the worst of both worlds, a report
and a credential citing the same rule ID while disagreeing about whether it
fired. It runs over two corpora, one per half of every sentinel.

`testdata/corpus.json` — the **finding** half. Generated from the Go detector,
because that is the side with real traffic behind it. `make test` fails if it
goes stale, and a new rule with no firing case also fails, so a rule cannot be
added without being compared.

`testdata/closures.json` — the **closure** half. Go has no closure
implementation to compare against (closures exist only here, and only the
control plane evaluates them), so its expectations come from two places that
are not the rules themselves: the state *vocabulary* is generated from
`internal/domain`, and the *scope* is each rule's own declared service. Its
negative cases need no per-rule knowledge at all, which is why they are the
stronger half — on a host the scan never reached, **nothing** may close,
whatever else the observation says.

That corpus exists because of a measured hole. Renaming
`domain.HostResponded`'s value left the entire Go suite green, regenerated
`corpus.json` cleanly, and kept the finding differential at 26/26 — no
`finding_condition` reads `host_state`, only closures do. All 19 sentinels
would have become permanently unsatisfiable: no finding would ever auto-close,
and every gate would have reported healthy.

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
