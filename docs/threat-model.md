# Threat Model — ray-guard (L1 scanner)

> **Scope:** the Phase-0 `ray-guard` scanner only. There is no control plane,
> no database, no collector, and no network egress in this repo yet; when
> those land (Phase 1), this document must be extended in the same PR that
> adds them (CLAUDE.md §12, §17).
>
> **Status:** current as of the Phase-0 scanner. **Last updated:** 2026-09-20.

## Why this document exists

CLAUDE.md P8 states that we are a security product and therefore a high-value
target, and requires a maintained threat model. There is a second reason: a
CISO deciding whether to let an unfamiliar binary touch a multi-million-dollar
cluster will ask exactly the questions below. Answering them in writing, before
being asked, is part of the low-friction guarantee that makes L1 sellable (P10).

## What ray-guard is

A single static Go binary, run by an operator from a host they control, against
hosts they are authorized to assess. It opens TCP connections, issues at most
one HTTP GET per check, and writes three local files: `report.json`,
`report.html`, and (only if asked) an anonymized benchmark snapshot.

It has **no** network egress beyond the targets the operator named. It does not
phone home, check for updates, submit telemetry, or contact any of our
infrastructure. This is a design constraint, not a configuration default
(P4) — there is no code path to disable, because there is no such code path.

## Trust boundaries

```
  operator's workstation                    customer infrastructure
  ┌──────────────────────┐                  ┌───────────────────────┐
  │ ray-guard binary     │  TCP connect     │ orchestrator services │
  │                      │ ───────────────► │ (Ray, vLLM, Triton,   │
  │                      │  1 HTTP GET      │  Jupyter, MLflow, …)  │
  │                      │ ◄─────────────── │                       │
  │  ▼ local filesystem  │  status + TLS    └───────────────────────┘
  │  report.json         │  facts only
  │  report.html         │
  │  snapshot.json       │        ═══ NO EGRESS TO US ═══
  └──────────────────────┘
```

Two boundaries matter:

1. **Target → scanner.** Data crossing inward is attacker-influenced. A
   malicious or compromised target controls its response entirely.
2. **Scanner → disk.** Whatever crosses here may later be shared with us, an
   auditor, or a prospect. It must contain no customer payload.

## Assets we protect

| Asset | Why it matters |
|---|---|
| Customer payload (weights, prompts, training data, inference content, object keys) | The P3 guarantee. A single violation is existential. |
| Target availability | We scan live clusters running expensive jobs. Disrupting one destroys trust permanently (P10). |
| Report integrity | The report is evidence used in a buying decision. |
| Release artifacts | A trojaned `ray-guard` would be run with intent against high-value infrastructure. |

## Threats and controls

### T1 — The scanner ingests customer payload (P3 violation)

*A probed service returns model output, prompts, or object listings in its
response body; the scanner stores it in a finding, a report, or a snapshot.*

**Controls.**
- Responses are drained to `io.Discard` with a bounded `CopyN`, never buffered
  into a variable, parsed, or logged (`internal/scan/probe.go`).
- Findings reason over status code, auth state, and TLS facts only.
- The bucket probe decides public-vs-private from the **status code alone** and
  never parses the listing — object keys are customer data.
- Boundary types are reflection-checked so no field capable of carrying payload
  can be added (`test/metadata_only_test.go`).
- An end-to-end sentinel test scans a server that serves payload in bodies and
  headers, then asserts none of it appears in any output or in the in-memory
  structures.

**Verified:** both guards were confirmed to fail when a payload field or a
body-retaining probe was deliberately introduced. A guard that has never been
seen to fail is not a guard.

**Residual risk.** A future contributor could route data around the boundary
types. Mitigated by `make test-p3` in CI and the rule in CONTRIBUTING.md.

### T2 — The scanner disrupts a running workload

*A probe crashes a service, saturates a link, or is mistaken for an attack and
triggers an incident on a cluster running a multi-week training job.*

**Controls.**
- GET only, no request body, no method other than GET — asserted in tests.
- Exactly one request per check; no retries against a responding host.
- Bounded concurrency (`-concurrency`, default 32) and a short per-probe
  timeout (`-timeout`, default 4s).
- Probe paths are restricted to a reviewed allowlist of documented health and
  info endpoints. Paths containing `..`, query strings, or substrings like
  `exec`, `submit`, `job`, or `run` fail the build.
- CIDR expansion refuses blocks wider than /16 without an explicit flag, and a
  hard ceiling the flag cannot lift.
- A fixed, identifying User-Agent (`ray-guard/<version> (+benign posture
  probe)`) so a defender who sees the traffic can attribute it immediately.

**Residual risk.** A fragile, undocumented service could still fail on a single
GET. Accepted: one GET to a health endpoint is the minimum possible probe.

### T3 — A malicious target attacks the scanner

*A target the operator was told to scan is hostile and returns a huge body, a
decompression bomb, an endless redirect chain, a slowloris response, or a
malformed certificate.*

**Controls.**
- Response reads are bounded by `CopyN`, so body size is irrelevant.
- Redirects are not followed (`CheckRedirect` returns `ErrUseLastResponse`).
- Every client and dialer carries a timeout; TLS handshake timeout is set.
- Certificates are parsed by the Go standard library; we extract only a
  boolean, a failure class, and a date.
- No response content is ever rendered into the HTML report, so there is no
  path to inject markup into the report a buyer opens. Everything that *is*
  rendered goes through `html/template` auto-escaping.

**Residual risk.** Standard-library parser vulnerabilities. Mitigated by
`govulncheck` in CI and prompt Go version bumps.

### T4 — The report leaks more than intended

*The HTML report is emailed to a prospect and reveals internal topology.*

**Controls.**
- The report contains only hosts the operator explicitly named, plus ports,
  rule IDs, and remediation text.
- The report is self-contained — no external asset references, asserted by
  test — so opening it cannot beacon to anyone, including us.
- The anonymized snapshot is a **separate opt-in file**: it replaces hostnames
  with salted hashes using a single-use random salt, and drops finding detail
  text entirely.

**Note.** The report deliberately *does* contain raw hostnames. It is the
operator's own inventory, written to their own disk, for their own use.
Anonymization applies at the point where data might leave their control — the
snapshot — not to the report they read themselves.

### T5 — Supply-chain compromise of a release

*A trojaned binary is distributed and run with intent against GPU clusters.*

**Controls.**
- Releases are built in CI from a tagged commit, never from a workstation.
- Every artifact is signed with cosign keyless signing (Sigstore transparency
  log); verification instructions ship in the release body and SECURITY.md.
- A CycloneDX SBOM and SHA-256 checksums accompany every release.
- `govulncheck` and `golangci-lint` (including `gosec`) gate every PR.
- Static, `CGO_ENABLED=0` builds — no dynamic linking surface.
- The same cosign mechanism is reserved for the Phase-1 air-gap update
  manifest (CLAUDE.md §13), so there will never be a second signing path.

**Residual risk.** Compromise of the GitHub Actions environment or a Go module
dependency. Partially mitigated by pinned actions and SBOM review.

### T6 — Misuse: scanning without authorization

*Someone points ray-guard at infrastructure they do not own.*

**Controls.** Documented prominently in README and SECURITY.md; the identifying
User-Agent makes the traffic trivially attributable.

**Residual risk.** Accepted and inherent to the tool class. The design choice
that matters is that ray-guard is a *detector*, not an exploit tool: it cannot
be turned into an attack by flag combination, because there are no flags that
change what a probe sends.

## Explicitly out of scope (Phase 0)

There is no multi-tenancy, no authentication, no stored credentials, no
database, and no network service in this repo. Tenant isolation, RLS, mTLS
enrolment, and credential signing arrive with the Phase-1 control plane and
belong in the next revision of this document — see CLAUDE.md §12 and
`docs/data-model.md`.
