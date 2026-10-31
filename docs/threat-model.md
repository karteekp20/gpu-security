# Threat Model — ray-guard (L1 scanner)

> **Scope:** the Phase-0 `ray-guard` scanner only. There is no control plane,
> no database, no collector, and no network egress in this repo yet; when
> those land (Phase 1), this document must be extended in the same PR that
> adds them (CLAUDE.md §12, §17).
>
> **Status:** current as of the Phase-0 scanner. **Last updated:** 2026-10-10.

## Why this document exists

CLAUDE.md P8 states that we are a security product and therefore a high-value
target, and requires a maintained threat model. There is a second reason: a
CISO deciding whether to let an unfamiliar binary touch a multi-million-dollar
cluster will ask exactly the questions below. Answering them in writing, before
being asked, is part of the low-friction guarantee that makes L1 sellable (P10).

## What ray-guard is

A single static Go binary, run by an operator from a host they control, against
hosts they are authorized to assess. It opens TCP connections, issues at most
one HTTP GET per check (plus one control request per identified port, see
T8), and writes three local files: `report.json`,
`report.html`, and (only if asked) an anonymized benchmark snapshot.

It has **no** network egress beyond the targets the operator named. It does not
phone home, check for updates, submit telemetry, or contact any of our
infrastructure. This is a design constraint, not a configuration default
(P4) — there is no code path to disable, because there is no such code path.

That last sentence is a claim about every future version of the binary, so it
is enforced rather than remembered: `TestOnlyTheProbeMayReachTheNetwork`
(`test/metadata_only_test.go`) fails the build if any package other than
`internal/scan` imports `net`, `net/http`, `os/exec`, or `syscall`. It applies
most pointedly to `internal/benchmark`, whose output is the one artifact
*designed* to be shared with us (P9) — "write a local file" and "POST it
somewhere" are a one-line difference, and this is the line.

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

**Verified:** four leaks were planted and each one was confirmed to turn the
suite red — a response header copied into a finding note, a buffered response
body, a parsed bucket listing, and a payload-shaped field on the boundary
type. They are written up at the top of `test/metadata_only_test.go` so the
check is reproducible rather than remembered; re-run them after changing a
probe or a boundary type. A guard that has never been seen to fail is not a
guard.

**Residual risk.** A future contributor could route data around the boundary
types. Mitigated by `make test-p3` in CI and the rule in CONTRIBUTING.md.

### T2 — The scanner disrupts a running workload

*A probe crashes a service, saturates a link, or is mistaken for an attack and
triggers an incident on a cluster running a multi-week training job.*

**Controls.**
- GET only, no request body, no method other than GET — asserted in tests.
- Exactly one request per check, plus a single control request on a port
  where a service was identified (T8); no retries against a responding host.
- Bounded concurrency (`-concurrency`, default 32) and a short per-probe
  timeout (`-timeout`, default 4s).
- Probe paths are restricted to a reviewed allowlist of documented health and
  info endpoints. Paths containing `..`, query strings, or substrings like
  `exec`, `submit`, `job`, or `run` fail the build.
- CIDR expansion refuses blocks wider than /16 without an explicit flag, and a
  hard ceiling the flag cannot lift.
- Every target is validated before anything is dialed: an entry that is not a
  host (a URL, `host:port`, a CIDR block in `-targets`, a malformed address)
  exits 2 rather than being probed or quietly skipped, and an IPv6 zone is
  constrained to an interface name so that the host we dial is the host we
  were given.
- The three parsers that turn operator input into a target list (`-cidr`,
  `-ports`, `-targets`) are fuzzed nightly. The properties they hold are the
  ones that keep a scan inside its authorization: every expanded target parses
  as an address, the host ceiling is never exceeded, no `-ports` string can
  introduce a probe path the allowlist never reviewed, and every accepted
  target survives into a probe URL as itself — naming no other host, port or
  path. A parser bug here does not crash the tool so much as point it
  somewhere nobody agreed to. The `-targets` property found one on the day it
  was written: an IPv6 zone may contain any bytes, including the ones that
  terminate a host inside a URL, so the zone is now constrained to an
  interface name.
- A fixed, identifying User-Agent (`ray-guard/<version> (+benign posture
  probe)`) so a defender who sees the traffic can attribute it immediately.
- Ctrl-C takes effect at once: no further target is dialed, in-flight probes
  are abandoned, and the partial report is still written. "Stop the scan" being
  cheap and immediate is a control, not a convenience — the alternative is an
  operator weighing a stop request against losing the run.

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
  boolean, a failure class, a protocol version, and a date.
- **The scanner deliberately negotiates down to TLS 1.0, and deliberately does
  not verify certificates.** Both read like weakened security and are neither:
  the probe exists to *measure* someone else's transport posture, and a client
  that refuses an obsolete handshake cannot see the service behind it or
  report that the handshake is obsolete (`RG-TLS-003`). Nothing confidential
  is at stake in either direction - one GET to a health path, no credentials,
  no request body, and the response is discarded unread. Certificate
  verification is performed *after* the handshake, by us, so that the failure
  class can be reported rather than merely acted on. Modern servers still
  negotiate 1.2/1.3: lowering the floor changes what we can see, not what we
  accept when better is on offer. SSLv3 and earlier are not supported by Go at
  all, so a server offering only those is reported as an unidentified open
  port - the honest ceiling of this check.
- No response content is ever rendered into the HTML report, so there is no
  path to inject markup into the report a buyer opens. Everything that *is*
  rendered goes through `html/template` auto-escaping.

**Residual risk.** Standard-library parser vulnerabilities. Mitigated by
`govulncheck` in CI and prompt Go version bumps.

### T4 — The report claims more coverage than it had

*A scan reaches none of its targets — wrong addresses, a firewall between the
scanner and the cluster, a DNS change — and the empty finding list is read as
a clean bill of health.*

This is not an attack; it is the failure mode most likely to actually cause
harm, because it produces confident, wrong reassurance. A tenant whose
pipeline scans a moved target would pass green indefinitely.

**Controls.**
- Host state is tracked per target: `responded` (a TCP RST or an open port
  proves the host is alive), `no-response`, or `unresolved`.
- Only a TCP RST counts as proof of life. "No route to host" returns promptly
  but comes from the network, not the host, so an empty subnet cannot
  masquerade as a clean one.
- A scan where nothing responded grades `N/A — INCONCLUSIVE`, scores 0, says
  "this is not a clean result" in the report, and exits **7** so CI fails.
- Partial coverage is disclosed in the report, above the findings: the
  unassessed targets are named individually up to the first ten, then counted
  (`report.json` carries them all). The cap exists so a dark /24 cannot bury
  the report it is supposed to qualify.
- An **interrupted** scan (Ctrl-C) is the same failure in a different shape, so
  it gets the same treatment: a clean grade is unreachable by construction, the
  report leads with "this report is partial" and states how many of the
  requested targets were probed, and the process exits **130**. A
  finding-driven grade still stands — an observed exposure is observed — but it
  is stated as a floor, not a verdict.
- Targets that were never dialed are absent from the report rather than listed
  as unreachable, and a probe abandoned mid-flight is discarded rather than
  recorded. "We stopped" is a fact about the scanner; "it did not answer" is a
  fact about the customer's host, and the report must not confuse them.
- A probe that fails **inside the scanner** - the open-file or ephemeral-port
  limit - is not recorded as a port state at all. Such a port yields no
  observation, the host is reported as `probe-failed` rather than
  "no response (firewalled, powered off...)", and the run is marked degraded:
  no clean grade, a banner naming the cause and the one-command fix, exit 7.
  This was measured, not theorized: with the limit at 128, a /24 of the demo
  cluster graded **C with 3 findings** where a healthy run graded **F with
  19**, and the unauthenticated Ray dashboard appeared as an unidentified
  service on 8265. Nothing in the report said anything had gone wrong.
- `-concurrency` is clamped to what the local descriptor limit sustains, so
  the degraded path is the backstop rather than the normal case. A constrained
  machine gets a slower correct scan instead of a fast wrong one.
- The benchmark snapshot carries all three flags, so the aggregate index can
  exclude a run that never covered what it set out to.

**Residual risk.** A firewalled-but-healthy host is indistinguishable from an
absent one. We report the ambiguity rather than resolving it, which is the
honest option.

### T5 — The report leaks more than intended

*The HTML report is emailed to a prospect and reveals internal topology.*

**Controls.**
- The report contains only hosts the operator explicitly named, plus ports,
  rule IDs, remediation text, the engagement label the operator passed with
  `-label`, and the host the scan ran from. The last two are evidence about
  the assessment rather than about the customer, and both are deliberately
  absent from the snapshot below.
- The report is self-contained — no external asset references, asserted by
  test — so opening it cannot beacon to anyone, including us.
- The anonymized snapshot is a **separate opt-in file**: it replaces hostnames
  with salted hashes using a single-use random salt, and drops finding detail
  text entirely. It has no field for the engagement label or the scanning
  host, so neither can be included by accident — asserted both by value and
  structurally in `internal/benchmark/snapshot_test.go`, and confirmed by
  adding such a field and watching the test fail.

**Note.** The report deliberately *does* contain raw hostnames. It is the
operator's own inventory, written to their own disk, for their own use.
Anonymization applies at the point where data might leave their control — the
snapshot — not to the report they read themselves.

### T6 — Supply-chain compromise of a release

*A trojaned binary is distributed and run with intent against GPU clusters.*

**Controls.**
- Releases are built in CI from a tagged commit, never from a workstation.
- Every artifact is signed with cosign keyless signing and ships with a
  Sigstore bundle (`<artifact>.sigstore.json`: signature, certificate and
  transparency-log proof in one file); verification instructions ship in the
  release body and SECURITY.md, and the release workflow runs them against
  what it just signed before it publishes anything. The cosign *binary* is
  version-pinned, not only the installer action — an unpinned cosign 3 broke
  the signing step once, and a signing step that breaks loudly is the good
  case; one that silently emits something the current verifier cannot read
  would be found by whoever took our instructions seriously.
- A CycloneDX SBOM and SHA-256 checksums accompany every release.
- `govulncheck` and `golangci-lint` (including `gosec`) gate every PR.
- Static, `CGO_ENABLED=0` builds — no dynamic linking surface.
- **No third-party Go dependencies at all.** `go.mod` has no `require` block;
  everything is the standard library. There is no transitive dependency tree
  to compromise, which is the strongest available answer to this threat and
  the reason it is worth keeping true.
- **Every third-party action is pinned to a commit SHA**, not a tag. A tag is
  mutable, and these actions run in the job that builds and signs the release,
  so a repointed tag is a direct path to a trojaned binary. Dependabot keeps
  the pins current so pinning does not decay into staleness. All seven pins
  were checked against the upstream tags on 2026-10-10 — the SHA that runs is
  the commit the `# vX.Y.Z` comment names, in every case. The comment is for
  humans, so it is worth knowing it is not lying:

  ```bash
  # for each "uses: owner/repo@<sha> # vX.Y.Z" in .github/workflows/
  gh api repos/<owner>/<repo>/git/ref/tags/<vX.Y.Z> --jq .object.sha
  # (annotated tags need one more hop: git/tags/<that sha> --jq .object.sha)
  ```
- The release workflow's write permissions are scoped per job (`contents:
  write` and `id-token: write` only on release; `contents: read` elsewhere).
- The same cosign mechanism is reserved for the Phase-1 air-gap update
  manifest (CLAUDE.md §13), so there will never be a second signing path.

**Residual risk.** Compromise of the GitHub Actions environment itself, or of
an action at a SHA we have already pinned. SBOM review and the absence of any
Go dependency tree narrow this, but a build running on someone else's compute
cannot be fully attested from inside itself. Reproducible builds would be the
next real mitigation; they are not yet in place.

### T7 — Misuse: scanning without authorization

*Someone points ray-guard at infrastructure they do not own.*

**Controls.** Documented prominently in README and SECURITY.md; the identifying
User-Agent makes the traffic trivially attributable.

**Residual risk.** Accepted and inherent to the tool class. The design choice
that matters is that ray-guard is a *detector*, not an exploit tool: it cannot
be turned into an attack by flag combination, because there are no flags that
change what a probe sends.

### T8 — The report names a service that is not there

*A host answers 2xx to every path — an SPA dev server, a catch-all ingress
route, a captive portal, a misconfigured reverse proxy — and the scan
attributes it to whatever orchestrator shares that port.*

Also not an attack, and in the same family as T4: the damage is a confident
claim that happens to be false. On 8265 it produces a **critical**
"unauthenticated Ray dashboard exposed" against something harmless. On 8000 it
produced vLLM *and* Triton at once — two services on one port, which cannot
happen and is immediately visible to the person reading the report. One such
finding in a buyer's own environment costs more credibility than ten correct
ones earn.

**Controls.**
- A service is attributed only on a 2xx from its own documented health path,
  never from an open port.
- On a port where something was identified, one further GET to
  `/ray-guard-probe-404`, a path nothing serves. A 2xx there means the port
  discriminates nothing, so the observation is downgraded to an unidentified
  service at Info with the reason stated in the finding.
- Real Ray, Jupyter, MLflow, Ollama and TorchServe were each checked against a
  nonexistent path and all answer 404, so the control costs correct
  attribution nothing. That was measured against the running containers, not
  assumed — a control probe that real services happened to 2xx would have
  silently downgraded the flagship finding.
- An unidentified port is reported at Info and never guessed at
  (`RG-EXPOSURE-001`), and 8080 is deliberately swept without attribution
  because it is shared by TorchServe, TGI, LocalAI and most model servers.
- A control request that fails is treated as "this port discriminates fine",
  because silently downgrading a real finding is the worse error.

**Residual risk.** A server that serves exactly one orchestrator's health path
and 404s everything else is indistinguishable from that orchestrator. We
accept that: it is the same evidence a human would have.

## Explicitly out of scope (Phase 0)

There is no multi-tenancy, no authentication, no stored credentials, no
database, and no network service in this repo. Tenant isolation, RLS, mTLS
enrolment, and credential signing arrive with the Phase-1 control plane and
belong in the next revision of this document — see CLAUDE.md §12 and
`docs/data-model.md`.
