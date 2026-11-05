# Architecture

> **Phase 0.** This document describes what exists. The target architecture —
> control plane, ingestion bus, correlation graph, credential signing — is
> specified in CLAUDE.md §4–§13 and is deliberately **not built yet** (P1, P2).
> Do not treat the diagrams in CLAUDE.md as a description of this repo.

## What exists today

One thing: `ray-guard`, a single static Go binary that scans from outside the
hosts and writes local files. No server, no database, no network egress to us.

```
  flags ──► targets ──► probe ──────► observations ──► detect ──► findings
            (list,      (per port,     (metadata        (rules)     │
             file,       one GET)       only)                       ▼
             CIDR)                                            ScanResult
                                                              (score, grade)
                                                                    │
                                              ┌─────────────────────┼──────────────┐
                                              ▼                     ▼              ▼
                                        report.json           report.html    snapshot.json
                                        (machine)             (the buyer     (anonymized,
                                                               artifact)      opt-in, local)
```

## Packages

| Package | Owns | Notes |
|---|---|---|
| `cmd/ray-guard` | Flags, target expansion, concurrency, exit codes | No detection logic lives here |
| `internal/scan` | Probing and detection | `probe.go` observes, `detect.go` judges, `targets.go` expands CIDRs |
| `internal/domain` | Shared types, severity ordering, grading | No I/O, no business logic beyond scoring |
| `internal/report` | JSON + HTML rendering, terminal summary | Golden-file tested |
| `internal/benchmark` | Anonymized snapshot (P9) | **Performs no network I/O, by design** |
| `test` | Metadata-only enforcement suite (P3) | Its own CI step |

Dependency direction is one-way: `cmd` → `scan`/`report`/`benchmark` →
`domain`. `domain` imports nothing of ours. Keep it that way — it is what makes
these types reusable by the Phase-1 collector without dragging the scanner
along.

**External dependencies: none.** `go.mod` has no `require` block. Everything is
standard library. This is a deliberate constraint, not an accident of youth: it
is what makes the binary trivially auditable, statically linked, and safe to
carry into an air-gapped environment (P4, P8).

## The two-stage pipeline, and why it is split

**Observation** (`probe.go`) records what is *true*: this port is open, this
service answered 200, this certificate is self-signed. **Detection**
(`detect.go`) decides what is *bad*.

Keeping them apart matters for three reasons:

1. Detection is unit-testable without a network — most of `detect_test.go`
   constructs observations directly.
2. Severity and grading can be re-tuned after buyer feedback without touching
   probing code. Since the grade thresholds are explicitly provisional
   (§10.0), that re-tuning is expected.
3. When the Phase-1 control plane arrives, observations are what the collector
   ships and OPA/Rego evaluates. The split is the seam that makes the rule
   library replaceable without rewriting the scanner.

## Probing model

Probing is **per port**, not per check:

1. Collect distinct ports from the check table.
2. Dial each once, concurrently. Classify `open` / `closed` / `filtered`.
3. For each open port: complete a TLS handshake and verify the chain
   explicitly, so a failure can be reported by class rather than as "no TLS".
4. Run the HTTP checks bound to that port. A service is attributed only when it
   returns 2xx on its **own** health path — this is what disambiguates vLLM
   from Triton, which both default to 8000.
5. An open port nothing identifies is reported as unknown at Info severity,
   never guessed at.

Every probe is a single GET with no body, to a path on a reviewed allowlist.
See `docs/threat-model.md` for why each of those constraints exists.

## Where this is going

The next architectural step is the Phase-1 control plane (CLAUDE.md §4, §14) —
gated on the buyer-validation gate in `docs/validation-log.md`, not on
engineering readiness. When it arrives:

- `internal/domain` types become the wire contract (`/proto`).
- `internal/scan/detect.go` is superseded by the OPA/Rego rule library in
  `/policies`, each rule carrying a verification sentinel (§8).
- `internal/benchmark` gains a *server-side* aggregator; the client stays
  local-file-only.
- The three web surfaces (§7.6) arrive with it — see below.

Until the gate clears, none of that gets built.

### The web surfaces

There is **no web UI in this repo, and the Phase-0 report is not one.**
`report.html` is a file the binary writes and someone opens or mails; nothing
serves it. Nothing in the tree binds a port — every `http.Server` lives in a
`_test.go` and listens on port 0 to give the scanner a target.

This is worth stating because CLAUDE.md §7.6 specifies **three** surfaces
rather than one portal, and a reader who finds only `report.html` here could
reasonably conclude the frontend is undesigned. It is not; it is unbuilt. The
three have different audiences and different phases:

| | Surface | Who reads it | Phase |
|---|---|---|---|
| A | Operator console | the Neocloud's own security/ops team | 1 (minimal), 2–3 (depth) |
| B | Public "Verified by [Platform]" trust page | the Neocloud's *enterprise buyers* | 1 — deliberately not later |
| C | Independent credential verifier | auditors, skeptical buyers | 1 |

B is the surface most often mistaken for an afterthought and is the reason a
Neocloud signs; C is what makes the credential more than a PDF. Both rest on
the signed credential (§10), which does not exist, so neither can precede the
control plane.

Tech is already fixed by §15 — Next.js + Tailwind, REST for CRUD, GraphQL
*only* for the graph screen, Cytoscape.js/react-force-graph for blast radius —
and §16 reserves `/web`. Nothing has been committed there.

**Design exploration does exist**, as standalone HTML prototypes kept outside
this repo alongside the decks. They are design references only, not a starting
codebase: neither is built on the stack §15 specifies, and both predate
decisions taken afterwards (tier-scoped grades, the A+ ceiling, the
asserted/unconfirmed CVE split). Check them against the current report before
showing them to anyone.
