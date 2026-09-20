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

Until the gate clears, none of that gets built.
