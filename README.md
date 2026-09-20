# gpu-security

Neutral, cross-vendor **security & trust posture for AI compute infrastructure** — bare-metal GPU
clusters, Neoclouds, and AI runtime frameworks. See `CLAUDE.md` for the full engineering
constitution, `docs/architecture.md` for what exists today, and `docs/data-model.md` for the
Phase-1 schema.

> **Status: Phase 0 (validation wedge).** This repo contains `ray-guard`, an agentless L1
> scanner, plus planning docs and Claude Code skills. No control plane, database, or credential
> yet — those are Phase 1+ and gated on buyer validation (see `docs/validation-log.md`).

## ray-guard — L1 agentless scanner

Detects exposed / unauthenticated AI orchestrators (Ray, vLLM, Triton, Slurm, MLflow, Jupyter,
Ollama), TLS problems, and publicly listable object storage — then emits a standalone
"GPU Risk & Isolation Report" you can hand to a security lead.

**Read-only and benign.** Detection is by observation, never exploitation: one GET per check, to
a documented health endpoint, with no request body. It confirms an unauthenticated Ray dashboard
by getting a 200 — not by submitting a job.

**Metadata only.** No model weights, prompts, training data, inference content, or object
contents are read, stored, or transmitted. This is enforced by a build-blocking test suite
(`make test-p3`), not by policy. See `docs/threat-model.md`.

**No egress.** ray-guard talks only to the targets you name. It does not phone home, check for
updates, or submit telemetry — there is no such code path.

Single static binary, no external dependencies (`go.mod` has no `require` block).

### Build & run

```bash
make build

# name hosts directly
./bin/ray-guard -targets 10.0.0.5,10.0.0.6

# or scan a subnet
./bin/ray-guard -cidr 10.0.0.0/24 -out ./report

# or read a host list
./bin/ray-guard -targets-file hosts.txt
```

Writes `report/report.json` and `report/report.html`. The HTML is self-contained — no external
assets — so it opens on an air-gapped workstation and mails as one file. To render a PDF
(optional, uses local Chrome; the scanner itself needs nothing):

```bash
make report-pdf                      # ./report/report.html → ./report/report.pdf
make report-pdf IN=x.html OUT=x.pdf
```

### Flags

| Flag | Purpose |
|---|---|
| `-targets` | Comma-separated hosts/IPs |
| `-targets-file` | One host per line; `#` comments ignored |
| `-cidr` | Comma-separated CIDR blocks; skips network/broadcast addresses |
| `-allow-large-cidr` | Permit blocks wider than /16 (IPv4) or /112 (IPv6) |
| `-ports` | Override probe ports: `vllm=8100,9000` (service=port, and/or bare ports) |
| `-buckets` | Object-storage URLs to check for public listing |
| `-out` | Report output directory (default `./report`) |
| `-benchmark-snapshot` | Write an anonymized snapshot to this path (see below) |
| `-timeout` | Per-probe timeout (default 4s) |
| `-concurrency` | Max concurrent host probes (default 32) |
| `-version` | Print version and exit |

### Exit codes

Wire it into your own CI — the exit code encodes the worst severity found.

| Code | Meaning |
|---|---|
| 0 | No findings |
| 1 | Runtime error |
| 2 | Usage error |
| 3 | Worst finding was low/info |
| 4 | Worst finding was medium |
| 5 | Worst finding was high |
| 6 | Worst finding was critical |

### Detections

| Rule | Service | Severity |
|---|---|---|
| `RG-RAY-001` | Unauthenticated Ray dashboard / Jobs API (CVE-2023-48022, CVE-2025-62593) | critical |
| `RG-RAY-002` | Ray client port reachable | high |
| `RG-VLLM-001` | Unauthenticated vLLM inference API | high |
| `RG-TRITON-001` / `-003` / `-002` | Triton HTTP / gRPC / metrics exposure | high / medium / low |
| `RG-MLFLOW-001` | Unauthenticated MLflow server | high |
| `RG-JUPYTER-001` | Jupyter reachable without token/auth | high |
| `RG-OLLAMA-001` | Unauthenticated Ollama API | medium |
| `RG-SLURM-001` | slurmctld reachable | medium |
| `RG-BUCKET-001` | Object storage lists publicly | high |
| `RG-TLS-001` | Certificate fails verification (self-signed / expired / mismatched) | medium |
| `RG-TLS-002` | Authenticated service served over plaintext HTTP | medium |
| `RG-EXPOSURE-001` | Open port on an AI-infrastructure port, service unidentified | info |

Grade thresholds are **provisional** until validated with buyers (CLAUDE.md §10.0).

### The anonymized snapshot (optional)

`-benchmark-snapshot path.json` writes aggregate metadata that seeds the "State of Neocloud
Security" index (CLAUDE.md P9). It contains rule IDs, services, ports, severities, the grade, and
salted-hash host identifiers using a **single-use random salt** — no hostnames, no IPs, no finding
details, no customer content.

**It is never transmitted.** The file is written to your disk; sending it is your deliberate
choice. Open it and read it first — it is small and legible on purpose.

> Only scan infrastructure you are authorized to assess.

## Development

```bash
make lint             # gofmt + go vet + golangci-lint
make test             # go test -race ./...
make test-p3          # metadata-only enforcement suite (P3) — never skip
make test-integration # detections against REAL Ray/Jupyter/MLflow/Ollama in Docker
make build-all        # cross-compile the release matrix + checksums
```

`make test-integration` is the one that proves the detections work against
software that actually behaves like Ray rather than against our own mocks —
see `test/integration/README.md`, including which services are real and which
are labelled fixtures.

Go 1.22+. See `CONTRIBUTING.md` before opening a PR — the P3 guarantee and the
observation-not-exploitation rule are enforced in CI and are not negotiable.

Release artifacts are cosign-signed and ship with a CycloneDX SBOM; verification instructions are
in `SECURITY.md`.

## Repo layout

```
CLAUDE.md               # engineering constitution (read first)
docs/architecture.md    # what exists today
docs/threat-model.md    # scanner attack surface + P3 controls
docs/decision-log.md    # append-only; why things are the way they are
docs/validation-log.md  # the Phase-0 buyer gate — tracks whether Phase 1 starts
docs/publishing.md      # manual checklist for going public + cutting a release
docs/data-model.md      # Postgres/Neo4j/Timescale schema (Phase 1+)
.claude/skills/         # Claude Code guardrail skills (see its README)
cmd/ray-guard/          # L1 scanner entrypoint
internal/scan/          # benign probes + detection rules + CIDR expansion
internal/report/        # JSON + HTML report (golden-file tested)
internal/domain/        # shared types + provisional grade
internal/benchmark/     # anonymized snapshot (no network I/O, by design)
test/                   # P3 metadata-only enforcement suite
test/integration/       # detections vs. real services in Docker (build-tagged)
policies/               # Rego rule library (Phase 1)
```

## Building with Claude Code

Open a Claude Code session in this repo. The skills in `.claude/skills/` load automatically.
Point it at scoped work, e.g.: *"Add a detection for an exposed Kubeflow endpoint per
CLAUDE.md §14 Phase 0 only. Obey P1/P2/P3; do not add a control plane."*
