# gpu-security

Neutral, cross-vendor **security & trust posture for AI compute infrastructure** — bare-metal GPU
clusters, Neoclouds, and AI runtime frameworks. See `CLAUDE.md` for the full engineering
constitution and `docs/data-model.md` for the schema.

> **Status: Phase 0 (validation wedge).** This repo currently contains `ray-guard`, an agentless
> L1 scanner, plus the planning docs and Claude Code skills. No control plane, database, or
> credential yet — those are Phase 1+ and gated on buyer validation (CLAUDE.md 14).

## ray-guard — L1 agentless scanner

Detects exposed / unauthenticated AI orchestrators (Ray, vLLM, Triton, Slurm, MLflow, Jupyter,
Ollama), missing TLS, and reachable control ports — then emits a "GPU Risk & Isolation Report".
Read-only: detection by observation, never exploitation. No customer payload is read or stored.

### Build & run
```bash
make build
./bin/ray-guard -targets 10.0.0.5,10.0.0.6 -out ./report
# or
./bin/ray-guard -targets-file hosts.txt
```
Outputs `report/report.json` and `report/report.html`.

Flags: `-targets` (comma list), `-targets-file` (one host/line), `-out`, `-timeout`, `-concurrency`.

> Only scan infrastructure you are authorized to assess.

## Repo layout
```
CLAUDE.md              # engineering constitution (read first)
docs/data-model.md     # Postgres/Neo4j/Timescale schema (Phase 1+)
.claude/skills/        # Claude Code guardrail skills (see its README)
cmd/ray-guard/         # L1 scanner entrypoint
internal/scan/         # benign probes + detection rules
internal/report/       # JSON + HTML report
internal/domain/       # shared types + provisional grade
policies/              # Rego rule library (Phase 1)
```

## Building with Claude Code
Open a Claude Code session in this repo. The skills in `.claude/skills/` load automatically.
Point it at scoped work, e.g.: *"Extend ray-guard per CLAUDE.md 14 Phase 0 only — add a
`-cidr` flag and a couple of scan unit tests. Obey P1/P2/P3; do not add a control plane."*
