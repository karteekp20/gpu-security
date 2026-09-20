---
name: ray-guard-scanner
description: >
  Use when building or editing the ray-guard L1 agentless scanner or any orchestrator-exposure
  detection (Ray, vLLM, Triton, Slurm, MLflow, Jupyter, Ollama). This is the Phase-0 deliverable
  and the only thing on the critical path to the validation gate. Covers Go structure, the probe
  set, ports, safety rules, output format, and grade mapping. Always also apply the
  metadata-only-guard skill when writing scanner code.
---

# ray-guard — L1 Agentless Scanner (CLAUDE.md §3 L1, §14 Phase 0)

The wedge. A single static Go binary that detects exposed/unauthenticated AI orchestrators and
basic isolation risks, and emits a clean report. **No backend, no database, no login** — it runs
standalone and writes a file. Keep it that way for Phase 0.

## Non-negotiables
- **Read-only and benign.** Detect exposure by observation (open port + unauthenticated response +
  missing TLS + public bind). NEVER send exploit payloads or code-execution attempts. Apply the
  metadata-only-guard skill.
- **Single static binary** (`CGO_ENABLED=0`), cross-compiled; easy to hand to a security lead and
  run in 60 seconds. This matters for air-gap and trust.
- **Fast, low-footprint.** Bounded concurrency, sane timeouts, no aggressive scanning that could
  destabilize a live cluster.

## Detection targets (ports are defaults; make them configurable)
| Orchestrator | Port(s) | Check |
|---|---|---|
| Ray dashboard / Jobs API | 8265 | reachable + unauthenticated (CVE-2023-48022, CVE-2025-62593) |
| Ray client | 10001 | reachable, exposure |
| vLLM | 8000 | reachable, unauthenticated inference API |
| NVIDIA Triton | 8000/8001/8002 (HTTP/gRPC/metrics) | reachable, exposure |
| Slurm (slurmctld) | 6817 | reachable, exposure |
| MLflow | 5000 | reachable, unauthenticated |
| Jupyter | 8888 | reachable, token/auth state |
| Ollama | 11434 | reachable, unauthenticated |
Plus: missing/invalid TLS, public-bound services (0.0.0.0), and public object-storage buckets.

## Suggested structure
```
cmd/ray-guard/            # entrypoint, flags, config
internal/probe/           # one prober per orchestrator; benign, read-only
internal/detect/          # exposure/auth/TLS evaluation → Finding structs
internal/report/          # JSON + HTML/PDF report generation
pkg/domain/               # shared Finding/Asset types (no business logic)
```

## Findings & grade
- Each finding gets a stable rule ID: `RG-<DOMAIN>-NNN` (e.g. `RG-RAY-001` for an
  unauthenticated Ray dashboard), plus severity, title, affected asset, and remediation text.
- Map the overall result to the grade band in CLAUDE.md §10.0 (F if a critical RCE-class exposure
  like an unauthenticated Ray dashboard is public). Treat grade thresholds as provisional until
  buyer validation — don't hard-code them as gospel.

## Output (the deliverable)
- Machine: JSON (for later ingestion).
- Human: one clean, standalone HTML/PDF "GPU Risk & Isolation Report" — exposure summary, ranked
  findings, proposed grade, and a short ShadowRay-flavored framing. This is the lead magnet you
  put in front of a Neocloud security lead. Use the official `pdf` skill for PDF rendering.

## Scope discipline
Do not add a control plane, database, credential, or web console to Phase 0. If a task asks for
those, it belongs to Phase 1 — stop and confirm against CLAUDE.md §14. The goal of this binary is
to run against a real cluster and produce a report good enough to earn the three buyer-led
assessments in the Phase-0 gate.
