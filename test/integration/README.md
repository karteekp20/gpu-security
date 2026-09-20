# Integration tests — detections against real services

```bash
make test-integration
```

Brings up a deliberately insecure AI stack in Docker, runs the detections
against it, and tears it down. Not part of `go test ./...` — the images are
several gigabytes, and they are behind a `//go:build integration` tag.

## Why this exists

Unit tests prove our detection logic agrees with our own mocks. That is a
weaker claim than it sounds. `RG-RAY-001` carries the entire ShadowRay pitch,
and if real Ray redirected, served a SPA shell, or answered on a path we
guessed wrong, every unit test would still pass while the detection misfired
in front of a buyer.

So the flagship services run for real here.

## Fidelity — read this before trusting a green run

Coverage is not uniform, and the split is deliberate:

| Service | Fidelity | Why |
|---|---|---|
| Ray | **Real** (`rayproject/ray`, CPU) | The flagship detection. Must be real. |
| Jupyter | **Real** | CPU-only, representative |
| MLflow | **Real** | CPU-only, representative |
| Ollama | **Real** | CPU-only; `/api/tags` answers without a model pull |
| vLLM | *Fixture* | GPU-bound image; replays documented `/v1/models` shape |
| Triton | *Fixture* | GPU-bound, ~15GB image; replays `/v2/health/ready` and `/metrics` |
| Slurm | *Fixture* | `RG-SLURM-001` is reachability-only, so a TCP listener is faithful |

The fixtures are labelled as such in the test output. They verify wiring, not
that we understand those services' real behaviour — if you get access to a GPU
host, promoting vLLM and Triton to real containers is worth doing.

## The negative cases matter as much as the positive ones

`control-secured` enforces authentication; `control-loopback` binds inside its
own namespace. Neither may raise a service-exposure finding. A scanner that
cannot tell a secured service from an exposed one is worse than no scanner —
false positives are how a security tool loses a customer.

## What this suite has already caught

The TLS probe used to consume the entire `-timeout` against any service that
accepts a connection and then waits silently for a complete HTTP request.
Ray rejects a ClientHello in ~1ms, so unit tests never showed it; real Jupyter
and MLflow both hang, and each cost a full 5s. The handshake is now bounded
separately (`handshakeTimeout` in `internal/scan/probe.go`), which cut the
suite from 28s to 18s and removes a per-port stall from every real scan.

That bug was invisible to mocks. It is the reason this suite exists.

## Local troubleshooting

If `docker compose` reports *"client version is too old"*, your compose plugin
predates the daemon:

```bash
DOCKER_API_VERSION=1.44 make test-integration
```

## CI

Runs nightly and on demand (`.github/workflows/integration.yml`), not on every
PR — multi-gigabyte pulls on each push would tax normal work for a signal that
changes rarely. The nightly run is what catches upstream image drift.
