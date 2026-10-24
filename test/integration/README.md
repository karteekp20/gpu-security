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
| TorchServe | **Real** (`pytorch/torchserve:0.12.0-cpu`, 1.9GB) | The second critical detection. Must be real, for the same reason Ray must be. Runs twice: exposed, and token-protected as a negative control. |
| TLS proxy | **Real** (`nginx:alpine`) | Terminates TLS with a real self-signed certificate in front of the real Ray dashboard. Until this existed, every TLS test ran against Go's own `httptest` server — our own TLS stack agreeing with itself. |
| vLLM | *Fixture* | GPU-bound image; replays documented `/v1/models` shape |
| Triton | *Fixture* in CI, **real on demand** | The image runs CPU-only but is 16GB — more than a standard GitHub runner's free disk. The fixture replays `/v2/health/ready` and `/metrics`; `docker compose --profile heavy up -d triton-real` runs the real one on `.25`, and `-run RealTriton` checks it. |
| SGLang | *Fixture* | GPU-bound image; replays `/get_model_info` on 30000 |
| dcgm-exporter | *Fixture* | Needs a real GPU to produce metrics; replays `/metrics` on 9400 |
| Slurm | *Fixture* | `RG-SLURM-001` is reachability-only, so a TCP listener is faithful |

The fixtures are labelled as such in the test output. They verify wiring, not
that we understand those services' real behaviour — if you get access to a GPU
host, promoting vLLM, Triton, SGLang and dcgm-exporter to real containers is
worth doing. **Both Critical rules are now validated against the real
software**, which is the bar that matters: those two carry the pitch.

**Ports and paths in these fixtures come from each project's own
documentation**, not from recollection — TorchServe's configuration
reference, SGLang's server-arguments page, NVIDIA's `dcgm-exporter` command
reference. A fixture that agrees with a wrong assumption proves nothing, and
a check on the wrong port is a silent miss, which reads to an operator as a
clean result.

Real TorchServe also serves 8080, its inference port, whose only `GET` is
`/ping`. ray-guard deliberately sweeps 8080 **without attributing it**, so the
assertion there is that the scan reports `RG-EXPOSURE-001` at Info and never
names a service. That port is shared by TGI, LocalAI and most things with a
model behind them; a 200 on `/ping` is not evidence of TorchServe.

## The TLS fixture is generated, not committed

`make tls-fixture` (a dependency of `make test-integration` and `make
demo-up`) runs `fixtures/gencert`, which writes a self-signed certificate and
key into `fixtures/tls/` — gitignored. **If you bring the stack up with a bare
`docker compose up`, run that first**, or nginx will not start and
`wait-ready.sh` will time out on `172.31.77.50:8265`.

No private key lives in this repository. A test key is harmless in principle,
but a security product shipping a `.pem` in its own tree invites exactly one
question in review, and "it's only for tests" is a worse answer than not
having one. The generator is ~90 lines of dependency-free Go because
`nginx:alpine` has no `openssl` binary and a test suite should not assume the
host has one either.

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

**Triton's metrics server answers 200 on *any* path.** Found by running the
real thing on the `heavy` profile, and it changed the design. A wildcard
control probe had just been added — one GET to a path nothing serves, so a
catch-all server is not reported as whatever orchestrator shares its port —
and real Triton's 8002 answered 200 to it. Applied naively, that downgraded
`RG-TRITON-002` to an unidentified-port finding, which would have left a rule
that cannot detect the software it is named after: worse than no rule, because
it makes the detection table look bigger than it is. Prometheus-style
endpoints are exempt from the control for exactly this reason, and the
exemption is a named list with a test that it only contains real services.
The fixture answered 404 there, so nothing but the real server could have
shown this.

**The official `pytorch/torchserve` image binds everything to `0.0.0.0`.** Its
bundled `config.properties` sets `inference_address`, `management_address`,
`metrics_address` and both gRPC addresses to `0.0.0.0`. Upstream's security
page says "these ports are accessible to `localhost` by default" — true of a
bare install, not of their own container. So the exposure here does not
require anyone to have edited a config: running the official image with
published ports is enough, and token authorization is the only thing standing
between that and CVE-2023-43654. The compose file deliberately does **not**
override the bind addresses, so the stack demonstrates this rather than
hiding it.

**TorchServe answers `400`, not `401`, when token authorization is required.**
Found within minutes of promoting it from a fixture to a real container, and
it matters twice over. It decides what an operator sees — a token-protected
management API is reported as an unidentified service at Info rather than as
"requires auth" — and it falsified the rule's own remediation text, which said
TorchServe has no native authentication. It has enforced token authorization
by default since 0.12, so `RG-TORCHSERVE-001` can only fire where that was
switched off or where the build predates it. The remediation now says exactly
that. The wrong version would have been corrected by the first TorchServe
operator in the room, on the rule we lead with.

**ray-guard could not see through TLS 1.0 or 1.1 at all.** Not found here —
found by pointing the probe at a server capped at those versions — but it is
why the nginx proxy now exists. Go's client refuses an obsolete handshake by
default, so the probe concluded "not TLS", tried plaintext against a TLS port,
and reported an unauthenticated Ray dashboard behind an old terminating proxy
as an unidentified open port. The floor is now TLS 1.0 for measurement
purposes and the negotiated version is reported (`RG-TLS-003`). The nginx
proxy is the other half of that check: modern TLS must still negotiate 1.2/1.3
and must *not* raise the obsolete-version finding.

## Running the heavy profile

```bash
cd test/integration
docker compose --profile heavy up -d triton-real      # 16GB pull, CPU-only
RAY_GUARD_INTEGRATION=1 go test -tags integration ./... -run RealTriton -v
docker compose --profile heavy down -v
```

It needs no GPU — NVIDIA's quickstart says the same image runs without one;
you omit `--gpus` and simply cannot load GPU-only model configurations, which
is irrelevant to a scanner that never loads a model. The test skips with
instructions if the container is not up, so `make test-integration` is
unaffected.

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
