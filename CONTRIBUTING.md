# Contributing

Read [`CLAUDE.md`](CLAUDE.md) first. It is the engineering constitution for
this project, and Section 2 ("Non-Negotiable Principles") is binding on every
change — human or agent. A PR that conflicts with a principle gets closed, not
debated.

## The three that will get a PR rejected fastest

**P3 — metadata only.** The scanner never reads, stores, logs, or transmits
customer payload: model weights, prompts, training data, inference content,
object contents. Existence, exposure, configuration, and version are metadata.
Contents are not. If you cannot tell which a value is, it is payload.
Enforced by `make test-p3`.

**Detection by observation, never exploitation.** Probes are GET-only, send no
body, and hit documented health/info endpoints. We confirm an unauthenticated
Ray dashboard by getting a 200 — not by submitting a job. Enforced by
`TestDefaultProbePathsAreBenign` and `TestProbesAreBenignAndReadOnly`.

**P1 — stay in phase.** This repo is in Phase 0. There is no control plane, no
database, no Rego rule library, no credential, and no web console, and none of
those are welcome yet (CLAUDE.md §14). If your change needs one, open an issue
first.

## Before you open a PR

```bash
make lint      # gofmt + go vet + golangci-lint
make test      # go test -race ./...
make test-p3   # the metadata-only enforcement suite
```

All three must pass. CI runs the same checks.

## Adding a detection

A new orchestrator check needs:

1. A `Check` in `internal/scan/probe.go` using a documented health or info
   endpoint. Add the path to the allowlist in `test/metadata_only_test.go` —
   deliberately, in the same PR, so the addition is reviewed.
2. A rule in `internal/scan/detect.go` with a stable `RG-<DOMAIN>-NNN` ID,
   a severity, and **remediation text that tells someone what to actually do**.
   A finding without a fix is noise.
3. Tests in `internal/scan/detect_test.go` covering both the exposed case and
   the correctly-configured case. A rule that cannot distinguish them is worse
   than no rule — false positives are how a security tool loses a customer.

If the service shares a port with an existing one, add a case to
`TestProbeDisambiguatesSharedPort`.

## Report changes

`internal/report` has golden files. When output changes intentionally:

```bash
go test ./internal/report -update
```

Review the golden diff before committing — that diff is the artifact a buyer
reads.

## Severity and grades

Grade thresholds (`gradeFor` in `internal/domain/types.go`) are **provisional**
until validated with real buyers (CLAUDE.md §10.0, P2). Do not treat them as
settled, and do not tune severity to make a demo look better.

## Style

Match the surrounding code. Comments explain *why* a thing is the way it is —
especially where a choice protects a guarantee — not what the next line does.
