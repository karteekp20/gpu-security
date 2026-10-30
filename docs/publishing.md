# Publishing checklist

The remaining §14 Phase-0 item is "Publish OSS on GitHub". Everything below is
**manual and deliberate** — publishing is outward-facing and hard to undo, so
it is written down as a checklist rather than left to recollection.

Repo: `git@github.com:karteekp20/gpu-security.git`

## Preflight — verified 2026-10-10 (TLS/descriptor/Ctrl-C rows 2026-10-24; targets rows 2026-10-30)

Everything mechanical below has been run and passes. Re-run it if the tree
moves; otherwise this is the record.

| Check | Command | Result |
| :-- | :-- | :-- |
| Lint | `make lint` | 0 issues (golangci-lint 2.14, config now actually enforced) |
| Unit tests | `go test -race ./...` | pass |
| P3 metadata-only | `make test-p3` | pass |
| **Real services** | `make test-integration` | **pass, 27.8s** (2026-10-30) — real Ray grades F; Jupyter, MLflow, Ollama, TorchServe and nginx-terminated TLS detected; vLLM/Triton/SGLang/DCGM/Slurm correctly announce themselves as fixtures |
| Cross-compile matrix | `make build-all` | 4/4 platforms, `SHA256SUMS` written |
| Fuzzing | `make fuzz FUZZTIME=120s` | 2026-10-30: 2.65M / 2.70M / 2.53M execs (`-cidr` / `-ports` / `-targets`), no crashers; nightly in CI at 150s. The `-targets` property found two defects on the day it was written (see the decision log) |
| **Target syntax** | `ray-guard -targets http://172.31.77.10:8265,172.31.77.22` against the live demo stack | exits **2** before any probing, naming the host meant; the corrected list grades **F** with both criticals. Previously the URL was filed as an unresolved host and graded around |
| No placeholders | `git grep -nE '<YOUR NAME>\|TODO\|FIXME\|/tmp/claude-'` | clean |
| LICENSE holder | — | MIT, "Copyright (c) 2026 Karteek" |
| `.gitignore` | — | covers `bin/`, `report/`, `report-*/`, `snapshot*.json`, `/ray-guard` |
| Threat model read as an outsider | `docs/threat-model.md` | T6 corrected — see below |
| Action pins match their comments | GitHub tag API, all 7 pins | OK — every SHA is the commit its `# vX.Y.Z` comment names |
| Threat-model claims traced to code | T1–T7 | T4 corrected (the coverage list is capped at 10, not "every target"); the rest hold — path allowlist, CIDR hard ceiling `1<<18`, `html/template`, no-redirect, `gosec` enabled, `pull_request` trigger |
| **TLS floor** | unit: server capped at TLS 1.0/1.1; integration: real nginx | service still identified behind 1.0/1.1 with `RG-TLS-003`; nginx negotiates 1.2/1.3 with no version finding |
| **Low descriptor limit** | `bash -c 'ulimit -Sn 128; ulimit -Hn 128; ray-guard -cidr <demo>/24'` | F with 19 findings, 0 probe errors, 4m1s (clamped to 2 hosts at a time). Before the clamp the same run graded **C with 3 findings** — re-run this if `MaxHostConcurrency` or the check set changes |
| **Ctrl-C mid-scan** | `kill -INT` against a running `-cidr` sweep | exit **130**, report written, `interrupted: true`, "0 of 254 targets were probed", nothing recorded as unreachable. Checked by hand because the signal path itself cannot be tested without a timing-dependent test; re-run it if `cmd/ray-guard` changes |
| Release instructions are runnable | `.github/workflows/release.yml` vs `SECURITY.md` | Re-checked 2026-10-30 after the cosign-3 migration: `.sigstore.json` bundle names, upload globs, `cd bin && sha256sum -c` paths and `VERSION=` override all line up |

**What that outsider read changed.** T6 claimed "pinned actions". The workflows
used mutable major tags (`@v4`, `@v0`) on the actions that build and sign the
release — so the claim was false in the one place it mattered. All third-party
actions are now pinned to commit SHAs with Dependabot keeping them current, the
release token is scoped to the release job, and the release verifies its own
signatures before publishing. Separately, the `golangci-lint` job ran action v6
against a v2 config, which v6 cannot drive: the lint gate was reporting green
without enforcing the file it pointed at. **Confirmed on GitHub 2026-10-30**:
CI run `41105260819` passed in 3m7s on the new pins with the v2 config actually
enforced (and `41106683714` after it).

What the same look at the Actions tab also turned up: the nightly
`Integration (real services)` job had been **failing for seven consecutive
nights** on `no space left on device`, extracting an Ollama layer — a runner
disk problem, not a detection problem (`make test-integration` passes locally
in 27.8s). It is the worst-shaped CI failure this repo could have, because that
job's name is the claim the README leans on hardest. Fixed by freeing the
preinstalled toolchains before the pulls; see the decision log.

## ⚠️ Read this before tagging: `v0.1.0` is already pushed (as a draft)

`v0.1.0` exists on `origin` and points at `79d559f`, which predates both the
working lint configuration and the fix that stops `report.Write` exiting 0 on a
truncated report. Check what the tag push actually produced:

Checked 2026-10-30: the `v0.1.0` release exists but **`isDraft: true`**, so it
was never visible to anyone. It does carry the full signed artifact set (12
binaries/`.sig`/`.pem`, `SHA256SUMS`, SBOM), because the release workflow ran
and succeeded once on that tag — and then ran a second time on the same tag and
**failed**, which is the moved tag the warning below is about.

```bash
gh release list
gh run list --workflow=release.yml --limit 5
```

**Do not move the tag.** A Sigstore-logged release is supposed to be immutable;
a repointed release tag is indistinguishable from an attack, and we are a
security product. Cut a new patch from `main` instead — the message is
pre-written in `docs/release-notes/v0.1.1.md`.

If a `v0.1.0` release *was* published, note in its body that v0.1.1 supersedes
it; do not delete it. It was **not** published — it is a draft — so nothing
public ever claimed v0.1.0 and there is nothing to supersede. Deleting the
draft is safe (it does not touch the tag) but is nobody's emergency; leave it
unless it starts confusing people.

## Repo description and topics

Paste these in rather than improvising at the Settings screen — this is most
of how the repo gets found, and it is the first thing a buyer reads.

**Description** (GitHub allows 350 characters):

> Agentless security scanner for AI compute infrastructure. Finds exposed and
> unauthenticated AI orchestrators — Ray, vLLM, Triton, TorchServe, SGLang,
> Slurm, MLflow, Jupyter, Ollama — plus exposed GPU telemetry, TLS and bucket
> problems, then writes a standalone GPU Risk & Isolation Report. Read-only,
> metadata-only, no egress, one static binary.

**Topics:**

```
ai-infrastructure  ai-security  security-scanner  gpu  ray
neocloud  cspm  mlops-security  golang  infrastructure-security
torchserve  llm-security
```

`ray` and `ai-infrastructure` are the two that matter: ShadowRay is the search
people actually run.

## Before making the repo public

Everything mechanical is done (see the preflight table). What is left needs a
human:

- [x] Lint, unit tests, P3 suite, integration suite, cross-compile matrix.
- [x] No placeholders or private paths in tracked files; LICENSE holder
      correct; `.gitignore` covers binaries and scan output.
- [x] `docs/threat-model.md` re-read as an outsider; T6 corrected.
- [x] Repo description and topics drafted (above).
- [x] **No client data anywhere in the history**, not just in the tree — the
      `.gitignore` patterns are a backstop, not proof. Checked 2026-10-10: the
      only matching paths ever committed are source files and
      `internal/report/testdata/*.golden.*`, and the only addresses in those
      are `10.0.0.5` / `10.0.0.6`.
      ```bash
      git log --all --name-only --pretty=format: | sort -u | grep -iE 'report|snapshot|\.json$'
      ```
- [x] Read the README and `docs/assessment/objections.md` once as a skeptic.
      Done 2026-10-10. Every checkable claim in the README was traced to the
      code — flags, exit codes, rule IDs and severities, `GET`-only with a nil
      body, the single-use salt, no `require` block, every `make` target. The
      demo was run end to end and matches `demo.md` exactly: grade **F**, 8
      hosts with findings, `RG-RAY-001` first, five items under "Fix these
      first". Three things did not survive the read and are fixed (§18 rev 9):
      the report footer cited `CLAUDE.md §10.0` at a buyer; two documents
      promised a /24 in "well under a minute" where the real bound is ~8 waves
      × the probe timeout; and `objections.md` claimed we had broken the P3
      suite on purpose with nothing in the repo to show — the four mutations
      are now written up at the top of `test/metadata_only_test.go` and each
      was re-confirmed to turn the suite red.

## Making it public

GitHub → Settings → General → Danger Zone → Change visibility → Public, or:

```bash
gh repo edit karteekp20/gpu-security --visibility public \
  --accept-visibility-change-consequences
```

Then enable, in Settings → Code security:

- [x] Dependabot alerts and security updates — enabled 2026-10-30
      (`PUT /vulnerability-alerts` → 204; `automated-security-fixes` →
      `enabled: true`). These are the two that work on a private repo.
- [ ] Private vulnerability reporting (SECURITY.md points people at it).
      `PUT /private-vulnerability-reporting` returns **404 while the repo is
      private** — this one has to wait for the flip, it is not a scope problem.
- [ ] Secret scanning. `PATCH /repos` returns **422 "Secret scanning is not
      available for this repository"** for the same reason.

## Cutting the first release

The release workflow triggers on a `v*` tag and does the rest: builds the
static matrix, generates the SBOM, cosign-signs every artifact, and publishes.

`v0.1.0` is already pushed (see above), so the first release to cut from the
current tree is `v0.1.1`:

```bash
git tag -a v0.1.1 -F docs/release-notes/v0.1.1.md
git push origin v0.1.1
```

Then watch it and verify the output yourself, because a signed release nobody
has verified is just a release:

```bash
gh run watch                       # or the Actions tab

# Download an artifact and its signature, then:
cosign verify-blob \
  --bundle ray-guard-linux-amd64.sigstore.json \
  --certificate-identity-regexp '^https://github.com/karteekp20/gpu-security/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ray-guard-linux-amd64

sha256sum -c SHA256SUMS
```

**Done 2026-10-30 — `v0.1.1` is published** (run `41109256221`, `isDraft:
false`, 12 assets: 4 binaries, 6 `.sigstore.json` bundles, `SHA256SUMS`,
`sbom.cyclonedx.json`).

- [x] `cosign verify-blob` succeeds against a freshly downloaded artifact.
      All six bundles verified `Verified OK` against a `gh release download`
      into a clean directory — the path a buyer takes, not the workflow's own
      self-check.
- [x] The checksums match (`sha256sum -c SHA256SUMS`: 4/4 OK).
- [x] The binary runs: the downloaded `ray-guard-linux-amd64` prints
      `ray-guard v0.1.1`.

**It took two attempts, and the first failure is the useful part.** The
initial `v0.1.1` build failed in the signing step: cosign 3 ignores
`--output-signature`/`--output-certificate` and wants `--bundle`. The installer
action was SHA-pinned; the cosign *binary* it installs was not. Artifacts are
now Sigstore bundles, the binary is pinned to `v3.1.4`, and the tag was
re-pushed — safe only because the failed run created no release and the repo
was still private. **The rule stays unconditional for anything that shipped:**
a tag whose release published is immutable, full stop. Verify a release
exists before concluding otherwise:

```bash
gh api repos/karteekp20/gpu-security/releases --jq '.[] | "\(.tag_name) draft=\(.draft)"'
```

## After publishing

- [ ] Point it at something real and log the result in
      `docs/validation-log.md`.
- [ ] Remember what the release is *for*. Stars and downloads are explicitly
      **not** the Phase-0 gate (CLAUDE.md §14). The gate is 3 buyer-led
      assessments and 2 pay-and-name-it intents. Publishing is distribution in
      service of getting into those rooms — it is not progress on the gate by
      itself.

## What publishing does not unlock

Nothing in Phase 1. No control plane, no database, no Rego rule library, no
credential, no web console. Those wait on the gate, not on engineering
readiness or on how the launch goes.
