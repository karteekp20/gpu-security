# Publishing checklist

The remaining §14 Phase-0 item is "Publish OSS on GitHub". Everything below is
**manual and deliberate** — publishing is outward-facing and hard to undo, so
it is written down as a checklist rather than left to recollection.

Repo: `git@github.com:karteekp20/gpu-security.git`

## Preflight — verified 2026-10-10

Everything mechanical below has been run and passes. Re-run it if the tree
moves; otherwise this is the record.

| Check | Command | Result |
| :-- | :-- | :-- |
| Lint | `make lint` | 0 issues (golangci-lint 2.14, config now actually enforced) |
| Unit tests | `go test -race ./...` | pass |
| P3 metadata-only | `make test-p3` | pass |
| **Real services** | `make test-integration` | **pass, 21.3s** — real Ray grades F; Jupyter, MLflow, Ollama detected; vLLM/Triton/Slurm correctly announce themselves as fixtures |
| Cross-compile matrix | `make build-all` | 4/4 platforms, `SHA256SUMS` written |
| Fuzzing | `make fuzz FUZZTIME=45s` | ~1.25M execs per parser, no crashes; nightly in CI at 150s |
| No placeholders | `git grep -nE '<YOUR NAME>\|TODO\|FIXME\|/tmp/claude-'` | clean |
| LICENSE holder | — | MIT, "Copyright (c) 2026 Karteek" |
| `.gitignore` | — | covers `bin/`, `report/`, `report-*/`, `snapshot*.json`, `/ray-guard` |
| Threat model read as an outsider | `docs/threat-model.md` | T6 corrected — see below |
| Action pins match their comments | GitHub tag API, all 7 pins | OK — every SHA is the commit its `# vX.Y.Z` comment names |
| Threat-model claims traced to code | T1–T7 | T4 corrected (the coverage list is capped at 10, not "every target"); the rest hold — path allowlist, CIDR hard ceiling `1<<18`, `html/template`, no-redirect, `gosec` enabled, `pull_request` trigger |
| Release instructions are runnable | `.github/workflows/release.yml` vs `SECURITY.md` | `.sig`/`.pem` names, upload globs, `cd bin && sha256sum -c` paths and `VERSION=` override all line up |

**What that outsider read changed.** T6 claimed "pinned actions". The workflows
used mutable major tags (`@v4`, `@v0`) on the actions that build and sign the
release — so the claim was false in the one place it mattered. All third-party
actions are now pinned to commit SHAs with Dependabot keeping them current, the
release token is scoped to the release job, and the release verifies its own
signatures before publishing. Separately, the `golangci-lint` job ran action v6
against a v2 config, which v6 cannot drive: the lint gate was reporting green
without enforcing the file it pointed at. **A CI run on these new pins has not
happened yet** — nothing here is authenticated to GitHub, so the first run after
push is the real confirmation. Watch it.

## ⚠️ Read this before tagging: `v0.1.0` is already pushed

`v0.1.0` exists on `origin` and points at `79d559f`, which predates both the
working lint configuration and the fix that stops `report.Write` exiting 0 on a
truncated report. Check what the tag push actually produced:

```bash
gh auth login                 # nothing in this workspace is authenticated
gh release list
gh run list --limit 10         # did the release workflow run, and did it pass?
```

**Do not move the tag.** A Sigstore-logged release is supposed to be immutable;
a repointed release tag is indistinguishable from an attack, and we are a
security product. Cut a new patch from `main` instead — the message is
pre-written in `docs/release-notes/v0.1.1.md`.

If a `v0.1.0` release *was* published, note in its body that v0.1.1 supersedes
it; do not delete it.

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

GitHub → Settings → General → Danger Zone → Change visibility → Public.

Then enable, in Settings → Code security:

- [ ] Private vulnerability reporting (SECURITY.md points people at it).
- [ ] Dependabot alerts and security updates.
- [ ] Secret scanning.

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
  --certificate ray-guard-linux-amd64.pem \
  --signature  ray-guard-linux-amd64.sig \
  --certificate-identity-regexp '^https://github.com/karteekp20/gpu-security/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ray-guard-linux-amd64

sha256sum -c SHA256SUMS
```

- [ ] `cosign verify-blob` succeeds against a freshly downloaded artifact.
      The workflow now runs this itself before publishing, so a green run is
      already evidence — but verify a *downloaded* artifact anyway, because
      that is the path a buyer takes.
- [ ] The checksums match.
- [ ] The binary runs: `./ray-guard-linux-amd64 -version`.

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
