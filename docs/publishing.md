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

**Done 2026-10-30.** The repo is public at
<https://github.com/karteekp20/gpu-security>.

Then enable, in Settings → Code security:

- [x] Dependabot alerts and security updates (`PUT /vulnerability-alerts` →
      204; `automated-security-fixes` → `enabled: true`). These are the two
      that also work while the repo is private.
- [x] Private vulnerability reporting (SECURITY.md points people at it).
      Returns **404 while the repo is private** — a visibility precondition,
      not a token scope. Enabled right after the flip.
- [x] Secret scanning, **and push protection**. `PATCH /repos` returns 422
      "not available for this repository" while private, for the same reason.

**Verified over the path a stranger takes** — `curl` with no authentication,
then `cosign verify-blob`: `Verified OK`, and the downloaded binary prints
`ray-guard v0.1.1`. Worth doing separately from the authenticated check: a
release can verify fine for its owner and still 404 for everyone else.

**Public surfaces checked 2026-10-31**, all 200 unauthenticated: repo root,
README, SECURITY.md, threat model, the assessment kit, the v0.1.1 release page,
`/security/policy`, and `/security/advisories/new` (so the private-reporting
route SECURITY.md promises actually exists). Every relative link in every
tracked `.md` resolves — 0 broken out of the whole tree — and the one external
link (GitHub's private-reporting doc) returns 200.

**One claim did not survive that read**, and it was mine from the day before:
the release body said "needs cosign 2.4+", which I had not tested with
anything. It now names the version actually used (v3.1.3) and marks 2.x as
untested inference. See the decision log. Published release bodies are
editable — the artifacts and the tag are not, which is the right split.

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

### v0.2.0 — cut 2026-10-31

Cut because the decks and the artifact had started contradicting each other:
`v0.1.1`'s report claims internet exposure on private address space, asserts
remote code execution from an HTTP 200, and grades a clean host `A+ 100/100`.
All three are corrected on `main`, and a demo deck that has to apologise for
its own output in front of a buyer is worse than no deck
(`docs/release-notes/v0.2.0.md`).

```bash
git tag -a v0.2.0 -F docs/release-notes/v0.2.0.md
git push origin v0.2.0
```

**Done 2026-10-31 — `v0.2.0` is published** (run `41172974493`, `isDraft:
false`, 12 assets: 4 binaries, 6 `.sigstore.json` bundles, `SHA256SUMS`,
`sbom.cyclonedx.json`). First release that went green on the first attempt.

- [x] Workflow run green, release published and not a draft.
- [x] `cosign verify-blob` succeeds against a **freshly downloaded** artifact.
      6/6 bundles `Verified OK` from a `gh release download` into an empty
      directory — the path a buyer takes, not the workflow's own self-check.
      Local client was **cosign v3.1.3**, which is the version every document
      named as tested, so this confirmed that claim and did **not** close the
      2.x gap. **The 2.x gap was closed separately on 2026-11-06** — see the
      entry below.
- [x] `sha256sum -c SHA256SUMS` passes (4/4 OK).
- [x] The downloaded binary prints `ray-guard v0.2.0`.
- [x] A scan of the demo stack still grades **F** with 21 findings, run with
      the **released** binary rather than a local build: `254` requested, `15`
      responded, `13` with findings, severities `3/6/6/3/3`, `tier: L1`, and no
      finding claiming internet exposure. Identical to `v0.1.1`'s numbers,
      which is the point — this release changed what the report *claims*, not
      what it *finds*, so the demo evidence slide survives the upgrade.

**Do not move this tag.** The `v0.1.1` re-push below was safe only because the
failed run created no release and the repo was private. Neither is true now.

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

### The cosign 2.x verification gap — closed 2026-11-06

Every document named **v3.1.3** as the only client we had actually run, and the
2026-10-31 decision row went further: it suspected a 2.x client might *not*
auto-detect our bundles, because cosign's own v2.6.0 examples pass
`--new-bundle-format` explicitly on verify. That suspicion was never tested,
and it sat in `SECURITY.md`, in the release workflow's body template and in two
sets of release notes as a caveat a buyer reads right before deciding whether
to trust us.

Measured, against the **published `v0.2.0`** downloaded fresh into an empty
directory:

```bash
cosign-2.4.3 verify-blob \
  --bundle ray-guard-linux-amd64.sigstore.json \
  --certificate-identity-regexp '^https://github.com/karteekp20/gpu-security/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ray-guard-linux-amd64
```

- **6/6 bundles `Verified OK` on cosign v2.4.3**, with the command exactly as
  published — **no `--new-bundle-format`**. The suspicion was wrong; 2.4.3
  auto-detects the bundle like 3.x does.
- `sha256sum -c SHA256SUMS`: 4/4 OK. The downloaded binary prints
  `ray-guard v0.2.0`.
- **Negative control.** One byte flipped at offset 4096 in a copy of the
  verified binary, same command: `invalid signature when validating ASN.1
  encoded signature`, exit 1. Without this, six passes only prove the command
  exits zero — not that it is checking anything.

What is **not** claimed: only **v2.4.3** was run. Support landed in v2.4.0, so
2.4.0–2.4.2 should behave the same, and that remains inference. Saying "2.4+"
on the strength of one point release is the exact error the 2026-10-31 row was
written about.

### v0.3.0 — **shipped** 2026-11-06, tag `v0.3.0` → `4dbccc9`

Cut because `v0.2.0` asserts a CVE it cannot support, and because the demo and
the download had diverged. Both were found by building the released tag and
running it against the live demo stack — not by reading the backlog, which
showed every item as Done.

| What `v0.2.0` does | Fixed on `main` by |
| :-- | :-- |
| Asserts **`CVE-2023-43654` against TorchServe 0.12.0**, which NVD bounds at `versionEndExcluding: 0.8.2` — refutable with `pip show torchserve` | PR #11, merged 2026-11-01 |
| Cannot draw the **exposure map** that `demo.md` beat 3c tells the operator to point at | PR #15 |
| No coverage bar, no grade band strip, no scan-parameters table | PRs #13, #14, #15 |
| No `parameters`, `responded`, `evidence` or `cves_unconfirmed` in `report.json` | PRs #11, #13, #15 |
| Re-resolves a hostname per dial, so a round-robin name is probed at a different machine port to port | PR #9 |

PR #16 and PR #17 were both **squash**-merged, so no branch commit exists on
`main` and the release is whatever `main`'s tip is once both have landed. A
bare `git tag -a v0.3.0` tags whatever `HEAD` happens to be at the moment it
runs, which is not something to find out afterwards: `cosign` logs the tag to a
public transparency log and `docs/publishing.md` says not to move a released
tag, so the first attempt is the only one. Read the commit, then name it:

```bash
git fetch origin
git rev-parse origin/main          # read it; do not assume
git tag -a v0.3.0 -F docs/release-notes/v0.3.0.md <that commit>
git push origin v0.3.0
```

The notes file is the tag message, so it must be the version on `main` —
including the cosign 2.4.3 result, which landed in PR #17.

**Why this is written as a rule and not as a SHA.** It was first written as a
SHA — "tag `97685b3`" — and that number was wrong within the hour: PR #17
moved the release notes forward, so `97685b3` would have tagged a release whose
notes did not match what shipped. The correction itself then missed its own
merge: it was pushed to the branch a moment after PR #17 was squash-merged, so
GitHub never attached it to the PR and `main` briefly carried the stale
instruction. A pinned SHA in a release procedure is stale the moment anything
else lands; resolving `origin/main` at the time of tagging cannot be.

Measured 2026-11-06 against the live stack, both binaries, same subnet:

- [x] `make demo-up` 7.5s warm; `make demo` 16.3s — both match the documented
      figures.
- [x] Detection identical across `v0.2.0` and `main`: `F`, `40/100`, 254
      requested, 15 responded, 13 with findings, severities `3/6/6/3/3`. This
      release changes what the report *says it knows*, not what it finds, so
      the demo evidence survives the upgrade.
- [x] All three charts render from `main` (`covbar`, `expstrip`, `bandstrip`);
      none render from `v0.2.0`.
- [x] `RG-TORCHSERVE-001` asserts no CVE on `main` and carries
      `cves_unconfirmed` with NVD's `0.8.2` verbatim.
- [x] Evidence bases across the 21 findings: 8 `service_api`, 6 `port_only`,
      4 `metrics_endpoint`, 2 `transport`, 1 `generic_path` (MLflow). **This
      corrected the 2026-11-05 decision row, which said 14 `service_api`** —
      the figures did not sum to 21 and nobody had added them up.
- [x] `go build ./...` and `go test ./...` green on the release branch.
- [x] `make lint`, `make test`, `make fuzz`, `make build-all`,
      `make test-integration` — all re-run on the merged `97685b3`, all green.
      `go vet` 0 issues; the race suite green across all six packages; the
      three fuzz targets (`FuzzExpandCIDR`, `FuzzApplyPortOverrides`,
      `FuzzNormalizeTarget`) clean at the 60s budget each; the four-platform
      matrix built with fresh `SHA256SUMS`; integration **15 passed, 0
      failed** against the real stack. The one skip is `TestRealTritonIsDetected`
      — `triton-real` is a 16GB image behind the `heavy` profile that CI does
      not run either, so the skip is the expected result and not a gap opened
      by this release.
- [x] **Post-tag, all measured 2026-11-06 after the tag push.** `Release`
      workflow green (run `42314035409`); the release is published and **not a
      draft**; 12 assets (6 artifacts + 6 bundles).
- [x] `cosign verify-blob` over a **freshly downloaded** `v0.3.0`, into an
      empty directory: **6/6 `Verified OK` on cosign v3.1.3 and 6/6 on cosign
      v2.4.3**, the same command for both, no `--new-bundle-format`. Negative
      control on 2.4.3 — one byte flipped at offset 4096 — rejected with
      `invalid signature … ASN.1`, exit 1. So the 2.x claim now rests on
      `v0.3.0` itself, not only on the `v0.2.0` run that first closed the gap.
- [x] `sha256sum -c SHA256SUMS`: 4/4 OK. The downloaded binary prints
      `ray-guard v0.3.0`.
- [x] **The withdrawn claim is actually gone from the artifact people
      download**, which is the entire reason this release exists. Scanned the
      live demo stack with the **released** `ray-guard-linux-amd64`: `F`,
      `40/100`, `tier: L1`, 254 requested, 15 responded, 21 findings,
      severities `3/6/6/3/3` — identical to `v0.2.0`, so detection did not
      move. `cves` asserts only `CVE-2023-48022`; **`CVE-2023-43654` now
      appears only under `cves_unconfirmed`**, with NVD's `0.8.2` verbatim and
      the `allowed_urls` check that settles it. Evidence bases 8 `service_api`,
      6 `port_only`, 4 `metrics_endpoint`, 2 `transport`, 1 `generic_path`,
      matching the corrected count. All three charts render; `report.html` is
      52K, still an email attachment. Scan took 16.0s against the documented
      16.3s.
- [x] **The tag push needed three attempts.** The first two were rejected with
      `Internal Server Error` and a GitHub request ID; the repo has no rulesets
      and no tag protection, and the status page was clean, so it was
      transient GitHub-side. Worth knowing before anyone concludes a rejected
      tag push means the tag is somehow already taken — `git ls-remote --tags
      origin` is the check.

**The standing step this release adds.** A fix merged to `main` does not
withdraw a claim from the artifact people download. G6 corrected the false CVE
on 2026-11-01 and the release carried it for five days afterwards, while
`docs/open-work.md` showed the item as **Done** — because "merged" and
"shipped" were never distinguished anywhere. So: **when a change alters what
the report claims — a rule title, a CVE assertion, a grade, a new report
section the kit then describes — either cut a release or write down in
`docs/open-work.md` that it is deliberately unreleased and why.** There is no
test for this; the gap is between a merge and a tag, where nothing runs.

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
