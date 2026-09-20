# Publishing checklist

The remaining §14 Phase-0 item is "Publish OSS on GitHub". Everything below is
**manual and deliberate** — publishing is outward-facing and hard to undo, so
it is written down as a checklist rather than left to recollection.

Repo: `git@github.com:karteekp20/gpu-security.git`

## Before making the repo public

- [ ] `make lint && make test && make test-p3` all pass.
- [ ] `make test-integration` passes — the detections work against real Ray,
      not just mocks. This is the one that matters before anyone runs it in
      anger.
- [ ] No placeholders or private paths in tracked files:
      ```bash
      git grep -nE '<YOUR NAME>|TODO|FIXME|/tmp/claude-' -- . ':!docs/publishing.md'
      ```
- [ ] `LICENSE` names the right copyright holder.
- [ ] `.gitignore` covers `bin/`, `report/`, and any snapshot output — no scan
      results or binaries in the history.
- [ ] Read `docs/threat-model.md` as an outsider would. It is the document a
      CISO will actually open, and publishing is when it starts being read by
      people who did not write it.
- [ ] Decide on the repo description and topics (`gpu`, `security`, `ray`,
      `ai-infrastructure`, `cspm`) — this is most of how it gets found.

## Making it public

GitHub → Settings → General → Danger Zone → Change visibility → Public.

Then enable, in Settings → Code security:

- [ ] Private vulnerability reporting (SECURITY.md points people at it).
- [ ] Dependabot alerts and security updates.
- [ ] Secret scanning.

## Cutting the first release

The release workflow triggers on a `v*` tag and does the rest: builds the
static matrix, generates the SBOM, cosign-signs every artifact, and publishes.

```bash
git tag -a v0.1.0 -m "ray-guard v0.1.0 — L1 agentless scanner"
git push origin v0.1.0
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
