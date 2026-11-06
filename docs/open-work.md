# Open work — resume here

**Purpose.** This file exists so a session that starts cold can continue without
re-deriving context. It is the *live backlog*. It is **not** a source of truth:
`CLAUDE.md` §2 (binding principles) and §18 / `docs/decision-log.md` (decisions)
outrank anything written here. If this file and a decision row disagree, the
decision row wins and this file is wrong.

**Last updated:** 2026-11-06 · **`main` at the time:** `f8cc81d` · **branch:** `release_v0.3.0`

---

## 1. Where the project stands

- Phase 0 is **built, published and released**. Public at
  <https://github.com/karteekp20/gpu-security>, `v0.2.0` signed with Sigstore
  bundles and verified over an unauthenticated download.
- **`v0.3.0` is prepared and not tagged.** `v0.2.0` is five report features
  behind `main` and asserts **`CVE-2023-43654` against TorchServe 0.12.0**,
  which NVD bounds at `0.8.2` - the claim G6 removed on `main` on 2026-11-01
  and that stayed in the downloadable artifact for five days while every row
  here said **Done**. It also cannot draw the exposure map that `demo.md` beat
  3c tells the operator to point at. Notes are written
  (`docs/release-notes/v0.3.0.md`), preflight is measured
  (`docs/publishing.md`), the tag push is the owner's. See the 2026-11-06
  decision row.
- `main` is green on all four CI jobs (`build-and-test`, `golangci-lint`,
  `policy`, `supply-chain`). The nightly `Integration (real services)` job and
  its `fuzz` sibling are green.
- The Phase-1 **Rego rule library** is built (19 rules, both sentinel halves,
  113 OPA assertions, two generated differential corpora). This was a
  deliberate P2 relaxation on the owner's instruction — see the dated row for
  2026-10-31 in §18.
- **The §14 buyer gate is `0/3` assessments and `0/2` pay-and-name-it.**
  Nothing in the backlog below moves it. Only buyer conversations do.

### The one thing to re-read before building anything
§14's gate and P1/P2. Everything in §4 below is deliberately *not* built, and
the reason is not that it is hard.

---

## 2. Pending decisions — blocked on the owner, not on work

| # | Question | Status | Recommendation on file |
| :-- | :-- | :-- | :-- |
| Q1 | Final product name | **Open.** Not finalised as of 2026-10-31; external review used "Vrampart" but that is not a decision | Keep `[Platform]` and the `RG-` rule prefix as placeholders (§20). Do not bake a name into rule IDs |
| Q2 | One grade, or a grade per tier? | **Closed 2026-10-31 — per tier.** Implemented in PR #6 | Ceilings L1 → A, L2 → A, L3 → A+; grades reported as `<tier>: <grade>`; L1 alone yields a report and no credential. See the decision row |
| Q3 | Strengthen the Ray evidence path? | **Closed 2026-10-31** | Done, but via `/api/version`, not `/api/jobs/`. See the decision row |

---

## 3. The backlog

Numbering is from `/home/karteek/Documents/GPU/feedback_review_2026-10-31.md`,
which reviews two external feedback documents against the code. That file has
the full reasoning; this is the actionable residue. **G-items came from external
review; C-items are chart work; D-items are decisions to record.**

### Done

| # | Item | Where |
| :-- | :-- | :-- |
| C1 | **Coverage bar.** One stacked inline-SVG bar under a new **Coverage** heading: responded / no response / unresolved / probe failed / not probed, with a sentence above it carrying every count and a note below saying what it means for the grade. Counts, not percentages, and a 7-unit floor so a single unassessed host cannot round away (measured: 1-of-254 renders at 2.36 of 600 units without it). Drawing it surfaced a real contradiction — the multi-address case drew as **full coverage** on a run graded **N/A for incomplete coverage**, because the bar counts targets and the gap is in addresses; the note now carries that and the positive claim is withheld. Three line directions rather than dots/cross-hatch, which the greyscale render falsified | `internal/report/coverage.go`; decision row 2026-11-02 |
| G5 | **The report records the settings it was measured with.** `parameters` in the JSON (`probe_timeout`, `concurrency`, resolved `ports`, `cidr`/`targets_file`/`named_targets`/`buckets`) and a table under **Scope & method** in the HTML. The clamped-concurrency case is disclosed rather than silent — measured under `prlimit --nofile=128:128`, where `-concurrency 64` ran at 2 and the report previously said nothing. The target specification is barred from the benchmark snapshot by value and structurally; only the timeout travels, because an aggregate exposure rate is not comparable across different timeouts | `domain.ScanParams`; `clampConcurrency` + `probedPorts` in `cmd/ray-guard/main.go`; `portsProbed`/`scopeGiven` in `internal/report/report.go`; decision row 2026-11-02 |
| G4 | Ray identified by `/api/version`, not `/`; report separates observation from consequence; the "remote code execution" sentence is keyed to `codeExecutionRules` rather than to severity | PR #4, `8b32710`. Also eliminated a **false Critical**: a plain web server on 8265 answers 200 on `/` and 404 on the wildcard control, so it was graded **F / critical RG-RAY-001** and is now **A / Info** |
| G1 | **Four** titles no longer claim internet exposure (`RG-TRITON-002`, `RG-TORCHSERVE-002`, `RG-DCGM-001`, and `RG-BUCKET-001`, which the review did not name but had the same defect). Both Go and Rego sides, with a note in `detect.go` so the reason survives the next person who wants a punchier title. Verified by mutation: drifting one Rego title fails `TestGoAndRegoRuleSetsAgree` | PR #5 |
| G7 | The report prints a "How this grade was reached" table: first-match-wins rows from `gradeFor`, plus the ordering point — an observed finding stands even on an unfinished scan, but an unfinished scan can never earn a clean grade. HTML only; the matrix is static documentation, not data about a particular scan, so it is not duplicated into every JSON | PR #5 |
| G2 | **Grades are tier-scoped.** §10.0 rewritten: per-tier ceilings (L1 → A, L2 → A, L3 → A+), grades reported as `<tier>: <grade>`, credential issuance keyed to which tiers were assessed, L1 alone yields no credential. Scanner: clean L1 is `94/A`, `tier: "L1"` in the JSON, ceiling stated with the grade. `TestL1CannotEarnAPlus` sweeps all 32 severity combinations across completed/interrupted/degraded/unreached runs; verified by mutation | PR #6 |
| R1 | **Hostnames are resolved once and pinned.** Every probe for a name dials the one address resolution chose; the report states it (`probed at 10.0.0.5`, `addresses` in the JSON) while the name stays in the URL, `Host` header, SNI and the x509 check. A name with several addresses discloses the unprobed ones and cannot earn a clean grade (`N/A`, exit 7). Verified end to end against a container with two A records for one name; both halves mutation-tested; the address is kept out of the P9 snapshot by its own guard | PR #9, `8565f37`. Was not on this list — found by reading the resolver path after a question about hostname input |
| G6 | **CVE claims are split into asserted and unconfirmed.** `cves` now holds only CVEs whose condition is the condition we observed; a CVE whose advisory names a fixed version moves to `cves_unconfirmed` with that version and the check that settles it. `RG-TORCHSERVE-001` asserts none. Found a real false claim on the way: the demo stack asserted `CVE-2023-43654` against TorchServe **0.12.0**, which NVD records as fixed in **0.8.2**. The Ray pair was true only by luck - 2.9.0 is below 2.52.0, but the scanner never read the version. Grade unchanged (`F`, 40, 21 findings), which is the test that severity never rested on the CVE | PR #11, `23833c5` |
| G8 | §3 now reads "Agentless, read-only **active** probe … (one benign GET per check plus a wildcard control; nothing is installed and no credentials are used)" | PR #5 |
| G3 | **Findings carry the evidence they rest on.** An `evidence` block per finding: `level` (the data-model ladder, always `observed` at L1, stated so the ceiling is visible) and `basis` - `service_api` / `metrics_endpoint` / `generic_path` / `port_only` / `transport` - plus the `probed_path` that produced it, so a reader can re-run the request. The basis is **derived from the check table** rather than declared, so moving a probe path changes it and fails parity until the rule file agrees. Measured on the demo stack: 8 `service_api`, 6 `port_only`, 4 `metrics_endpoint`, 2 `transport`, and exactly **one `generic_path` - MLflow**, the case this row was written about. Grade unchanged (`F`, 40, 21 findings): evidence is new information, not a re-scoring. Five mutations, each failing its own gate. Also closes the two deck slides promising a confidence tier the report did not emit | `domain.Evidence`; `evidenceBasisForRule` in `detect.go`; all 19 `.rego` files; `internal/scan/evidence_test.go`; decision row 2026-11-05 |
| C2 | **Host × port exposure strip.** One row per host that *answered*, one column per port probed, each cell the worst finding there with a severity letter as well as a colour. Required a new `domain.ScanResult.Responded`: the responded host list was never retained, so a host that answered and raised nothing was unrecoverable from the artifact - a reporting gap independent of the chart. Three things the build surfaced: the bucket rule has no port, so without a port-less column a public bucket drew as a *clean* host; the label column truncated by bytes, which splits a rune and emits invalid UTF-8 into an SVG; and the `.sev` pill palette is not monotonic in greyscale, so printed, an **Info cell was as dark as a Critical one** on two of the negative controls. The new field also opened a P9 route that needed its own structural guard. Six mutations | `internal/report/exposure.go`; `domain.ScanResult.Responded`; `internal/report/exposure_test.go`; `TestSnapshotCarriesNoRespondedHostIdentity`; demo beat 3c in `docs/assessment/demo.md`; decision row 2026-11-05 |
| C3 | **Grade band strip**, above the G7 matrix. The §10.0 scale with the achieved band filled, the A+ band hatched and labelled *L3 only*, and every band carrying its letter and range as text. **No marker**: `gradeFor` returns a representative score per band, not a measurement, so a needle would claim precision we do not have. An inconclusive run draws nothing, because N/A is not a position on the scale. Moved the band table into code (`domain.GradeBands`), which closed a real gap - the ranges lived only in prose while `gradeFor` returned bare integers, so a score edited into the wrong band would have been silent. Two defects found by rendering: the achieved band drew unfilled (CSS specificity) and the A+ label was illegible over its hatch. Four mutations | `internal/report/gradeband.go`; `domain.GradeBands`/`BandFor`; `internal/report/gradeband_test.go`; decision row 2026-11-05 |
| D-1 | **Decided: no DCGM body parsing before the gate.** `RG-DCGM-001` keeps deciding from the status code and discarding the body. The analysis found the prerequisite nobody had written down - the P3 denylist is made of *content* words, and `GPUModel`, `GPUUUID`, `Pod`, `Namespace`, `Utilization` tripped none of them, so the suite would have waved through the very data that makes this sensitive. `forbiddenIdentityFieldNames` now bars tenant identity from every boundary type, with its own message, and ships **ahead** of any parser rather than alongside one | `test/metadata_only_test.go`; decision row 2026-11-05 |

### Open

The engineering backlog from the external review is empty: G3 and the three
charts are built, and D-1 was settled as a decision rather than built (see
Done). What is left is **release and surface work, not features**:

| # | Item | Notes |
| :-- | :-- | :-- |
| R-1 | **Push the `v0.3.0` tag.** `git tag -a v0.3.0 -F docs/release-notes/v0.3.0.md && git push origin v0.3.0` | Owner's call - publishing is outward-facing and a Sigstore-logged release is immutable. Re-run `make lint`, `make test-integration`, `make fuzz`, `make build-all` first; the post-tag checklist is in `docs/publishing.md` |
| ~~R-2~~ | ~~**Re-publish the plain-English page.**~~ **Done 2026-11-06** - the shareable page at <https://claude.ai/artifact/KCzRtCE2fAgL1xUWiZeNAF> is at version 3 and now walks the reader through **seven** report sections, with the exposure map as §3, the evidence basis in the findings section and the band strip in the grade section. Source and page state the same claims again | Was the drift the housekeeping note predicted, in the direction nobody watches for: the page *under*-promised, omitting the most persuasive thing in the report. **The page is private** - if it is going to a prospect it has to be shared from its own Share menu first |
| R-3 | **Decide `Demo_V1`'s fate.** `origin/Demo_V1` is at `94b78fd`, one commit behind `main`, and the missing commit is PR #15 - the charts | It drifted again within a day of being re-cut, which is the third time. The recommendation already on file is the right one: once `v0.3.0` is tagged, delete the branch and demo from the release tag, which cannot silently fall behind |

None of those three is a feature, and that is deliberate. This is the state P2
was written for: **the only thing that moves this project now is a buyer
conversation** - the §14 gate is still `0/3` and `0/2`, and
`docs/assessment/outreach.md` is written and unused. Do not restock this list
to pass the time; §4 below is the list of things that would be the wrong
answer, and it is still correct.

**"Done" here means merged, not shipped.** That distinction did not exist until
2026-11-06 and its absence is what let a withdrawn CVE claim stay in the
published release for five days. When a change alters what the report
*claims*, either cut a release or record here that it is deliberately
unreleased, and why.

### Chart constraints — non-negotiable, do not rediscover these

| Constraint | Why |
| :-- | :-- |
| **Inline SVG generated in Go** | No CDN, no external font, no JS library. `go.mod` has no `require` block; a chart library costs the zero-dependency air-gap binary (P4, §15) |
| **Must print** | `make report-pdf` renders through local Chrome. SVG prints; canvas/JS often does not |
| **Never colour alone** | §7.6 accessibility rule, and reports print to greyscale |
| **No implied precision** | No trend lines (one point in time; drift is Phase 2), no gauge needles on a provisional score |
| **Small** | The report is an email attachment |

---

## 4. Do NOT build this yet

All post-gate under P1/P2. Listed so a future session does not drift into them
because an external document asked:

GPU discovery (NVML / `nvidia-smi`), MIG, driver/firmware posture, Kubernetes
RBAC, runtime/eBPF, the correlation graph, the control plane, any of the three
web surfaces (§7.6 A/B/C), the signed credential.

**A specific trap.** External review proposed GPU discovery as "an intermediate
milestone" *before* buyer validation. That inverts P1/P2, and contradicts the
same document's own warning not to confuse development progress with commercial
validation. It is also a **tier error**: `nvidia-smi`/NVML needs on-node access,
which is **L2** by §3 — a DaemonSet and a CISO conversation, not an increment on
an agentless scanner.

---

## 5. Already satisfied — do not rebuild

The external review asked for 13 things that already existed; it had only
`CLAUDE.md` and one `report.json` to go on. Check here before starting anything
that sounds like a gap.

| Ask | Where it already lives |
| :-- | :-- |
| Unanswered hosts must read Unknown, not Secure | `N/A` grade + exit 7 (decision log, 2026-09-25) |
| Separate scan failures from filtered hosts | `host_state: probe-failed` vs `no-response` (2026-10-24) |
| Record the scan vantage | `ScanResult.ScannedFrom` |
| Duration and coverage counts | `started_at`/`completed_at`, four host-state counts |
| Don't close a finding when the host stops responding | `lib.host_reached` + a mandatory dark-host test per rule |
| Finding lifecycle incl. accepted-risk | `docs/data-model.md:227` |
| Lifecycle audit trail | `finding_events`, `docs/data-model.md:237` |
| Evidence hierarchy | `docs/data-model.md:300` — five levels. **Unused at L1; that is G3** |
| "Only verified closure counts" | §8 and the whole sentinel library |
| Automated tests for the metadata boundary | `test/metadata_only_test.go`, plus an import-boundary test: only `internal/scan` may import `net`/`net/http` |
| SOC 2 + ISO 27001 first | All 19 rules carry only `SOC2:*` / `ISO27001:*` |
| Not every 200 is the service | Wildcard control probe `/ray-guard-probe-404` (T8) |
| "Why should we trust you?" | `docs/assessment/objections.md` |
| Don't lead with PQC | Outreach leads with the CISA KEV listing |
| Interrupted scans must not grade clean | Exit 130; `Interrupted` gates clean grades |

---

## 6. How this project verifies things — keep doing this

These are habits that found real defects, not ceremony:

- **Mutate to prove a gate works.** Every new check in this repo was verified by
  breaking the thing it guards and watching it go red. A gate that has never
  failed is a gate nobody has tested.
- **Measure against real software, not mocks.** `make test-integration` runs real
  Ray, Jupyter, MLflow, Ollama, TorchServe and an nginx TLS proxy. Real
  TorchServe falsified two claims a rule was making; real Triton corrected a
  fix's first design; real Ray's `/api/version` was chosen over `/api/jobs/`
  only because the response was measured.
- **There is no OPA on the dev machine.** Rego behaviour is verified by the
  `policy` CI job. Local Go checks are structural by design, so a Rego change
  must not be called verified until that job is green.
- **Regenerate corpora deliberately:**
  `RAY_GUARD_UPDATE_CORPUS=1 go test ./internal/scan -run 'TestRegoCorpusIsCurrent|TestRegoClosureCorpusIsCurrent'`
- **Client output never enters this repo.** Reports go to `~/assessments/`
  (`docs/assessment/runbook.md`). The repo is public; `docs/validation-log.md`
  is generated from a private CSV and names a client only with written
  permission.
- **Never scan a prospect before written authorization** (`docs/assessment/outreach.md`, T7).

---

## 7. Housekeeping, when someone wants it

- **Two buyer-facing surfaces now restate the claims, so a claim that moves has
  to move in both.** `docs/assessment/plain-english.md` is the source of truth;
  the shareable page at <https://claude.ai/artifact/KCzRtCE2fAgL1xUWiZeNAF> is
  published from it. Both carry the grade table, the ceiling (`A`, no `A+`), the
  ~30s-per-/24 bound and the do-not-claim list, which is exactly the set most
  likely to drift. Add them to the sweep whenever a rule title, a grade
  threshold or a limit changes — the rev-9 pattern of a document promising what
  the code does not do, with a page that a client may have already forwarded.

- ~~Merged branches not yet deleted~~ — done 2026-10-31: all nine merged
  branches deleted locally and on the remote (`rego_rule`,
  `rego_rule_differential`, `rego_rule_closures`, `ray_evidence_path`,
  `report_claims`, `tier_grades`, `release_v0.2.0`, `v020_preflight`,
  `pinned_resolution`). `Demo_V1` is a deliberate snapshot and was kept; it and
  `main` are the only branches left.
- **`Demo_V1` was 27 commits stale — re-cut locally 2026-11-05, remote still
  pending.** It sat at `a66fbdb` with no commits of its own, predating the Rego
  library, the coverage bar, the scan-parameters table, the pinned-resolution
  fix *and the asserted/unconfirmed CVE split* — so demoing from it would have
  put the **false `CVE-2023-43654` claim against TorchServe 0.12.0 back on
  screen**, the one an operator refutes with `pip show torchserve`, which is
  why G6 exists. A snapshot branch silently a month behind is worse than no
  snapshot, because its name says "this is the demo".

  Moved to `main` (`94b78fd`); nothing was lost, since `a66fbdb` is an ancestor
  of `main`. Force-pushed to `origin` by the owner on 2026-11-05 — **and it was
  stale again within the day.** `origin/Demo_V1` now sits at `94b78fd`, one
  commit behind `main`, and the missing commit is PR #15: the evidence block and
  the two charts, including the exposure map the demo script now tells the
  operator to point at. That is three drifts in a row, which settles the
  question this entry kept deferring — **delete the branch once `v0.3.0` is
  tagged and demo from the release tag**, which cannot silently fall behind.
  Tracked as R-3 above.
- ~~A `v0.1.0` **draft** release~~ — deleted 2026-10-31. It was never published,
  was superseded by `v0.1.1`, and its 18 assets were signed in the **old
  detached `.sig`/`.pem` format**, which a current cosign cannot verify at all
  (see the 2026-10-31 bundle-format row in §18) — so publishing it by accident
  would have shipped artifacts with unverifiable signatures. The `v0.1.0` **tag**
  is still pushed and was deliberately left alone: a tag is a point in history,
  and `docs/publishing.md` says not to touch released tags.
- `.claude/settings.local.json` still pre-approves the repo visibility flip,
  which has nothing left to use it for.
- **Open verification gap needing a human:** whether a buyer on cosign 2.x can
  verify our `v0.3` Sigstore bundles. `v0.2.0` was verified end to end with the
  locally installed **cosign v3.1.3** (6/6 bundles, 4/4 checksums), which confirms
  the tested claim but says nothing about 2.x. Closing it means one run of
  `cosign v2.4.3 verify-blob --bundle` against a `v0.2.0` artifact. It matters
  because the demo talk track tells the prospect to verify the release themselves,
  so a 2.x client failing is a trust step failing live in the room.
