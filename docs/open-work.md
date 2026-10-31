# Open work — resume here

**Purpose.** This file exists so a session that starts cold can continue without
re-deriving context. It is the *live backlog*. It is **not** a source of truth:
`CLAUDE.md` §2 (binding principles) and §18 / `docs/decision-log.md` (decisions)
outrank anything written here. If this file and a decision row disagree, the
decision row wins and this file is wrong.

**Last updated:** 2026-10-31 · **`main` at the time:** `8b32710`

---

## 1. Where the project stands

- Phase 0 is **built, published and released**. Public at
  <https://github.com/karteekp20/gpu-security>, `v0.1.1` signed with Sigstore
  bundles and verified over an unauthenticated download.
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
| Q2 | One grade, or a grade per tier? | **Open — this blocks G2, the biggest item** | **Per-tier for the Phase-1 credential; cap L1 at `A` now.** Zero findings → `94/A` (top of §10.0's A band); `A+` (95–100) stays reserved for attested tiers; label output "L1 grade". Rejected: one grade plus a prose qualifier — that is what exists today and is exactly what got flagged |
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
| G4 | Ray identified by `/api/version`, not `/`; report separates observation from consequence; the "remote code execution" sentence is keyed to `codeExecutionRules` rather than to severity | PR #4, `8b32710`. Also eliminated a **false Critical**: a plain web server on 8265 answers 200 on `/` and 404 on the wildcard control, so it was graded **F / critical RG-RAY-001** and is now **A / Info** |

### Open — no decision needed, safe to start

| # | Item | Anchors | Acceptance criterion |
| :-- | :-- | :-- | :-- |
| **G1** | Three rule titles claim internet exposure on private address space. The scanner cannot know internet exposure; it knows reachability from one vantage (which is why `scanned_from` exists). It is in the **title** — the most-read string in the report | `internal/scan/detect.go:30` `:55` `:65`; mirrored in `policies/orchestrator/triton_metrics.rego`, `torchserve_metrics.rego`, `dcgm_exporter.rego` | No output string asserts internet exposure. Parity test and both differential corpora green (titles are parity-enforced across Go and Rego, so **both sides plus the corpora** must change together) |
| **G7** | The grade matrix is not in the report. `grade_reason` names the driving finding, but the mapping (`Critical→40/F`, `High→60/C`, `Medium→78/B`, `Low\|Info→90/A`, none→`100/A+`, unreached\|incomplete→`N/A`) appears nowhere a buyer can see | `internal/domain/types.go:280` is the source of truth; render in `internal/report/report.go` | A reader can reconstruct the score from the page. Do **not** adopt the reviewer's richer model (exploitability, asset criticality, business impact) — every input needs data L1 does not have |
| **G8** | §3 calls L1 "Passive". It is an active, benign, read-only probe: one GET per check plus a wildcard control | `CLAUDE.md:95` | Wording is "agentless, read-only active assessment" |
| **G5** | The report cannot be reproduced from itself. `-ports`, `-cidr`, `-timeout`, `-concurrency` are absent. A host recorded `no-response` at `-timeout 1s` is a different claim from the same host at 5s, and the reader cannot tell which they hold | `domain.Run` / `ScanResult` at `internal/domain/types.go:214`; flags in `cmd/ray-guard/main.go` | A reader can reproduce the scan from the report alone. Already present and **not** to be re-added: `scanned_from`, duration, coverage counts, `probe_errors`, probe-failed vs filtered |
| **G6** | Half done. The report narrative now says the version was not determined and marks `CVE-2025-62593` applicable-if-vulnerable, but `detect.go:21` still attaches both CVEs to the finding and the JSON still emits `"cves"` unqualified, so a machine consumer sees an unqualified claim | `internal/scan/detect.go:21`; `domain.Finding.CVEs` | A version-dependent CVE is not asserted about a host whose version is unknown, in **JSON as well as prose**. `CVE-2023-48022` stays as-is: no fixed version exists, so reachability is the whole control |

### Open — blocked on Q2

| # | Item | Anchors |
| :-- | :-- | :-- |
| **G2** | An L1-only scan can print **A+ (100/100)**, while §10.0 reserves A+ for L3-verified hardware attestation ("Issuable — Gold"). Today the report footer scopes it honestly. Once the Phase-1 credential is issued off the grade, this path signs a Gold attestation for hardware never examined — structurally the dark-host closure hazard one layer up | `internal/domain/types.go:293`; the clean-grade reason at `:333`; `CLAUDE.md §10.0`. Needs a dated row superseding §10.0 |

### Open — larger, and worth doing in this order

| # | Item | Notes |
| :-- | :-- | :-- |
| **G3** | No evidence level on findings, **although the ladder already exists** at `docs/data-model.md:300` (`observed`, `policy_compliant`, `verified_config`, `cryptographically_attested`, `runtime_validated` — five levels, finer than the reviewer's three). The shipping artifact ignores it. The concrete reason it matters: probe paths differ in evidentiary strength and nothing records it. `/v1/models` (vLLM), `/models` (TorchServe mgmt), `/api` (Jupyter), `/api/tags` (Ollama), `/get_model_info` (SGLang) are the service's **own API**; `/` (MLflow) is **only the root page**. Ray was the worst case and is fixed (G4). Touches `domain.Finding`, `detect.go`, all 19 `.rego` files and the parity test |
| **C1** | **Coverage bar** (inline SVG). Highest-value chart: `254 requested → 15 responded → 239 silent`. Silent hosts *look* like safety and are actually ignorance. One stacked, labelled bar — responded / no-response / unresolved / probe-failed |
| **C2** | **Host × port exposure strip** (inline SVG). The frame a security lead photographs, and it renders the negative controls — `.40` and `.42` quiet beside `.10` and `.22` answers "does this scream at everything?" instead of arguing it (demo beat 3c) |
| **C3** | **Grade band strip** with the G7 matrix under it |
| **D-1** | Record a decision on **DCGM body parsing**. We detect the exporter on 9400 and discard the body. Its metrics carry GPU model, UUID, utilisation **and pod/namespace labels** — so a bounded agentless GPU inventory is reachable with no agent, which is what the external review's "Stage 2" wants and cannot otherwise have. But it would be the first response body the scanner parses (today every rule decides from the status code alone; the bucket rule discards the body unparsed because object keys are customer data). Needs a dated row and an explicit P3 analysis **before** anyone writes a parser. Instinct on file: worth doing eventually, not before the gate, and only with a hard allowlist of metric names and labels |

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

- Merged branches not yet deleted: `rego_rule`, `rego_rule_differential`,
  `rego_rule_closures`, `ray_evidence_path`. `Demo_V1` is a deliberate snapshot — keep.
- A `v0.1.0` **draft** release from 2026-09-26 was never published and is
  superseded by `v0.1.1`.
- `.claude/settings.local.json` still pre-approves the repo visibility flip,
  which has nothing left to use it for.
- **Open verification gap needing a human:** whether a buyer on cosign 2.x can
  verify our `v0.3` Sigstore bundles. Every document names v3.1.3 as the tested
  version and labels 2.x as untested inference. Closing it means running
  `cosign v2.4.3 verify-blob --bundle` against a `v0.1.1` artifact; downloading
  and running a third-party binary was refused in-session, correctly.
