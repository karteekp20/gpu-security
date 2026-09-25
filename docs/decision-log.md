# Decision Log

Append-only mirror of CLAUDE.md §18, plus implementation-level decisions that
are too fine-grained for the constitution but still shouldn't be silently
reversed.

**Never edit a row.** To change a decision, add a new dated row and name what
it supersedes.

## Architecture decisions (mirror of CLAUDE.md §18)

| Date | Decision | Rationale | Supersedes |
| :-- | :-- | :-- | :-- |
| 2026-09-20 | Modular monolith control plane, not microservices | Lean team, unknown seams, air-gap simplicity (§5) | — |
| 2026-09-20 | NATS JetStream for the ingestion bus | Air-gap friendly, simpler than Kafka | — |
| 2026-09-20 | Polyglot persistence: PG + Neo4j + Timescale + object + Redis | Data-shape fit (§6) | — |
| 2026-09-20 | Graph MAY start on Apache AGE, target Neo4j | Reduce early ops; team knows Neo4j | — |
| 2026-09-20 | Go for scanner/agent/control plane; Python for compliance/AI; Rust for eBPF + PQC | Single-binary/air-gap + team strengths | — |
| 2026-09-20 | Hybrid classical+PQC signatures on credentials from v1 | Quantum-safe differentiator = moat #2 | — |
| 2026-09-20 | Defer L3 (eBPF/DPU) until paying-customer demand | P1 — difficulty inverted from value | — |
| 2026-09-20 (rev 2) | Every Rego rule requires `finding_condition` + `verification_condition` | Verified closures underpin the signed credential (§8) | — |
| 2026-09-20 (rev 2) | Split CC-mode verification: L2 observes claimed state, L3 proves it | Keeps L2 low-friction/read-only (§3, §9) | — |
| 2026-09-20 (rev 2) | Formal signed air-gap update manifest in `/deploy/airgap` | Prevent ad-hoc update mechanisms; reuse §12 signing (§13) | — |
| 2026-09-20 (rev 2) | AGE→Neo4j trigger: 4-hop latency >500ms OR cross-tenant graphs | Cross-tenant blast-radius is what AGE handles worst (§6.2) | — |
| 2026-09-20 (rev 2) | Phase-0 gate = ≥3 buyer-led assessments + ≥2 pay-and-name-it intents | Vanity metrics don't test P2 (§14) | prior stars/count gate |
| 2026-09-20 (rev 2) | Add §14.1 Future Horizon (H1–H6) with trap warnings on H5/H6 | Visibility without MVP bloat | — |
| 2026-09-20 (rev 3) | Adopt the Posture Grading Matrix (A+/A/B/C/F → credential status) | Ties score bands to issue/revoke (§10.0) | — |
| 2026-09-20 (rev 3) | Pin concrete libs (circl, go-nvml, OPA SDK, cosign); widen to Slurm + RoCE v2 | Coding-ready; RoCE matters for non-IB neoclouds | — |
| 2026-09-20 (rev 3) | Merge external draft's concreteness but preserve P2, P3, P9, §5.3/5.4, §14.1 | Those are the disciplines that matter most | — |
| 2026-09-20 (rev 4) | Web is THREE surfaces + the Phase-0 report; public trust page ships Phase 1 | The public trust page is the revenue surface (§7.6) | — |
| 2026-09-20 (rev 5) | Document the tenant-side scan vantage + two-buyer model | Prevents building a separate tenant scanner (§1.5) | — |

## Implementation decisions (Phase 0)

| Date | Decision | Rationale | Supersedes |
| :-- | :-- | :-- | :-- |
| 2026-09-20 | Keep scanner packages as `internal/scan` + `internal/domain` rather than the `internal/probe` / `internal/detect` / `pkg/domain` split suggested in §16 | At Phase-0 size, probing and detection are one bounded concern and splitting them buys nothing. `pkg/domain` implies a public API we do not offer yet; `internal/` keeps it unexported until the control plane needs to share it. Recorded so contributors and agents stop re-litigating it against §16. Revisit when the L2 collector lands and genuinely shares types. | — |
| 2026-09-20 | Probe per **port**, not per check; attribute the service from which health path returns 2xx | vLLM and Triton both default to 8000. Probing per check dialed shared ports twice and made a host with filtered ports cost `timeout × len(checks)`. Per-port probing fixed both, and 2xx-on-own-health-path is a reliable discriminator. | — |
| 2026-09-20 | No Go PDF library; the HTML report carries `@media print` rules and `make report-pdf` shells out to headless Chrome | A PDF dependency would cost the zero-dependency static binary, which is what makes ray-guard air-gap-deployable and handable to a security lead (§15, P4). Chrome is optional and local; the scanner never needs it. | — |
| 2026-09-20 | The P9 benchmark snapshot is a **local file with zero network egress**, not opt-in telemetry | Network telemetry would need a receiving endpoint that does not exist, and would give the scanner a phone-home surface to justify in every CISO conversation — for no benefit before there are buyers. A local file the operator chooses to send preserves the flywheel and keeps P4 true by construction. Revisit if volume makes manual collection the bottleneck. | — |
| 2026-09-20 | Host IDs in the snapshot use a **single-use random salt** per snapshot | Makes host identifiers unlinkable across snapshots. Costs longitudinal tracking, which an aggregate benchmark index does not need. | — |
| 2026-09-20 | Grade thresholds stay provisional and are stated as such in the report footer | Publishing a confident grade we have not validated with buyers would be the exact "sophistication ahead of demand" failure P2 exists to prevent (§10.0). | — |
| 2026-09-20 | An open port we cannot identify is reported at Info (`RG-EXPOSURE-001`), never guessed at | Misattributing a service is worse than admitting we do not know. A false "Triton exposed" on a Neocloud's report is how the tool loses credibility in the room. | — |
| 2026-09-20 | Exit codes encode the worst severity found (0 clean, 3–6 by severity, 1 runtime, 2 usage) | Lets a tenant gate their own CI on posture, which is how the tenant-side vantage (§1.5) actually gets used. | — |
| 2026-09-20 | The P3 suite lives in `/test` as a separate CI step, and its guards were verified to fail when a violation was introduced | P3 is existential; a guard nobody has seen fail is not a guard. | — |
| 2026-09-20 | Integration suite runs Ray, Jupyter, MLflow and Ollama as **real containers**; vLLM and Triton stay **labelled fixtures** | Those two ship GPU-bound, multi-gigabyte images that cannot run on a CPU-only host. Dressing a mock up as a real service would reproduce the exact blind spot the suite exists to remove, so the split is stated in the compose file, the README, and the test output. Promote them if a GPU host becomes available. | — |
| 2026-09-20 | The TLS handshake gets its own bounded deadline, separate from `-timeout` | A peer that speaks TLS answers a ClientHello within a round trip; one that does not never will. Real Jupyter and MLflow accept the connection and wait silently for an HTTP request, so every open plaintext port cost the full probe timeout. Found only by running against real services — Ray rejects a ClientHello in ~1ms, so no mock exposed it. Cut the integration suite 28s→18s. | — |
| 2026-09-20 | Integration tests are build-tagged and run nightly/on-demand, never on `pull_request` | Multi-gigabyte image pulls on every push would tax normal work for a signal that changes rarely. The nightly run is what catches upstream image drift. | — |
| 2026-09-25 | A scan that reached nothing grades `N/A` (inconclusive), never `A+`, and exits 7 | **The false all-clear was the most damaging bug the product could have.** An unresolvable hostname, a dark /24, and a genuinely clean host all produced an identical confident "A+ — No exposure was observed". A typo in front of a buyer, or a DNS change in a tenant's pipeline, would have reported perfect security forever. Host state is now tracked (`responded` / `no-response` / `unresolved`), clean grades require at least one host that answered, and partial coverage is disclosed on the report. | prior grading, which ignored reachability |
| 2026-09-25 | Only `ECONNREFUSED` counts as proof a host is alive | "No route to host" and "host unreachable" also return promptly rather than timing out, so classifying every non-timeout error as "closed" let an empty subnet masquerade as a clean one. Found by the integration suite, which caught the same address reporting differently across two subtests once ARP had failed — a case no unit test would have produced. | — |
| 2026-09-25 | Renamed `HostsNoResponse` → `HostsUnanswered` rather than relaxing the P3 field-name guard | The guard flagged its own false positive (a count field containing "response"). A blunt guard that occasionally costs a rename is worth more than a clever one that might miss a real payload field. Weakening it to accommodate our own naming would have been the wrong precedent. | — |
