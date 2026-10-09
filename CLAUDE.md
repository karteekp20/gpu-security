# CLAUDE.md — AI Infrastructure Trust & Posture Platform

> **Repo / working name:** `gpu-security` · **Scanner CLI:** `ray-guard` · **Platform / portal brand & trust badge:** deliberately deferred until Phase 1 — buyers often name it better. `[Platform]` in this doc and the `RG-` rule-ID prefix are placeholders standing in for that deferred brand.
> **Purpose of this file:** Single source of truth for the project. Read this fully before writing any code, making any architecture decision, or adding any dependency. It encodes not just *what* to build but *what not to build yet* and *why*. Both humans and coding agents (Claude Code) should treat the "Non-Negotiable Principles" section as binding constraints, not suggestions.
> **Owner:** Karteek
> **Last updated:** 2026-10-10 (rev 9)
> **Status:** Pre-MVP (Wedge stage) — **Phase-0 build complete; blocked on the §14 buyer gate (0/3 assessments, 0/2 pay-and-name-it). See `docs/validation-log.md`.**
>
> **rev 9 changelog:** no scope change — one §18 row from reading the buyer-facing surface as a skeptic, which was the last open item on the publishing checklist. The report footer cited `CLAUDE.md §10.0` to a buyer who will never see that file; two documents promised a /24 in "well under a minute" where the code bounds it at ~8 waves × the probe timeout (~30s at the default, measured 16.3s at 2s); and `objections.md` claimed we had deliberately broken the P3 suite with nothing in the repo to show. All three corrected. A second pass traced every threat-model control to the code (T4's "named list of every target" was capped at ten; the rest hold, and all seven action pins match their version comments) and turned the no-egress claim into a test. A third pass hardened the wedge itself (P1's "production polish"): output paths are now checked before a scan runs rather than after one is thrown away, and the two parsers that read operator input are fuzzed. **The §14 gate is still 0/3 and 0/2.**
> **rev 8 changelog:** no scope change — three §18 rows recording supply-chain and CI corrections found while making the repo publish-ready. The lint gate could not enforce its own config (`golangci-lint-action` v6 cannot drive a v2 config), and the threat model's T6 claim of "pinned actions" was not true of the workflows — they used mutable major tags on the actions that build and sign releases. Both fixed; the release now verifies its own signatures before publishing. **The §14 gate is still 0/3 and 0/2.**
> **rev 7 changelog:** no scope change — two §18 rows recording a correctness fix. The scanner could report a confident `A+` for targets it never reached (unresolvable name, dark subnet), which is a false all-clear and the worst thing a security tool can say. Scans that reach nothing now grade `N/A` and exit 7. Also added the assessment kit (`docs/assessment/`), which is how the §14 gate actually gets run.
> **rev 6 changelog:** ticked the §14 Phase-0 build items that are actually done and split the publish/telemetry item (telemetry shipped as a local-only snapshot; publishing still open) — the checklist claimed nothing was built while the wedge was finished. Appended §18 rows for the implementation decisions made building it. **The gate itself remains unticked, and that is the point:** Phase 1 does not start because the code is ready, it starts when buyers say yes.
> **rev 5 changelog:** added §1.5 (two scan vantages / two buyers) documenting that the same `ray-guard` serves both the Neocloud (landlord) and the tenant (renter) — a clarification, not new build scope. Continuous monitoring was already covered (Phase 2 / §9) and is unchanged.
> **rev 4 changelog:** documented the web surfaces (§7.6) — the file previously described the backend in depth but the frontend was a single diagram box. Establishes that this is *three* surfaces (operator console, public trust page, independent verifier) plus the standalone Phase-0 report, and pins the phasing (public trust page ships in Phase 1, not later). Enhanced §14 Phase-0/1 accordingly.
> **rev 3 changelog:** merged the concrete-implementation additions from an external engineering draft onto this file's principled spine — added the Posture Grading Matrix (§10.0), pinned key libraries (§15), a worked Rego sentinel example + NATS subject taxonomy (§8, §6.6), exact L2 securityContext and NVML call (§9, §12), Prometheus metrics + Makefile/coverage standards (§17), and widened scope to Slurm + RoCE v2 (§1.2, §3, §8). **Explicitly preserved from rev 2 (the external draft dropped these):** P2 validate-before-build, P3 metadata-only, P9 benchmark flywheel, §5.3/§5.4 extraction seams, and §14.1 Future Horizon with the H5/H6 trap-warnings.
> **rev 2 changelog:** verification sentinels (§8); CC-mode tier split (§3, §9); signed air-gap manifest (§13, §16); AGE→Neo4j trigger (§6.2); buyer-led Phase-0 gate (§14); §14.1 Future Horizon backlog.

---

## 0. How to use this document

- If you are a **coding agent**, load this entire file into context at the start of every session. Do not violate Section 2 (Non-Negotiable Principles). When a task conflicts with a principle, stop and flag it.
- If you are a **human contributor**, Sections 1–3 give you the "why," Sections 4–13 give you the "how," Section 14 gives you the "build order," Section 14.1 is the explicitly-deferred backlog.
- **Section 18 (Decision Log)** is append-only. Every material architecture decision gets an entry with date + rationale. Never silently reverse a decision — add a new dated entry that supersedes the old one.

---

## 1. Mission & Positioning

### 1.1 What we are
The **neutral, cross-vendor trust and security-posture standard for AI compute infrastructure** — bare-metal GPU clusters, Neoclouds, and AI runtime frameworks.

We are **not** "another GPU vulnerability scanner." The scanner is our *wedge*, not our *product*. The product is the trust attestation a Neocloud hands its customers to close deals, and the continuous posture assurance a regulated enterprise needs to run private models on rented GPUs.

### 1.2 The blind spot we exploit
Traditional CSPM/CNAPP and AI-SPM tools (Wiz, Prisma AIRS, Orca, CrowdStrike, Microsoft Defender) audit **cloud metadata, models, data, and agents via cloud APIs**. They stop at the hardware boundary. They are blind to:

1. **AI orchestrator exposure / RCE** — Ray (dashboard 8265), vLLM (8000), Triton (8001), Slurm (slurmctld 6817), MLflow, Ollama, Jupyter exposed and unauthenticated (see ShadowRay: CVE-2023-48022, CVE-2025-62593).
2. **High-speed fabric isolation** — InfiniBand Partition Keys (P_Keys), M_Keys, SA_Keys, RDMA protection domains (InfiniBand *and* RoCE v2 over Ethernet), NVLink isolation.
3. **GPU hardware & DPU attestation** — secure boot, firmware integrity, NVML state, NVIDIA BlueField DPU (DICE) attestation.
4. **VRAM / confidential-computing posture** — whether CC mode is actually enabled, attested, and *staying* enabled (drift).

### 1.3 Our three structural moats (things incumbents cannot easily copy)
1. **Neutrality.** Wiz is Google-owned; a Neocloud competing with GCP cannot hand its buyers a Google-owned attestation. We are the independent third party. This is a *positioning* moat.
2. **Cross-vendor, cryptographically-verifiable trust credential.** NVIDIA/Intel/AMD produce raw, per-vendor attestation evidence. Nobody normalizes it across vendors into one portable, compliance-mapped, tamper-evident, **PQC-signed** credential. This is a *technical + crypto* moat.
3. **Cross-layer correlation graph.** Orchestrator exposure ↔ fabric misconfig ↔ hardware attestation ↔ blast radius, rendered as an attack path across tenants. A port scanner can never show this. This is a *data + engineering* moat.

### 1.4 What success looks like (and the honest ceiling)
- **Realistic prize:** a strong specialist business or a $150M–$700M strategic acquisition (CNAPP incumbent, Neocloud-tooling player, NVIDIA-adjacent, or confidential-computing vendor). Not an obvious standalone unicorn. Build accordingly — clean IP boundaries, clean integration surfaces.

### 1.5 Two scan vantages, one tool, two buyers
The same `ray-guard` scanner runs from **either side** of a GPU rental. This is a documentation clarification, **not** new build scope — it is one tool, one codebase, two vantage points:
- **Neocloud-side (the landlord):** the provider scans its own environment; the report is sales-enablement it hands to prospective tenants (→ the "Verified by [Platform]" trust page).
- **Tenant-side (the renter):** a regulated enterprise renting GPU capacity runs the same scanner against *its own rented slice* to produce audit evidence for *its own* auditors. Note the difference from a hyperscaler CSPM like Wiz: a tenant renting bare-metal/Kubernetes GPU capacity usually has **no cloud management API to connect to**, so tenant-side scanning runs from inside, against the hosts/services the tenant controls — not via an account API.

Often the tenant's demand ("prove this is safe before we run our models here") is what pushes the Neocloud to buy. So include a regulated renter alongside Neoclouds in the Phase-0 buyer conversations; which side leans in harder tells you the beachhead.

**Scope note (be honest with buyers):** the tenant-side L1 scan covers the *renter's own exposure*. Deep cross-tenant *isolation proof* from the tenant vantage — "can another tenant actually reach me?" — needs the L2/L3 fabric/hardware checks and is a later stage, not something a Phase-0 scan can prove.

---

## 2. Non-Negotiable Principles (BINDING CONSTRAINTS)

> These exist because the biggest risk to this project is **building sophistication ahead of demand**. Every one of these was hard-won. Do not relax them without a dated Decision Log entry.

**P1 — Wedge first. The difficulty is inverted from the value ladder.**
Build Level 1 (agentless scanner) to *production polish* before writing a single line of Level 3 (eBPF/DPU). The easy tier wins clients; the hard tier is a moat you *earn* on a paying customer's demand. **Do not build the eBPF/DPU engine until a paying or committed design-partner customer requires it.**

**P2 — Validate before you build.** No large build precedes a real buyer conversation. The decision gate for the whole company is: *will a Neocloud pay for the neutral trust report and ask for it by name?* Nothing about elegant architecture substitutes for that answer.

**P3 — Metadata only. Zero payload access, always.** We NEVER read, store, or transmit customer model weights, prompts, training data, or inference payloads. Collectors anonymize and strip at the edge. This is a hard guarantee we sell on; a single violation is existential. Enforce it in code and in tests.

**P4 — Air-gap / sovereign from day one.** Every component must be deployable fully offline, single-tenant, no phone-home. This is not a v2 feature. It is our disqualifier-of-incumbents (all SaaS, all US-owned). If a design choice breaks air-gapped operation, it is wrong.

**P5 — Modular monolith until proven otherwise.** Do NOT start with microservices. See Section 5. Draw clean module seams; extract to services only when a specific scaling or team-boundary pressure demands it, with a Decision Log entry.

**P6 — The rules/graph/compliance library is the crown jewel, not the probes.** Probes use open tooling (NVML, `saquery`, `ibnetdiscover`, eBPF, DOCA, `nv-attestation-sdk`). Never invest moat energy in the probes. Invest it in the correlation graph, the rule library, and the compliance packaging.

**P7 — Sovereign is a candidate beachhead, not an afterthought.** Architect so a defence/government air-gapped single-tenant deployment is a first-class SKU, not a painful fork.

**P8 — We are a security product; we are a high-value target.** Secure the platform itself to a higher bar than we hold customers to. Signed releases, SBOM on every build, least privilege, short-lived credentials, supply-chain hardening. See Section 12.

**P9 — Every scan feeds the anonymized benchmark index.** The data flywheel (an anonymized "State of Neocloud Security" dataset) is a first-class product output, not an afterthought. Design the data pipeline to produce it from day one, with strict anonymization.

**P10 — Read-only, low-friction is a sales guarantee, not just a default.** L1 and L2 must remain strictly read-only and observational. Any capability that requires elevated privilege, active enforcement, or that could disrupt a running workload belongs in L3 (opt-in) or the deferred backlog (§14.1) — never smuggled into a lower tier. Privilege creep into L1/L2 breaks P1 and the trust story.

---

## 3. Product Architecture — The 3-Tier Progressive Trust Model

The deployment model is designed to eliminate CISO friction on multi-million-dollar clusters. A customer can start at Level 1 with zero risk and progress as trust builds.

| Level | Name | What it does | CISO Friction | Build Priority |
| :-- | :-- | :-- | :-- | :-- |
| **L1** | Agentless Control-Plane Scan | Passive API/network/endpoint probe. Orchestrator exposure, open ports, TLS, public buckets, unauthenticated dashboards. | **None** (no software on nodes) | **NOW (MVP wedge)** |
| **L2** | Kubernetes DaemonSet | Read-only container. NVML telemetry, `/dev/nvidia*` mount perms, driver/firmware versions, container privilege, K8s config hygiene, **CC-mode *claimed* state observation** (via `nvmlDeviceGetConfidentialComputeStatus`, read-only). | **Low** (open-source, read-only) | After L1 traction |
| **L3** | Deep eBPF & DPU Sidecar | Kernel/fabric tracing, InfiniBand P_Key/M_Key audit, **cryptographic CC-mode attestation verification** (SPDM/quote), CUDA/VRAM checks, DPU (DOCA) hardware attestation, cross-tenant traffic detection. | **Medium/High** (root/eBPF) | **ONLY on paying-customer demand (P1)** |

**The value ladder:** L1 = discovery + the free assessment report (the hook). L2 = continuous posture (the recurring SaaS). L3 = high-assurance / confidential-computing / sovereign (the premium moat).

**CC-mode verification is deliberately split across tiers (do not collapse it into L2).** Full CC-mode attestation (verifying the cryptographic quote, PCIe/NVLink isolation, SPDM sessions) needs privileged access to `/dev/nvidia-caps/*`, SPDM, and sometimes DOCA — that is L3-grade privilege. Dragging it into L2 would break the "L2 is low-friction and read-only" guarantee (P10). Therefore:
- **L2** performs *cheap, read-only observation*: does NVML report CC mode as *claimed* on? Driver/firmware versions consistent? This is an indicator, not proof.
- **L3** performs *privileged cryptographic verification*: validate the attestation quote against vendor roots, confirm isolation, detect drift. This is proof.

L2 findings on CC state are surfaced as "claimed / unverified — enable L3 for cryptographic proof," which is also a natural upsell into the premium tier.

---

## 4. System Architecture (Overview)

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ CUSTOMER ENVIRONMENT (Neocloud / Hybrid / On-Prem / Air-Gapped)                │
│                                                                                │
│  ┌────────────┐   ┌─────────────────┐   ┌──────────────────────────────────┐  │
│  │ ray-guard  │   │ L2 DaemonSet     │   │ L3 eBPF/DPU Sidecar (DEFERRED)    │  │
│  │ CLI (L1)   │   │ (NVML/container) │   │ (InfiniBand/CUDA/CC/DOCA)        │  │
│  └─────┬──────┘   └────────┬─────────┘   └───────────────┬──────────────────┘  │
│        │                   │                             │                     │
│        └───────────────────┴──────────────┬──────────────┘                     │
│                                            ▼                                    │
│                          ┌──────────────────────────────────┐                  │
│                          │ Local Collector                   │                  │
│                          │ • Metadata-only enforcement (P3)  │                  │
│                          │ • Anonymizer / PII+payload strip  │                  │
│                          │ • Buffer (survives disconnect)    │                  │
│                          │ • mTLS client identity            │                  │
│                          └───────────────┬──────────────────┘                  │
└──────────────────────────────────────────┼────────────────────────────────────┘
                                            │  Encrypted gRPC (mTLS) — OR —
                                            │  Offline signed bundle (air-gap, P4)
                                            ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│ CONTROL PLANE  (Modular Monolith — Section 5)                                   │
│                                                                                │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │ Ingestion Gateway (gRPC)  ──►  NATS JetStream (durable ingest bus)        │  │
│  └───────────────────────────────────────┬────────────────────────────────┘  │
│                                           ▼                                     │
│  ┌───────────────┐ ┌──────────────────┐ ┌──────────────────┐ ┌─────────────┐ │
│  │ Asset/Inventory│ │ Policy Engine    │ │ Attestation      │ │ Correlation │ │
│  │ Module         │ │ (OPA/Rego +      │ │ Verification     │ │ Graph       │ │
│  │                │ │  rule library)   │ │ Module           │ │ Engine      │ │
│  └───────┬────────┘ └────────┬─────────┘ └────────┬─────────┘ └──────┬──────┘ │
│          │                   │                     │                  │        │
│          └───────────────────┴─────────┬───────────┴──────────────────┘        │
│                                         ▼                                       │
│  ┌───────────────┐ ┌──────────────────┐ ┌──────────────────┐ ┌─────────────┐ │
│  │ Compliance     │ │ Trust Report /   │ │ Alerting/Eventing│ │ Benchmark   │ │
│  │ Mapping Module │ │ Verifiable Cred  │ │ (Slack/PD/SIEM)  │ │ Index (P9)  │ │
│  │                │ │ (PQC-signed)     │ │                  │ │             │ │
│  └───────────────┘ └──────────────────┘ └──────────────────┘ └─────────────┘ │
│                                         │                                      │
│  ┌──────────────────────────────────────────────────────────────────────────┐│
│  │ API Layer:  REST (OpenAPI) + GraphQL (graph queries) + gRPC (internal)     ││
│  └──────────────────────────────────────────────────────────────────────────┘│
│                                         │                                      │
│  ┌──────────────────────────────────────────────────────────────────────────┐│
│  │ DATA LAYER (Section 6): PostgreSQL+JSONB · Neo4j · TimescaleDB · Object     ││
│  │                         Store (S3/MinIO) · Redis                            ││
│  └──────────────────────────────────────────────────────────────────────────┘│
└──────────────────────────────────────────────────────────────────────────────┘
                                         │
                                         ▼
                   ┌────────────────────────────────────────┐
                   │ Web Dashboard (Next.js) — Multi-tenant   │
                   │ + Public "Verified by [Platform]" trust page  │
                   └────────────────────────────────────────┘
```

**On future change / separation of Web, API, Data-processing:** Web is a fully separate deployable app talking only through the API. The API is a separate *layer* (thin, stateless, in front of the modules) but shares the control-plane process today — it can be extracted into its own gateway service when needed. Data processing (ingestion) is already async-decoupled via NATS and is extraction seam #1. See §5.3 for the extraction order and §5.4 for the boundary rules that keep all of this cheap to change.

---

## 5. Microservices vs. Monolith — DECISION

**Verdict: Modular Monolith for the control plane + independently deployable edge components + a durable ingestion bus. NOT microservices (yet).**

### 5.1 Why not microservices now
- Team is lean (2–4 engineers at MVP). Microservices tax a small team with distributed-systems overhead (network failures, versioning, tracing, deploy orchestration) that buys nothing at this scale.
- We do not yet know the true service boundaries. Premature decomposition freezes the wrong seams. A monolith lets boundaries emerge from real usage.
- Air-gapped/sovereign deployment (P4) is dramatically simpler with fewer moving parts. A single deployable control plane + a few edge binaries is far easier to ship into a defence datacenter than 12 microservices with a service mesh.
- Faster iteration during the validation phase (P2).

### 5.2 Why not a naive monolith either
- The **ingestion path** genuinely needs to scale/decouple independently (many clusters pushing telemetry in bursts; drift verification is continuous). So we carve ingestion out via **NATS JetStream** from day one — the collector → gateway → bus → processors path is async and independently scalable without a full microservices split.
- The **edge components** (scanner, DaemonSet, sidecar) are *already* separate deployable artifacts by nature — they run in the customer environment. They talk to the control plane over gRPC. This gives us process isolation where it matters (blast radius, independent release cadence) without distributed-monolith pain.

### 5.3 The rule: modular monolith with pre-drawn extraction seams
The control plane is ONE deployable binary/image internally organized as strictly bounded modules (Section 4 boxes). Modules communicate through **in-process interfaces**, never by reaching into each other's data. Each module owns its own tables/schema namespace. This makes future extraction mechanical.

**Pre-drawn extraction order (extract only under real pressure, with a Decision Log entry):**
1. **Ingestion + stream processors** (first to go — highest independent scaling need).
2. **Report/Verifiable-Credential generation** (CPU-heavy PQC signing; bursty).
3. **Policy evaluation** (if rule volume explodes).
4. **Correlation graph engine** (if graph compute dominates).

### 5.4 Module boundary rules (enforced in code)
- A module exposes a Go interface package; callers depend on the interface, not the impl.
- No cross-module DB access. Module A never queries module B's tables — it calls B's interface.
- Shared types live in a `pkg/domain` package (entities, value objects) with no business logic.
- A linter/CI check enforces import boundaries (e.g. `go-arch-lint` or import restrictions).

---

## 6. Data Architecture

**Polyglot persistence, justified by data shape.** Each store earns its place. In air-gapped mode, all stores run locally (MinIO replaces S3).

### 6.1 PostgreSQL (+ JSONB) — primary transactional store
Everything relational and config-shaped. The system of record.

Core entities (each module owns its schema namespace):
- `tenants` — org, plan, deployment mode (saas | single_tenant | air_gapped).
- `users`, `roles`, `role_bindings` — RBAC, tenant-scoped.
- `clusters` — a customer GPU cluster (name, provider, region, deployment type, enrolment status).
- `nodes` — GPU hosts (hostname hash, GPU model, driver/firmware version, DPU present).
- `gpus` — per-GPU records (uuid hash, model, VRAM, CC-capable, CC-enabled-observed).
- `assets` — generic discovered asset (orchestrator endpoint, bucket, dashboard, fabric partition).
- `scans` — a scan run (level L1/L2/L3, started_at, status, collector_id).
- `findings` — a detected issue (rule_id, severity, asset_id, evidence_ref, status, first_seen, last_seen, remediation_ref, **verification_status**).
- `policies` — policy metadata (rule set version, enabled rules).
- `compliance_state` — per-control status per framework per cluster.
- `credentials` — issued trust credentials (report_id, hash, signature_ref, issued_at, expires_at, revoked).
- `evidence_index` — pointers to raw evidence blobs in object storage (never the payload itself).

Use JSONB for the variable-shape `evidence` and `raw_config` fields (config snapshots differ per asset type). Index with GIN where queried.

**Why Postgres:** ACID for tenant/billing/findings integrity; JSONB flexibility for heterogeneous evidence; one well-understood engine; runs anywhere (air-gap friendly).

### 6.2 Neo4j — the correlation / attack-path graph (THE MOAT)
The graph is not a nice-to-have; it is moat #3. It answers "what is the blast radius?" and "what is the cross-tenant attack path?"

> **MVP shortcut allowed:** to reduce ops early, the graph MAY start on **Apache AGE** (a graph extension for Postgres) to avoid running a second datastore. (Karteek already has Neo4j experience from prior inventory-graph work, so Neo4j is the default target.)
>
> **Explicit migration trigger (AGE → Neo4j):** migrate the graph to Neo4j when **4-hop traversal query latency exceeds 500ms**, OR when cross-tenant reachability queries span more than a single cluster's graph. **Caveat:** our flagship demo *is* the cross-tenant blast-radius traversal, which is exactly the deep multi-hop query AGE handles worst. Expect this trigger to fire as soon as cross-tenant analysis becomes a sales priority — **budget the Neo4j migration slightly ahead of a pure latency reading**, not after it starts hurting.

**Node types:** `Cluster`, `Node`, `GPU`, `DPU`, `FabricPartition` (P_Key), `OrchestratorEndpoint` (Ray/vLLM/Triton/…), `Bucket`, `IAMRole`, `Tenant`, `Finding`, `AttestationState`.

**Edge types:** `HOSTS` (Node→GPU), `CONNECTED_VIA` (Node→FabricPartition), `EXPOSES` (Node→OrchestratorEndpoint), `CAN_REACH` (Node→Node over fabric), `ATTESTED_BY` (GPU→AttestationState), `AFFECTED_BY` (asset→Finding), `ESCALATES_TO` (Finding→Finding, the attack path), `BELONGS_TO` (asset→Tenant), `CROSSES_TENANT_TO` (the killer edge — cross-tenant reachability).

**Signature query (the demo that sells):** given an exposed Ray dashboard with RCE, traverse `EXPOSES → ESCALATES_TO(RCE) → CONNECTED_VIA(default P_Key live) → CAN_REACH → CROSSES_TENANT_TO` to render the full cross-tenant blast radius. This is the SemiAnalysis finding made visual and sellable.

### 6.3 TimescaleDB — time-series (posture drift & metrics)
A Postgres extension (keeps the stack lean; no separate engine early). Stores:
- Attestation state over time (is CC mode *still* enabled? drift detection — the "M" in posture Management).
- Posture score history per cluster.
- Finding open/close timelines.
- Telemetry samples from L2/L3.

**Why not ClickHouse yet:** Timescale is a Postgres extension = one fewer engine, air-gap friendly. Move high-volume analytical/telemetry workloads to **ClickHouse** only when Timescale strains (Decision Log entry).

### 6.4 Object storage — S3 (SaaS) / MinIO (air-gapped)
Immutable blobs:
- Raw attestation quotes (NRAS responses, DPU DICE certs) — evidence, never payload.
- Generated trust reports (PDF + signed credential JSON).
- Anonymized scan snapshots feeding the benchmark index.
- Signed release artifacts / SBOMs.

MinIO for air-gap gives an S3-compatible API locally — same code path, P4 satisfied.

### 6.5 Redis — cache, queue, rate limit, sessions
- Short-lived caches (asset lookups, policy compile cache).
- Rate limiting (API + agent enrolment).
- Ephemeral job coordination (or use NATS for jobs — prefer NATS to avoid Redis-as-queue in air-gap; keep Redis for cache/rate-limit).

### 6.6 NATS JetStream — durable ingestion bus
Async decoupling of ingestion from processing. Durable streams survive restarts; consumers (asset updater, policy evaluator, graph updater, drift detector) scale independently. Chosen over Kafka for operational simplicity and air-gap friendliness (single lightweight binary, no ZooKeeper/heavy JVM).

**Subject taxonomy (initial):**
- `gpusec.events.scan.completed` — an L1/L2 collector finished a sweep.
- `gpusec.events.finding.created` — a rule's `finding_condition` evaluated true.
- `gpusec.events.finding.resolved` — a rule's `verification_condition` evaluated true (auto-closure, §8).
- `gpusec.events.attestation.issued` — a signed W3C credential was generated for a cluster.

### 6.7 Data isolation & tenancy
- **Row-level tenant scoping** on every query in SaaS mode (tenant_id on every table; enforce via a query layer that refuses tenant-less queries).
- **Single-tenant / air-gapped mode** = one tenant per deployment; tenant_id still present for code uniformity.
- Consider Postgres RLS (Row-Level Security) policies as a defense-in-depth backstop.
- Evidence blobs are tenant-prefixed in object storage with per-tenant access policies.

---

## 7. API Design

Three surfaces, each fit-for-purpose:

### 7.1 External REST API (OpenAPI 3.1) — CRUD + reports
For dashboard, integrations, and customers' programmatic access.
- Versioned: `/api/v1/...`.
- Resources: `/clusters`, `/scans`, `/findings`, `/assets`, `/compliance`, `/reports`, `/credentials`.
- OpenAPI spec is generated and published; it is a product surface (customers build against it).
- Standard: pagination (cursor-based), idempotency keys on POST, RFC 7807 problem+json errors, ETags.

Example:
```
POST /api/v1/scans            # start a scan (body: cluster_id, level)
GET  /api/v1/scans/{id}       # scan status + summary
GET  /api/v1/findings?cluster_id=&severity=&status=open   # paginated
POST /api/v1/reports          # generate a trust report (body: cluster_id, framework[])
GET  /api/v1/credentials/{id}/verify   # public verification of a signed credential
```

### 7.2 GraphQL — graph exploration only
The correlation graph is naturally a graph query problem (variable-depth traversals, "show me everything reachable from X"). REST would be N+1 hell. Expose a **read-only GraphQL endpoint** scoped to graph/attack-path/blast-radius queries. Do not GraphQL the whole API — keep CRUD on REST.

### 7.3 Internal gRPC — collector ↔ control plane ingestion
- Typed, efficient, streaming (telemetry streams), mTLS mutual auth.
- Protobuf schemas are the contract between edge and control plane; versioned carefully (edge and control plane deploy independently).
- Backpressure-aware; collector buffers locally on disconnect (survives network partitions — critical for on-prem).

### 7.4 Outbound eventing
Webhooks + native integrations: Slack, PagerDuty, generic webhook, SIEM (Splunk/Sentinel via CEF/OCSF). **Metadata only** (P3) — alerts describe posture, never payload.

### 7.5 Auth model
- **Users:** OIDC/OAuth2; enterprise SSO via SAML/OIDC. RBAC, tenant-scoped.
- **Agents/collectors:** short-lived enrolment token → mTLS client cert. Certs rotate automatically. No long-lived static secrets on nodes.
- **Public credential verification:** unauthenticated read of a signed credential's validity (the "Verified by [Platform]" page must be publicly checkable).
- **Air-gap:** local IdP or static admin bootstrap; no dependency on external auth providers.

### 7.6 Web Surfaces (Frontend Portals)

> **Key framing: this is not one portal.** The product is a trust *standard*, so it has three distinct web surfaces for three different viewers, plus the standalone Phase-0 report. Building it as a single internal dashboard misses the surface that actually drives revenue (the public trust page). Tech is fixed by §15: Next.js + Tailwind; REST for CRUD; **GraphQL only for the graph screen**; Cytoscape.js / react-force-graph for the blast-radius viz; public pages statically cacheable.

**Surface A — Operator Console (private; the Neocloud's own security/ops team).** The posture-management product. Organize *every* screen around the grade (§10.0) — it is the through-line the buyer sees, the credential encodes, and the ops team is trying to move.

Screens, in build-priority order:
- **Overview** — grade + score (large), score trend over time (drift is the differentiator — surface it early), open-critical count, credential status (issued / withheld / revoked), cluster count. One glance answers "are we sellable right now?"
- **Clusters → cluster detail** — per-cluster grade, active tiers (L1/L2/L3 coverage), last scan time, top findings.
- **Findings (work queue)** — severity, rule ID, affected asset, first/last seen, and the **verification-sentinel status** (open → remediated → *verified-closed*; never render a self-reported closure as verified, §8). Each finding carries remediation + compliance mappings.
- **Attack-path / blast-radius graph (the hero screen)** — moat #3 made visible: click an exposed Ray endpoint, watch it escalate through an RCE, across a live default P_Key, to *another tenant's node*. Nothing a scanner can draw; this is the demo. Deserves the most design attention. GraphQL-backed.
- **Attestation / hardware posture** — CC-mode shown as **claimed vs. cryptographically verified** (this visual split honors §3/§9 and is a trust statement), firmware/DPU state, drift timeline.
- **Compliance** — per-framework readiness (SOC2, ISO 27001 first; then 42001/NIST/EU-AI-Act/HIPAA/DPDP), control-by-control, one-click **exportable evidence pack**.
- **Trust report / credential** — generate, view, download, get badge + share link, revoke.
- **Settings** — cluster enrolment, integrations (Slack/PagerDuty/SIEM), users/RBAC/SSO, rule-version pinning, air-gap signed-bundle import.

**Surface B — Public "Verified by [Platform]" trust page (public; the Neocloud's enterprise buyers).** The sales-enablement moat, and the surface most teams wrongly treat as an afterthought. It is arguably the highest-ROI screen in the product: it's what a Neocloud puts in front of a prospect to pass a vendor-security review. Deliberately shows *less* — grade + badge, validity window, plain-language summary of what's attested (tenant isolation, orchestrator hygiene, hardware-attestation level), high-level compliance coverage, "last verified" date, and a prominent independent-verify link. **No raw findings** — those stay internal. Its whole job is to let a buyer's reviewer tick a box faster.

**Surface C — Independent Verifier (public; auditors, skeptical buyers).** Paste a credential or open its URL → cryptographically verify the hybrid classical+PQC signature against our published keys, **without trusting us** (§10). Small surface, disproportionate credibility — it's what makes the credential more than a PDF.

**The Phase-0 report (not a portal).** A standalone HTML/PDF that `ray-guard` emits with no login — the exposure summary, ranked findings, proposed grade, ShadowRay-flavored hook. This is the lead magnet and the *only* UI on the critical path to the validation gate.

**UX principles that matter here:**
- **Grade-forward everywhere** — the A+/A/B/C/F band is the organizing metaphor; don't bury it under tables.
- **Continuous, not point-in-time** — put drift/time-series up front; "A, holding 40 days" tells a different story than "A, scanned once."
- **Claimed ≠ verified, visually** — two distinct treatments; not cosmetic, it's the honesty the credential rests on.
- **Progressive disclosure** — Overview → cluster → finding → raw evidence; never dump everything at once.
- **Severity color-coded but never color-alone** (accessibility + it prints into reports).
- **Empty / new states are real screens** — a freshly enrolled cluster mid-first-scan is the first thing every new customer sees.
- **Tenant switcher in SaaS; hidden in single-tenant/air-gap** — same codebase, config-driven (ties to §13 deployment modes).

**Phasing (do NOT build all of this at once):**
- **Phase 0:** no portal. Only the standalone `ray-guard` assessment report. That is the sole UI on the critical path to the validation gate.
- **Phase 1:** minimal operator console (Overview, Clusters, Findings, basic Compliance, credential generation) **+ Surface B (public trust page) + Surface C (verifier).** B and C belong in Phase 1, not later — B is the reason a Neocloud signs.
- **Phase 2:** drift timelines, full attack-path graph at scale, integrations, SSO/RBAC depth.
- **Phase 3:** L3 hardware-attestation views, sovereign/air-gap console polish.

---

## 8. Policy & Rules Engine (moat component)

**OPA / Rego for policy-as-code + a curated, versioned rule library.**

- **Why OPA/Rego:** declarative, auditable, testable, decoupled from app code. "Our rules are open-source and auditable" is a *selling point* to CISOs (low L2 friction). Rules ship as data, not code deploys.
- **Rule library structure:** rules grouped by domain — `orchestrator/` (Ray, vLLM, Triton, MLflow, Jupyter, Ollama, **Slurm** exposure), `fabric/` (P_Key/M_Key/SA_Key, RDMA PD, **RoCE v2**, NVLink), `hardware/` (secure boot, firmware, NVML), `attestation/` (CC mode, DPU DICE), `k8s/` (privilege, mounts), `cloud/` (buckets, TLS, IAM).

- **Deterministic verification sentinels (REQUIRED for every rule).** Every rule MUST define **both**:
  1. `finding_condition` — the predicate that raises the finding, and
  2. `verification_condition` — a deterministic predicate that confirms the fix actually landed and the finding can be **auto-closed**.

  This is not optional metadata. It is load-bearing for the trust credential: a credential is only worth signing if closures are **verified by us**, not self-reported by the customer. "We told you to fix it" becomes "we cryptographically attest it is fixed." The verification pass runs automatically on the next scan; a finding only transitions to `verified_closed` when `verification_condition` passes. CI rejects any rule missing either predicate.

- Each rule also carries: `id`, `severity`, `description`, `evidence_query`, `remediation` (the corrected config — audit-to-fix, not audit-only), and **compliance mappings** (which SOC2/ISO/NIST/EU-AI-Act controls it satisfies).
- **Rule versioning:** the rule library is semver'd and independently updatable (like a threat-intel feed). Customers can pin versions. This is a recurring-value lever. (Air-gap update format: see §13.)
- **Custom Python policy layer** for rules that need imperative logic or ML (e.g. anomaly detection on drift) that Rego can't express cleanly.

**Worked example — the required sentinel shape (every rule follows this):**
```rego
package gpusecurity.orchestrator.ray

# Detection: unauthenticated Ray dashboard bound to all interfaces
finding_condition {
    input.service == "ray-dashboard"
    input.port == 8265
    input.auth_enabled == false
    input.bind_address == "0.0.0.0"
}

# Verification sentinel: deterministic proof the fix landed (auto-close only when true)
verification_condition {
    input.service == "ray-dashboard"
    input.port == 8265
    input.auth_enabled == true
} {
    input.service == "ray-dashboard"
    input.bind_address == "127.0.0.1"
}

finding_metadata := {
    "id": "RG-RAY-001",
    "title": "Unauthenticated Ray dashboard exposed",
    "severity": "CRITICAL",
    "cve": ["CVE-2023-48022", "CVE-2025-62593"],
    "remediation": "Enable Ray auth or bind the dashboard to loopback/private subnet.",
    "compliance": ["SOC2:CC6.6", "ISO27001:A.8.20"]
}
```
Every rule ships a matching `*_test.rego` asserting BOTH a positive finding trigger and a positive remediation closure (§17).

---

## 9. Attestation & Verification Subsystem

The engine behind moat #2. Normalizes per-vendor evidence into one model.

- **Inputs:** NVIDIA attestation (NRAS quotes via `nv-attestation-sdk`, RIM, OCSP), Intel Trust Authority (composite CPU+GPU), AMD (future), BlueField DPU DICE-based secure/measured boot certs.
- **Normalization:** map heterogeneous evidence into a canonical `AttestationState` model (device, mode, measured firmware hash, cc_enabled, verified_at, evidence_ref, verifier, result).
- **Tiered CC verification (see §3):** L2 records *claimed* CC state from NVML via `nvmlDeviceGetConfidentialComputeStatus` (read-only, indicator only); L3 performs the *privileged cryptographic verification* of the quote/SPDM session and isolation. The subsystem tracks both, and never reports L2's claimed state as "verified."
- **L2 device-mount contract:** the L2 DaemonSet's required device nodes (e.g. read-only NVML access) are explicitly documented and pinned in the Helm chart with a strictly read-only security context, so CISOs can audit exactly what it touches during onboarding. Anything requiring `/dev/nvidia-caps/*`, SPDM, or DOCA is L3, never L2.
- **Continuous verification (drift):** re-verify on a schedule; compare against baseline; raise a finding on drift (CC mode disabled, firmware changed, P_Key altered). This is the underserved "posture *management*" gap.
- **Trust anchors:** ship vendor CA roots; support offline verification bundles for air-gap (P4, format per §13).
- **Output:** a normalized, timestamped, verifiable attestation record that feeds the trust credential (Section 10).

---

## 10. Trust Report / Verifiable Credential (moat #2 delivery)

### 10.0 Posture Grading Matrix (governs credential issuance)
A deterministic posture score (0–100) maps to a grade, and the grade governs whether a credential is issuable. This is the link between findings and the trust badge.

| Grade | Score | Definition | Credential status |
| :-- | :-- | :-- | :-- |
| **A+** | 95–100 | Full hardware attestation (CC mode cryptographically verified via L3), isolated IB P_Key, zero exposed management ports, encrypted fabric. | Issuable — Gold |
| **A** | 85–94 | L2-verified posture, clean orchestrator endpoints, correct K8s network policies, CC mode *claimed* active. | Issuable — Silver |
| **B** | 70–84 | Non-critical drift (outdated driver, unencrypted local metrics endpoint). | Issuable with warnings |
| **C** | 50–69 | Multi-tenant isolation risk (e.g. shared P_Key across distinct tenants). | Withheld / non-issuable |
| **F** | <50 | Active RCE exposed (e.g. Ray CVE-2023-48022 / CVE-2025-62593 on a public IP). | Revoked + immediate alert |

A credential is only ever issued off **verified** closures (§8) — a fix a customer self-reports but that fails its `verification_condition` does not raise the grade.

### 10.1 The credential itself
The commercial artifact. Not a PDF — a **signed, tamper-evident, cross-vendor, compliance-mapped credential**.

- **Format:** W3C Verifiable Credential–style JSON + a human-readable PDF rendering. The JSON is the source of truth; the PDF is derived.
- **Content:** cluster identity (hashed), posture score, control-by-control compliance status, attestation summary, findings summary (with verified-closure state), validity window.
- **Signing:** detached signature over a canonical hash of the credential. **PQC-ready from day one** — use a hybrid signature (classical Ed25519/ECDSA **+** a PQC scheme, e.g. ML-DSA/Dilithium) so the credential survives the quantum transition and is a genuine differentiator. (This is where Karteek's PQC work becomes the moat, not a side project.)
- **Payload-size handling:** ML-DSA signatures add ~2.4–4.5 KB per credential (ML-DSA-44/65). Account for this in the VC schema, and have the public verification page + CLI **cache the public keys / cert chain** so validation stays fast (the credential is fetched-and-cached, not on a hot path — this is a minor concern, do not over-engineer it).
- **Verification:** a public endpoint + an offline verifier CLI. Anyone can verify a credential hasn't been altered *without trusting us* (they verify the signature against our published public key / cert chain).
- **Revocation:** a revocation list (and/or status endpoint) so a credential can be invalidated if posture regresses.
- **The badge:** "Verified by [Platform] — valid until <date>" links to the public verification page. This is the sales-enablement object a Neocloud puts in front of its buyers.

---

## 11. Compliance Mapping Engine

- Maps findings/controls to: **SOC 2**, **ISO 27001**, **ISO/IEC 42001**, **NIST AI RMF**, **EU AI Act**, **HIPAA**, **India DPDP** (sovereign GTM), and emerging Neocloud trust expectations.
- Mapping lives *with the rules* (Section 8) so a single scan produces multi-framework evidence automatically.
- Output: per-framework readiness view + exportable evidence pack (the thing auditors want).
- Note the honest nuance: 42001/NIST/EU-AI-Act are AI *governance* frameworks; our infra findings map more cleanly to SOC2/ISO27001 + confidential-computing controls. Lead with those; present governance frameworks as "we also feed your governance evidence."

---

## 12. Securing the Platform Itself (P8)

A security posture product is a top-tier target. Hold ourselves higher than we hold customers.

- **Supply chain:** SBOM on every build (CycloneDX/SPDX), signed releases (Sigstore/cosign), pinned dependencies, dependency scanning in CI, reproducible builds where feasible.
- **Secrets:** no static secrets on nodes; short-lived mTLS; secrets via vault (or sealed secrets in air-gap).
- **Least privilege:** collectors run read-only; L1 needs no node access; L3 root/eBPF capabilities are scoped and documented. **L2 DaemonSet hardening (enforced in the Helm chart):** `runAsNonRoot: true` (UID 10001), `readOnlyRootFilesystem: true`, `allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]`, read-only device mounts only (§9). **L3 host agent** runs under a restricted SELinux/AppArmor profile scoped to `/dev/nvidia-caps/*` and SPDM interfaces.
- **Metadata-only enforcement (P3):** a hard filter at the collector + a test suite that fails the build if any payload-shaped data can traverse the boundary.
- **Tenant isolation:** enforced at query layer + Postgres RLS backstop + object-store per-tenant policies.
- **Our own attestation:** eventually attest our own control plane (dogfood the trust credential).
- **Threat model doc:** maintain `/docs/threat-model.md`; update it every time an ingestion or trust surface changes.

---

## 13. Deployment Topologies

Design once, deploy three ways. Same artifacts, different composition.

| Mode | Control plane | Data stores | Auth | Notes |
| :-- | :-- | :-- | :-- | :-- |
| **SaaS multi-tenant** | Our cloud (K8s) | Managed PG/Neo4j/S3/Redis/NATS | OIDC + SSO | Default commercial motion |
| **Single-tenant** | Customer VPC (K8s/Helm) | Dedicated instances | Customer IdP | Regulated enterprises |
| **Air-gapped / sovereign (P4, P7)** | On-prem, offline | All local (MinIO, self-hosted PG/Neo4j/NATS) | Local IdP / bootstrap | Defence/govt; no phone-home; offline license; bundled deps; offline rule-feed updates via signed bundle |

- Everything ships as **containers + a Helm chart** + the scanner as a **single static Go binary**.

- **Air-gap update manifest (formalized standard — do not improvise).** All offline updates (rule-library releases, vendor CA root bundles, attestation trust anchors) ship as a **versioned, signed bundle**, defined and tooled in `/deploy/airgap`:
  - Format: a `.tar.gz` payload + a **detached signature**, signed with the **same cosign/Sigstore keys used for release signing in §12** (one signing mechanism, not a parallel one).
  - A `manifest.json` inside the bundle declares: bundle type, semver, contents + per-file hashes, minimum compatible control-plane version, and issue/expiry dates.
  - The importer verifies the detached signature against pinned public keys, checks the manifest hashes, and refuses partial/unsigned/expired bundles. No ad-hoc update paths are permitted anywhere in the codebase.

---

## 14. Build Sequence / Roadmap (tied to the 12–18 month plan)

> Sequencing obeys P1 and P2. Do not jump ahead.

### Phase 0 — Validation wedge (Weeks 0–8)
- [x] `ray-guard` open-source scanner (Go single binary): detect exposed/unauthenticated Ray, vLLM, Triton, Jupyter, MLflow, Ollama; open ports; missing TLS; public buckets. *Also Slurm + Triton gRPC. TLS is classified (self-signed/expired/mismatched), not just present/absent. **RG-RAY-001 is verified against real Ray**, not mocks (`make test-integration`).*
- [x] JSON + terminal output; a clean standalone (no-login) "GPU Risk & Isolation Report" (PDF/HTML) — the lead magnet; the only UI on the critical path to the gate (§7.6). *HTML is self-contained and print-ruled; `make report-pdf` renders it via local Chrome rather than adding a Go PDF dependency that would cost the static binary.*
- [x] No backend required yet — the scanner runs standalone and prints a report. This is the distribution magnet (ride ShadowRay/CISA news). *`go.mod` has no `require` block at all.*
- [x] Instrument opt-in anonymized telemetry (respecting P3) to seed the benchmark index. *Shipped as a **local-only** snapshot (`-benchmark-snapshot`) with zero network egress: no endpoint to build, no phone-home surface to justify to a CISO, air-gap-safe by construction (P4). Sending it is the operator's manual choice.*
- [ ] **Publish OSS on GitHub.** *Repo is publish-ready — signed/SBOM'd release workflow, SECURITY.md, CONTRIBUTING.md, threat model. Going public and tagging are deliberate manual steps: see `docs/publishing.md`.*
- [ ] **Gate (P2) — buyer-led, not vanity:** the decision to invest in the Phase-1 control plane requires **at least 3 completed assessment runs conducted directly alongside a Neocloud's own Security/Ops lead** (not just downloads or GitHub stars), and **at least 2 of those buyers stating they would pay for the trust report and would ask for it by name.** Stars/assessment counts are supporting signal only. If the buyer-led runs don't happen or don't convert, re-think before building the platform.

### Phase 1 — MVP control plane + paid trust report (Months 2–6)
- [ ] Modular monolith control plane (Go): Ingestion Gateway (gRPC) → NATS → Asset/Policy/Graph modules.
- [ ] PostgreSQL schema + object storage + Redis. Graph on Apache AGE or Neo4j (per §6.2 trigger).
- [ ] Policy engine (OPA/Rego) with the L1 rule library + **verification sentinels** + compliance mappings (start SOC2 + ISO27001).
- [ ] Trust Report generation + **v1 signed credential** (hybrid classical+PQC signature) + public verification page + "Verified by [Platform]" badge.
- [ ] Minimal operator console (Overview, Clusters, Findings, basic Compliance, credential generation), first correlation-graph view (§7.6 Surface A).
- [ ] Public "Verified by [Platform]" trust page (Surface B) + independent credential verifier (Surface C) — ship in Phase 1, not later; Surface B is the sales-enablement reason a Neocloud signs.
- [ ] Air-gap update manifest tooling scaffolded in `/deploy/airgap` (§13).
- [ ] Land 3–5 design-partner Neoclouds. Publish first anonymized "State of Neocloud Security" index (authority + press + flywheel).
- [ ] **Target:** first paid ACV.

### Phase 2 — Continuous posture + L2 (Months 6–12)
- [ ] L2 Kubernetes DaemonSet collector (Go): NVML telemetry, mount/privilege/driver hygiene, **claimed** CC-state observation (§3/§9), read-only device-mount contract documented.
- [ ] TimescaleDB drift detection; continuous attestation re-verification.
- [ ] Attestation Verification Module v1 (NVIDIA NRAS + Intel Trust Authority normalization).
- [ ] Expand compliance to ISO 42001 / NIST AI RMF / HIPAA. Enterprise SSO + RBAC.
- [ ] Air-gapped single-tenant deployment SKU hardened (P4/P7); signed update manifest in production use.
- [ ] **Target:** ~$1–3M ARR across ~10–20 Neoclouds + a few regulated renters → fundable Seed/Series A milestone.

### Phase 3 — L3, sovereign, and the full moat (Months 12–18+, ON DEMAND per P1)
- [ ] L3 eBPF probes (Rust): InfiniBand P_Key/M_Key audit, CUDA/VRAM checks, **cryptographic CC-mode attestation verification** (SPDM/quote), cross-tenant traffic detection.
- [ ] DPU integration (Rust + NVIDIA DOCA SDK) for BlueField DICE attestation.
- [ ] Full cross-tenant blast-radius graph on Neo4j at scale.
- [ ] Sovereign anchor deployment(s) — defence/government, fully air-gapped, cross-vendor credential.
- [ ] Cyber-insurance underwriting partnership (turn security spend into measurable ROI for thin-margin buyers).

---

## 14.1 Future Horizon (Phase 4 / Post-Series A Backlog) — EXPLICITLY DEFERRED

> These are documented so they stay visible to contributors and agents **without entering MVP scope**. Nothing here is built before the Phase-2 milestone, and each item still obeys P1/P2/P10. Ranked by strategic value. Read the caveats — two of these are traps if pulled forward.

**H1 — FinOps + SecOps risk-correlation / ROI engine (highest value; framing comes forward now).**
Correlate GPU utilization + burn rate with security posture, e.g. "32 idle H100s costing $1,152/day running an unauthenticated Ray control plane with critical RCE." This is the answer to the thin-margin-Neocloud objection — it translates security into a number FinOps already watches. Plus a dedicated **cyber-insurance telemetry export schema** (Coalition/Cowbell-style) turning continuous attestation into premium reductions. *The feature is Phase-4; the framing should enter the sales pitch immediately.*

**H2 — Multi-vendor accelerator expansion.** AMD Instinct (ROCm auditing, SEV-SNP attestation), Intel Gaudi (TDX), hyperscaler ASICs (AWS Trainium/Inferentia via Neuron, Google TPU) node posture in hybrid deployments. Already latent in the "cross-vendor" moat. *Rule: build the vendor a real customer actually runs — never all of them speculatively.*

**H3 — KV-cache & CUDA-context forensic hygiene (strong L3 premium differentiator).** Verify LLM KV-caches are zeroed in VRAM between tenant sessions; detect lingering memory artifacts / zombie CUDA contexts after job termination. Natural extension of L3; correctly deferred under P1.

**H4 — AI supply-chain / model-registry provenance (middle case — partly pull-forward-able).** Verify model weights come from signed/trusted registries and safe formats (`.safetensors`, GGUF) vs. unsafe pickle (`.pt`/`.bin`) RCE vectors; audit the NVMe-oF / S3-to-VRAM streaming path. The unsafe-format detection is close enough to the L1 scanner to pull *partly* forward — **but it edges onto Protect AI's turf, so guard the differentiation line (we do it as infra posture, not model AppSec).**

**H5 — Active blast-radius containment / self-healing (CAUTION — very late, opt-in only).** Auto-quarantine a compromised node to an isolated P_Key via OpenSM; auto-cordon K8s nodes; inject eBPF drop rules on unauthenticated ports. **This violates the read-only, zero-friction story (P10) and is terrifying to sell early: one false positive that isolates a running multi-million-dollar training job destroys the trust you spent a year building.** Ship only after deep customer trust, strictly opt-in, with hard blast-radius limits and human-in-the-loop by default.

**H6 — Runtime agentic / MCP tool-execution guardrails (CAUTION — scope-drift trap).** Posture-aware agent authorization API (LangGraph/AutoGen/CrewAI query posture before high-risk tool calls). **This quietly walks the product off "infrastructure trust" and onto AI-application security — the crowded, consolidated layer we are deliberately avoiding.** Parked with a warning label; do not pursue without a Decision Log entry justifying the category move.

---

## 15. Tech Stack (languages & why)

Tool-to-job, leveraging the team's strengths (Rust for crypto, Python for AI, Go for infra distribution).

| Layer | Choice | Why |
| :-- | :-- | :-- |
| Scanner CLI (L1), collectors (L2), control plane | **Go** | Single static binary → ideal for air-gap + K8s DaemonSet; strong stdlib for network scanning; fast; easy cross-compile |
| Policy authoring, compliance logic, report gen, benchmark analytics, any agentic/AI features | **Python** | Team's strength (RAG/agentic AI); rich data/ML libs; report templating |
| Policy definitions | **Rego (OPA)** | Declarative, auditable, testable; ships as data |
| L3 eBPF probes, DPU (DOCA), PQC signing | **Rust** | Memory-safe systems perf for kernel/fabric; team's PQC strength = the crypto moat |

**Pinned key dependencies:** PQC + hybrid signatures — `github.com/cloudflare/circl` (ML-DSA/Dilithium + Ed25519); GPU telemetry — `github.com/NVIDIA/go-nvml`; policy — OPA Go SDK (`github.com/open-policy-agent/opa`); signing — Sigstore/`cosign` SDK. Go 1.22+ multi-module workspace (`go.work`).
| Dashboard | **Next.js + Tailwind** | SSR, fast iteration, good graph-viz ecosystem |
| Graph viz | **Cytoscape.js / react-force-graph** | Render attack paths / blast radius |
| Infra | **Docker + Kubernetes + Helm** | Portable across SaaS / single-tenant / air-gap |
| IaC | **Terraform + Helm** | Reproducible deploys |
| CI/CD | **GitHub Actions** + cosign + SBOM | Signed, attested builds (P8) |

> **Note on Go:** it's the right tool for a distributable security scanner + K8s agent even if it's newer to the team than Python/Rust. If early velocity demands it, the Phase-0 scanner MAY be Python (packaged with PyInstaller), but migrate to Go before wide OSS distribution for the single-binary + air-gap benefits. Log the choice in Section 18.

---

## 16. Repository Structure (monorepo)

A monorepo keeps the modular monolith + edge components + shared protobufs in sync.

```
/gpu-security
├── CLAUDE.md                      # this file
├── /docs
│   ├── architecture.md
│   ├── threat-model.md
│   ├── data-model.md
│   └── decision-log.md            # mirror of Section 18 (append-only)
├── /cmd
│   ├── ray-guard/                 # L1 scanner CLI (Go)
│   ├── collector/                 # local collector (Go)
│   ├── daemonset/                 # L2 agent (Go)
│   └── controlplane/              # control-plane entrypoint (Go)
├── /internal                      # control-plane modules (import-boundary enforced)
│   ├── ingestion/
│   ├── inventory/
│   ├── policy/
│   ├── attestation/
│   ├── graph/
│   ├── compliance/
│   ├── report/                    # trust report + credential
│   ├── alerting/
│   └── benchmark/                 # anonymized index (P9)
├── /pkg
│   └── domain/                    # shared entities/value objects (no business logic)
├── /proto                         # protobuf contracts (edge ↔ control plane)
├── /policies                      # Rego rule library (versioned, semver'd)
│   ├── orchestrator/ fabric/ hardware/ attestation/ k8s/ cloud/
│   └── (every rule: finding_condition + verification_condition — §8)
├── /crypto                        # Rust: PQC signing + verifier (cbindgen/FFI)
├── /ebpf                          # Rust: L3 probes (Phase 3 — do not build early, P1)
├── /web                           # Next.js dashboard + public verify page
├── /py                            # Python: compliance logic, report templating, analytics
├── /deploy
│   ├── helm/                      # Helm charts
│   ├── terraform/
│   └── airgap/                    # signed update-manifest format + import tooling (§13)
└── /test                          # integration + metadata-only-enforcement tests (P3)
```

Import-boundary linting enforces Section 5.4. Protobuf changes require a compatibility check in CI. Rego CI rejects any rule missing `finding_condition` or `verification_condition`.

---

## 17. Conventions, Testing, CI/CD, Observability

- **Testing:** unit per module; integration across the ingestion path; a dedicated **metadata-only enforcement test suite** (P3) that fails the build if payload-shaped data can cross the collector boundary; golden-file tests for report/credential output; Rego policy tests (`opa test`) that must exercise both `finding_condition` and `verification_condition`.
- **CI/CD:** every build produces an SBOM + signed artifacts (cosign). Dependency + container scanning. No merge without passing the P3 suite, the import-boundary lint, and the rule-completeness check.
- **Versioning:** control plane, edge binaries, protobufs, and the rule library are versioned independently (edge/control-plane deploy on different cadences). Air-gap bundles are versioned signed manifests (§13).
- **Observability:** structured logging (no payloads — P3), OpenTelemetry traces, Prometheus metrics at `/metrics`. In air-gap, all telemetry stays local. Core metrics: `gpusec_scan_duration_seconds{tier}`, `gpusec_active_findings{severity}`, `gpusec_verification_sentinel_evaluations_total{status}`, `gpusec_attestation_credentials_issued_total`.
- **Makefile targets (required):** `make build` (all binaries → `/bin`), `make test` (`go test -race ./...`), `make test-integration` (docker-compose suites), `make fuzz` (the parsers that read operator input; nightly in CI), `make lint` (`golangci-lint`), `make airgap-bundle` (build + cosign-sign the manifest, §13).
- **Coverage / rule QA:** ≥80% coverage on core logic (`pkg/attestation`, `pkg/policy`, `pkg/graph`); every Rego rule has a `*_test.rego` asserting both a positive finding trigger and a positive remediation closure.
- **Config:** 12-factor; env + config files; every feature that phones out has an air-gap-off switch (P4).
- **Docs:** update `/docs/*` and Section 18 in the same PR as the change they describe.

---

## 18. Decision Log (append-only)

| Date | Decision | Rationale | Supersedes |
| :-- | :-- | :-- | :-- |
| 2026-09-20 | Modular monolith control plane, not microservices | Lean team, unknown seams, air-gap simplicity (Section 5) | — |
| 2026-09-20 | NATS JetStream for ingestion bus | Air-gap friendly, simpler than Kafka | — |
| 2026-09-20 | Polyglot persistence: PG + Neo4j + Timescale + object + Redis | Data-shape fit (Section 6) | — |
| 2026-09-20 | Graph MAY start on Apache AGE, target Neo4j | Reduce early ops; team knows Neo4j | — |
| 2026-09-20 | Go primary for scanner/agent/control plane; Python for compliance/AI; Rust for eBPF+PQC | Single-binary/air-gap + team strengths | — |
| 2026-09-20 | Hybrid classical+PQC signatures on credentials from v1 | Quantum-safe differentiator = moat #2 | — |
| 2026-09-20 | Defer L3 (eBPF/DPU) until paying-customer demand | P1 — difficulty inverted from value | — |
| 2026-09-20 (rev 2) | Every Rego rule requires finding_condition + verification_condition; findings auto-close only when verified | Verified closures underpin the signed credential; "attest it's fixed," not "self-reported" (§8) | — |
| 2026-09-20 (rev 2) | Split CC-mode verification: L2 observes claimed state (read-only), L3 does cryptographic proof | Keeps L2 low-friction/read-only; privilege creep would break P1/P10 (§3, §9) | — |
| 2026-09-20 (rev 2) | Formal signed air-gap update manifest (.tar.gz + detached sig, cosign, manifest.json) in /deploy/airgap | Prevent ad-hoc update mechanisms; reuse §12 signing (§13) | — |
| 2026-09-20 (rev 2) | AGE→Neo4j migration trigger: 4-hop latency >500ms OR cross-tenant/multi-cluster graphs; budget ahead of pure latency | Cross-tenant blast-radius is the query AGE handles worst; it's also the flagship demo (§6.2) | — |
| 2026-09-20 (rev 2) | Phase-0 gate = ≥3 buyer-led assessments with a Neocloud security/ops lead + ≥2 pay-and-name-it intents | Vanity metrics don't test P2; buyer-in-the-room does (§14) | prior stars/count gate |
| 2026-09-20 (rev 2) | Add §14.1 Future Horizon as explicitly-deferred backlog (H1–H6) with caveats on H5/H6 | Keep capabilities visible without MVP bloat; H5 (active containment) and H6 (agentic guardrails) flagged as traps | — |

| 2026-09-20 (rev 3) | Adopted Posture Grading Matrix (A+/A/B/C/F → credential status) from external draft | Operationalizes the credential; ties score bands to issue/revoke (§10.0) | — |
| 2026-09-20 (rev 3) | Pinned concrete libs (circl, go-nvml, OPA SDK, cosign) + widened scope to Slurm + RoCE v2 | Coding-ready; RoCE matters for non-IB neoclouds (§1.2, §8, §15) | — |
| 2026-09-20 (rev 3) | Merged external draft's concreteness but PRESERVED P2, P3, P9, §5.3/5.4, §14.1 | External draft dropped validate-first, metadata-only, the flywheel, extraction seams, and the deferred backlog — these are the disciplines that matter most; kept them | — |

| 2026-09-20 (rev 4) | Documented web surfaces as THREE portals + Phase-0 report (§7.6); public trust page ships Phase 1 | Frontend was undocumented (one diagram box); the public trust page is the revenue surface and must not be deferred | — |
| 2026-09-20 (rev 5) | Documented tenant-side scan vantage + two-buyer model (§1.5); same tool, no new scope | Prevents building a separate tenant scanner; captures that renter demand often drives the Neocloud sale | — |

| 2026-09-20 (rev 6) | Scanner probes **per port**, not per check; a service is attributed only when it answers 2xx on its own health path | vLLM and Triton both default to 8000, so per-check probing dialed shared ports twice and cost `timeout × len(checks)` on filtered hosts. An unidentified open port is reported at Info (`RG-EXPOSURE-001`), never guessed — misattributing a service on a Neocloud's report is how the tool loses credibility in the room | — |
| 2026-09-20 (rev 6) | P9 telemetry ships as a **local-only anonymized snapshot**, not network telemetry | No receiving endpoint exists, and a phone-home surface must be justified in every CISO conversation for no benefit before there are buyers. Local file + single-use salt keeps the flywheel and makes P4 true by construction. Revisit if manual collection becomes the bottleneck | — |
| 2026-09-20 (rev 6) | No Go PDF dependency; HTML carries `@media print` and `make report-pdf` shells out to local Chrome | A PDF library would cost the zero-dependency static binary, which is what makes ray-guard air-gap-deployable and handable to a security lead (§15, P4) | — |
| 2026-09-20 (rev 6) | Kept `internal/scan` + `internal/domain` rather than §16's suggested `internal/probe` / `internal/detect` / `pkg/domain` split | At Phase-0 size, probing and detection are one bounded concern; `pkg/domain` implies a public API we do not offer yet. Recorded so it stops being re-litigated against §16. Revisit when the L2 collector genuinely shares types | §16 layout (for the scanner only) |
| 2026-09-20 (rev 6) | Detections are validated against **real** Ray/Jupyter/MLflow/Ollama containers; vLLM and Triton remain labelled fixtures | Unit tests only prove our logic agrees with our own mocks — a weaker claim than it sounds when RG-RAY-001 carries the whole ShadowRay pitch. vLLM/Triton ship GPU-bound multi-GB images; dressing mocks up as real would reproduce the blind spot the suite exists to remove, so the split is stated in the test output | — |
| 2026-09-25 (rev 7) | A scan that reached nothing grades **`N/A` (inconclusive)**, never `A+`, and exits 7 | An unresolvable hostname, a dark /24, and a genuinely clean host all produced an identical confident "A+ — No exposure was observed". That false all-clear is the most damaging thing this product could say, and it is exactly what a typo in front of a buyer — or a DNS change in a tenant's pipeline — would have produced. Clean grades now require at least one host that answered; partial coverage is disclosed on the report | prior grading, which ignored reachability |
| 2026-09-25 (rev 7) | Only a TCP RST (`ECONNREFUSED`) proves a host is alive | "No route to host" arrives promptly rather than as a timeout, so treating every non-timeout error as "closed" let an empty subnet look like a clean one. Caught by the integration suite, not by unit tests — the behaviour only appears once ARP has failed against a real network | — |
| 2026-09-20 (rev 6) | TLS handshake gets a bounded deadline separate from `-timeout` | Real Jupyter and MLflow accept a connection then wait silently for an HTTP request, so every open plaintext port burned the full probe timeout. Ray rejects a ClientHello in ~1ms, so **no mock ever exposed this** — it was found only by running against real services, which is the argument for the integration suite | — |

| 2026-10-10 (rev 8) | Every third-party GitHub Action is pinned to a **commit SHA** (with a `# vX.Y.Z` comment), Dependabot updates the pins weekly, the release token is scoped to the release job, and the release workflow **verifies the signatures it just produced** before publishing | `docs/threat-model.md` T6 already claimed "pinned actions", but the workflows used mutable major tags (`@v4`, `@v0`) on actions that run inside the job which builds and signs the binaries people point at GPU clusters — a repointed tag is a direct path to a trojaned release. Pinning without Dependabot would just trade tag risk for staleness. Self-verification matters because the release body instructs people to run `cosign verify-blob`: a signing step that silently produced an unverifiable signature would otherwise be discovered by the first person who took that instruction seriously. | tag-pinned actions; workflow-level write token |
| 2026-10-10 (rev 8) | `golangci-lint-action` v6 → v9, with the linter pinned to `v2.14` rather than `latest` | Action v7+ is required to drive golangci-lint **v2**, and `.golangci.yml` is now a v2 config — so the lint job could not have enforced the file it was pointed at. `latest` is not used because a future golangci-lint v3 would silently turn the gate off again in exactly the same way. A lint gate that cannot fail is worse than no gate: it reports green. | — |
| 2026-10-10 (rev 8) | `go.mod` stays at `go 1.22` while CI builds on Go 1.27 | The `go` directive is the **minimum needed to build**, not the newest available. Nothing in the scanner needs anything past 1.22, and requiring a brand-new toolchain to compile an air-gap-oriented single binary narrows who can build it offline — which is the opposite of the point (§15, P4). CI still uses the newest compiler so we get its checks. | a brief bump of go.mod to 1.27 |

| 2026-10-10 (rev 9) | The report footer states that grades are provisional **without citing `CLAUDE.md 10.0`**; the "a /24 completes in well under a minute" claim in `docs/assessment/objections.md` and the authorization template is replaced with the bound the code actually gives (~8 waves of 32 hosts x the probe timeout; measured 16.3s at `-timeout 2s`); and the four leaks planted to confirm the P3 suite fails are written up at the top of `test/metadata_only_test.go` | Found by reading the buyer-facing surface as a skeptic, which was the last open item on the publishing checklist. An internal engineering-document reference inside a deliverable handed to a security lead means nothing to them and invites a question about a file they will never see. The timing claim was exactly the kind a reviewer checks with a stopwatch against a filtered /24 - where it is ~30s at the default, which is true but is not "well under a minute". And the negative control was a claim made in a sales script with nothing in the repo to show: the mutations are now reproducible instead of remembered. | the footer's internal citation; the "well under a minute" claims |

| 2026-10-10 (rev 9) | Only `internal/scan` may import `net`, `net/http`, `os/exec` or `syscall`, enforced by `TestOnlyTheProbeMayReachTheNetwork` in the P3 suite | The README, SECURITY.md and threat model all tell a CISO that ray-guard cannot phone home *because there is no such code path* - a claim about every future version, which until now rested on nobody adding one. `internal/benchmark` is the pointed case: its output is the one artifact designed to be shared with us (P9), so "write a local file" and "POST it somewhere" are a one-line difference. Verified by planting `net/http` there and watching the suite go red. `net/netip` is allowed - address parsing, no I/O. | — |

| 2026-10-10 (rev 9) | The `-out` directory and the `-benchmark-snapshot` path are checked for writability **before** any probing starts; a failure exits 2 (usage), not 1 | Previously a scan ran to completion and *then* failed to write, discarding everything. On a /24 that is ~30s of a customer's cluster scanned and thrown away, and the fix is to scan them a second time - against an authorization that may well have been for one scan in one window (`docs/assessment/authorization.md`). Getting this wrong costs credibility in the room out of all proportion to the bug. | exiting 1 after a wasted scan |
| 2026-10-10 (rev 9) | `-cidr` and `-ports` are fuzzed, nightly in CI (`make fuzz`), with the seed corpora running in `make test` | These two parse strings an operator pastes on a command line, and `ExpandCIDR` does arithmetic on prefix lengths including a left shift. The properties asserted are the ones that keep a scan inside its authorization: every expanded target parses as an address, the `1<<18` ceiling holds, and **no `-ports` value can introduce a probe path the benign-path allowlist never reviewed** - which the existing allowlist test does not cover, since it only guards `DefaultChecks()`. ~1.25M executions per target found nothing, which is the result worth recording. | — |

> When you change any of the above, **add a new dated row** and set "Supersedes." Never edit history.

---

## 19. Glossary

- **CSPM / CNAPP / AI-SPM** — Cloud/AI security posture & protection categories we extend below the hardware line.
- **Neocloud** — GPU-as-a-service provider on bare metal (CoreWeave, Lambda, RunPod, Nebius, Voltage Park…).
- **P_Key / M_Key / SA_Key** — InfiniBand partition/management/subnet-admin keys; misconfiguration = cross-tenant fabric exposure.
- **RDMA / NVLink** — high-speed interconnects invisible to traditional cloud tools.
- **NVML** — NVIDIA Management Library (GPU telemetry).
- **DPU / BlueField / DOCA / DICE** — data processing unit, NVIDIA's DPU, its SDK, and its attestation root.
- **CC mode** — NVIDIA Confidential Computing (encrypted VRAM + attestation) on Hopper/Blackwell.
- **NRAS** — NVIDIA Remote Attestation Service.
- **SPDM** — Security Protocol and Data Model; session-based attestation used in privileged CC verification (L3).
- **SEV-SNP / TDX** — AMD / Intel confidential-VM attestation technologies (multi-vendor, §14.1 H2).
- **ShadowRay** — Ray RCE campaign (CVE-2023-48022 / CVE-2025-62593); our #1 demand-validation reference.
- **Verifiable Credential** — the signed, tamper-evident trust artifact we issue (moat #2).
- **Verification sentinel** — the paired finding_condition + verification_condition on every rule (§8).
- **Drift** — a cluster leaving its attested/baseline state; continuous detection is the "M" in posture Management.

---

## 20. Open Questions / Revisit

- Final product name + trademark.
- Graph store: confirm Apache AGE vs Neo4j against the §6.2 trigger after MVP load testing.
- Timescale vs ClickHouse threshold (revisit when telemetry volume is known).
- PQC scheme selection (ML-DSA-44 vs -65) — track NIST finalization + India CCA guidance; confirm VC payload budget.
- Cyber-insurance underwriting partner (§14.1 H1 ROI lever).
- Beachhead call: sovereign-first vs commercial-Neocloud-first — decide from the Phase-0 buyer-led assessments (P2).

---

*End of CLAUDE.md. Sections 1–3 = why. Sections 4–13 = how. Section 14 = order. Section 14.1 = deferred. Section 2 is binding.*
