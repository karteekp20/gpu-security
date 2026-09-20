# data-model.md — gpu-security Data Model

> Companion to `CLAUDE.md` (belongs at `/docs/data-model.md` in the repo). Concrete tables, columns, graph schema, and the isolation mechanics for every datastore named in CLAUDE.md §6.
> **Design authority order:** PostgreSQL is the **system of record**. Neo4j is a **derived projection** (rebuildable from Postgres). TimescaleDB holds time-series. Object storage holds immutable blobs. Redis is ephemeral.
>
> **Phasing (do not build it all at once — CLAUDE.md P1/P2):**
> - **Phase 0 (scanner + report):** *no database at all.* `ray-guard` runs standalone and emits a report file. Nothing below is needed yet.
> - **Phase 1 (control plane):** the tables tagged **[P1]** below.
> - **Phase 2:** **[P2]** (attestation, drift/Timescale, integrations).
> - **Phase 3 / on customer pull:** **[P3+]** (credentials/trust, Neo4j at scale, benchmark).

---

## Conventions

- Primary keys: `id UUID PRIMARY KEY DEFAULT gen_random_uuid()`.
- Every tenant-scoped table has `tenant_id UUID NOT NULL REFERENCES tenants(id)` — this is the RLS key (see §Isolation).
- Timestamps: `created_at timestamptz NOT NULL DEFAULT now()`, `updated_at timestamptz` (trigger-maintained).
- Enumerations shown as `text CHECK (... IN ...)` for portability (swap to native `ENUM` later if desired).
- Free-form / type-specific data in `jsonb` (GIN-indexed where queried).
- **P3 metadata-only (CLAUDE.md P3):** identifiers that could contain customer content are stored **hashed** (`*_hash` columns). Never store raw payloads.

---

## 1. PostgreSQL — Identity, Tenancy & Access

### `tenants` [P1]
| column | type | notes |
|---|---|---|
| id | uuid PK | |
| name | text NOT NULL | |
| slug | text UNIQUE | URL-safe |
| deployment_mode | text CHECK IN (saas, single_tenant, air_gapped) DEFAULT 'saas' | drives isolation model (§Isolation) |
| plan | text | |
| status | text CHECK IN (active, suspended) DEFAULT 'active' | |
| created_at / updated_at | timestamptz | |

### `users` [P1]
| column | type | notes |
|---|---|---|
| id | uuid PK | |
| tenant_id | uuid FK→tenants NOT NULL | RLS key |
| email | citext NOT NULL | |
| idp_subject | text | OIDC `sub` claim |
| display_name | text | |
| status | text CHECK IN (invited, active, disabled) DEFAULT 'invited' | |
| last_login_at | timestamptz | |
| created_at / updated_at | timestamptz | |
| | UNIQUE (tenant_id, email) | |

### `roles` [P1]
| column | type | notes |
|---|---|---|
| id | uuid PK | |
| tenant_id | uuid FK→tenants NULL | NULL = system/global role |
| name | text NOT NULL | |
| is_system | bool DEFAULT false | seeded roles (admin, security_analyst, auditor, read_only) |
| description | text | |
| permissions | jsonb NOT NULL DEFAULT '[]' | list of permission strings, e.g. `["finding:read","report:issue"]` |
| created_at / updated_at | timestamptz | |
| | UNIQUE (tenant_id, name) | |

> Seed system roles (map to CLAUDE.md §7.5 personas): `admin`, `security_analyst` (CISO/SecOps — read+remediate), `infra` (fix, no policy control), `auditor` (read + evidence export), `read_only` (buyer view). **Finalize the middle tiers from design-partner org structure — don't over-specify now.**

### `role_bindings` [P1]
| column | type | notes |
|---|---|---|
| id | uuid PK | |
| tenant_id | uuid FK→tenants NOT NULL | RLS key |
| user_id | uuid FK→users NOT NULL | |
| role_id | uuid FK→roles NOT NULL | |
| scope | text CHECK IN (tenant, cluster) DEFAULT 'tenant' | cluster-scoped roles supported |
| scope_id | uuid NULL | cluster id when scope='cluster' |
| created_at | timestamptz | |
| | UNIQUE (tenant_id, user_id, role_id, scope, scope_id) | |

### `sso_connections` [P1→P2]
| column | type | notes |
|---|---|---|
| id | uuid PK | |
| tenant_id | uuid FK→tenants NOT NULL | |
| protocol | text CHECK IN (oidc, saml) | |
| config | jsonb | issuer/client_id/metadata_url; **secrets in vault, ref only** |
| enabled | bool DEFAULT false | |
| created_at / updated_at | timestamptz | |

### `collectors` [P1] — machine identity for L1/L2/L3 agents (mTLS)
| column | type | notes |
|---|---|---|
| id | uuid PK | |
| tenant_id | uuid FK→tenants NOT NULL | |
| cluster_id | uuid FK→clusters NOT NULL | a collector maps to exactly one cluster (ingest isolation) |
| name | text | |
| tier | text CHECK IN (l1, l2, l3) | |
| cert_fingerprint | text | SHA-256 of mTLS client cert |
| enrolment_token_hash | text | one-time enrolment |
| status | text CHECK IN (pending, active, revoked) DEFAULT 'pending' | |
| last_seen_at | timestamptz | |
| created_at / updated_at | timestamptz | |

### `audit_log` [P1] — append-only (critical for a security product)
| column | type | notes |
|---|---|---|
| id | bigserial PK | |
| tenant_id | uuid | NULL for system events |
| actor_type | text CHECK IN (user, collector, system) | |
| actor_id | uuid | |
| action | text | e.g. `credential.issued`, `finding.status_changed` |
| resource_type / resource_id | text / uuid | |
| metadata | jsonb | |
| ip | inet | |
| created_at | timestamptz | index (tenant_id, created_at DESC) |

---

## 2. PostgreSQL — Inventory

### `clusters` [P1]
| column | type | notes |
|---|---|---|
| id | uuid PK | |
| tenant_id | uuid FK→tenants NOT NULL | RLS key |
| name | text NOT NULL | |
| provider | text | coreweave/lambda/runpod/nebius/self/… |
| region | text | |
| deployment_type | text CHECK IN (bare_metal, k8s, hybrid) | |
| fabric_type | text CHECK IN (infiniband, roce_v2, ethernet, mixed, unknown) DEFAULT 'unknown' | |
| enrolment_status | text CHECK IN (pending, active, disabled) DEFAULT 'pending' | |
| current_grade | text NULL | A+/A/B/C/F (CLAUDE.md §10.0); NULL until first scan |
| current_score | int NULL | 0–100 |
| last_scan_at | timestamptz | |
| created_at / updated_at | timestamptz | |

### `nodes` [P1]
| column | type | notes |
|---|---|---|
| id | uuid PK | |
| tenant_id | uuid FK NOT NULL | |
| cluster_id | uuid FK→clusters NOT NULL | |
| hostname_hash | text | **hashed (P3)** |
| role | text CHECK IN (head, worker, login, storage, unknown) | |
| gpu_count | int | |
| dpu_present | bool DEFAULT false | |
| driver_version | text | |
| firmware_version | text | |
| os | text | |
| secure_boot | bool NULL | |
| last_seen_at | timestamptz | |
| created_at / updated_at | timestamptz | |

### `gpus` [P1] (cc_* columns [P2])
| column | type | notes |
|---|---|---|
| id | uuid PK | |
| tenant_id | uuid FK NOT NULL | |
| node_id | uuid FK→nodes NOT NULL | |
| cluster_id | uuid FK→clusters NOT NULL | denormalized for query |
| gpu_uuid_hash | text | **hashed (P3)** |
| vendor | text CHECK IN (nvidia, amd, intel, other) | |
| model | text | H100/H200/B200/MI300X/Gaudi3/… |
| vram_gb | int | |
| cc_capable | bool NULL | |
| cc_claimed_enabled | bool NULL | **L2 observed** (`nvmlDeviceGetConfidentialComputeStatus`) |
| cc_verified | bool NULL | **L3 cryptographically verified** — never set from L2 |
| created_at / updated_at | timestamptz | |

### `fabric_partitions` [P1/P2]
| column | type | notes |
|---|---|---|
| id | uuid PK | |
| tenant_id | uuid FK NOT NULL | |
| cluster_id | uuid FK→clusters NOT NULL | |
| partition_type | text CHECK IN (ib_pkey, roce_vlan) | |
| key_value | text | P_Key hex / VLAN id (config metadata) |
| is_default_partition | bool DEFAULT false | flags the `0xffff` risk |
| member_node_count | int | |
| created_at / updated_at | timestamptz | |

### `assets` [P1] — generic long-tail (orchestrator endpoints, buckets, dashboards, IAM)
| column | type | notes |
|---|---|---|
| id | uuid PK | |
| tenant_id | uuid FK NOT NULL | |
| cluster_id | uuid FK NULL | |
| node_id | uuid FK NULL | |
| asset_type | text | orchestrator_endpoint / bucket / dashboard / iam_role / storage_path |
| subtype | text | ray / vllm / triton / slurm / mlflow / jupyter / ollama / s3 / … |
| identifier | text | normalized/hashed handle |
| exposure | text CHECK IN (public, internal, private, unknown) | |
| port | int NULL | 8265/8000/8001/6817/… |
| tls_enabled | bool NULL | |
| auth_enabled | bool NULL | |
| attributes | jsonb | type-specific (GIN) |
| first_seen_at / last_seen_at | timestamptz | |
| created_at / updated_at | timestamptz | |

---

## 3. PostgreSQL — Scanning, Findings & Verification

### `scans` [P1]
| column | type | notes |
|---|---|---|
| id | uuid PK | |
| tenant_id | uuid FK NOT NULL | |
| cluster_id | uuid FK NOT NULL | |
| collector_id | uuid FK NULL | |
| level | text CHECK IN (l1, l2, l3) | |
| mode | text CHECK IN (external, authorized, bundle) | ties to L1-A/B/C |
| status | text CHECK IN (queued, running, completed, failed) DEFAULT 'queued' | |
| rule_set_version | text | which rule library version ran |
| summary | jsonb | counts by severity |
| started_at / completed_at | timestamptz | |
| created_at | timestamptz | |

### `findings` [P1]
| column | type | notes |
|---|---|---|
| id | uuid PK | |
| tenant_id | uuid FK NOT NULL | |
| cluster_id | uuid FK NOT NULL | |
| asset_id | uuid FK NULL | |
| node_id | uuid FK NULL | |
| rule_id | text NOT NULL | e.g. `RG-RAY-001` |
| severity | text CHECK IN (critical, high, medium, low, info) | |
| title | text | |
| status | text CHECK IN (open, remediated_unverified, verified_closed, accepted_risk, false_positive) DEFAULT 'open' | the **verification sentinel** lifecycle (CLAUDE.md §8) |
| evidence_ref | uuid FK→evidence_index NULL | |
| compliance_refs | jsonb | control ids this finding maps to |
| first_seen_at / last_seen_at | timestamptz | |
| remediated_at / verified_closed_at | timestamptz NULL | |
| created_at / updated_at | timestamptz | |
| | UNIQUE (tenant_id, cluster_id, rule_id, COALESCE(asset_id, node_id)) | dedupe |

> **Rule:** `status = verified_closed` is set **only** when a scan's `verification_condition` passes — never from customer self-report (CLAUDE.md §8). This is what makes the credential trustworthy.

### `finding_events` [P1] — lifecycle audit trail
| column | type | notes |
|---|---|---|
| id | bigserial PK | |
| tenant_id | uuid NOT NULL | |
| finding_id | uuid FK→findings NOT NULL | |
| scan_id | uuid FK NULL | |
| event_type | text CHECK IN (created, remediation_detected, verification_passed, verification_failed, reopened, accepted, marked_fp) | |
| detail | jsonb | |
| created_at | timestamptz | |

---

## 4. PostgreSQL — Policy, Compliance, Attestation, Credentials

### `rule_sets` [P1] — metadata (Rego rules live as files in `/policies`, semver'd)
| column | type | notes |
|---|---|---|
| id | uuid PK | |
| version | text UNIQUE | semver |
| checksum | text | |
| source | text CHECK IN (built_in, custom) | |
| released_at | timestamptz | |
| notes | text | |

### `rule_state` [P1] — per-tenant enable / pin / override
| column | type | notes |
|---|---|---|
| id | uuid PK | |
| tenant_id | uuid FK NOT NULL | |
| rule_id | text NOT NULL | |
| enabled | bool DEFAULT true | |
| severity_override | text NULL | |
| pinned_rule_set_version | text NULL | |
| | UNIQUE (tenant_id, rule_id) | |

### `compliance_frameworks` [P1] & `compliance_controls` [P1] — reference (global, tenant_id NULL)
`compliance_frameworks`: id, key (soc2/iso27001/iso42001/nist_ai_rmf/eu_ai_act/hipaa/dpdp), name, version.
`compliance_controls`: id, framework_id FK, control_key (CC6.6 / A.8.20), title, description.

### `compliance_state` [P1/P2] — per control per cluster
| column | type | notes |
|---|---|---|
| id | uuid PK | |
| tenant_id | uuid FK NOT NULL | |
| cluster_id | uuid FK NOT NULL | |
| control_id | uuid FK→compliance_controls NOT NULL | |
| status | text CHECK IN (satisfied, partial, not_satisfied, not_applicable) | |
| evidence_finding_ids | jsonb | |
| evaluated_at | timestamptz | |
| | UNIQUE (tenant_id, cluster_id, control_id) | |

### `attestation_states` [P2] — normalized cross-vendor (CLAUDE.md §9)
| column | type | notes |
|---|---|---|
| id | uuid PK | |
| tenant_id | uuid FK NOT NULL | |
| cluster_id | uuid FK NOT NULL | |
| gpu_id | uuid FK NULL | |
| node_id | uuid FK NULL | |
| device_type | text CHECK IN (gpu, dpu, cpu_tee) | |
| vendor | text CHECK IN (nvidia, intel, amd) | |
| mode | text CHECK IN (cc_on, cc_off, unknown) | |
| **evidence_level** | text CHECK IN (observed, policy_compliant, verified_config, cryptographically_attested, runtime_validated) | the evidence-level ladder — makes "verified" precise |
| measured_firmware_hash | text NULL | |
| verifier | text | nras / intel_ta / self |
| result | text CHECK IN (pass, fail, indeterminate) | |
| evidence_ref | uuid FK→evidence_index | |
| verified_at | timestamptz | |
| created_at | timestamptz | |

### `credentials` [P3+] — issued trust credentials (only after the trust product is validated)
| column | type | notes |
|---|---|---|
| id | uuid PK | |
| tenant_id | uuid FK NOT NULL | |
| cluster_id | uuid FK NOT NULL | |
| grade | text | A+/A/B/C/F |
| score | int | |
| canonical_hash | text | hash of the W3C VC JSON |
| signature_ref | uuid FK→evidence_index | detached hybrid signature blob |
| sig_algorithms | text[] | e.g. `{ed25519, ml-dsa-65}` |
| public_slug | text UNIQUE | public verify URL segment |
| issued_at / expires_at | timestamptz | |
| revoked | bool DEFAULT false | |
| revoked_at / revocation_reason | timestamptz / text | |

### `integrations` [P2] & `evidence_index` [P1]
`integrations`: id, tenant_id FK, kind (slack/pagerduty/webhook/splunk/sentinel), config jsonb (**secrets in vault**), enabled, timestamps.

`evidence_index` [P1] — pointers to object-store blobs (never the blob in Postgres):
| column | type | notes |
|---|---|---|
| id | uuid PK | |
| tenant_id | uuid FK NOT NULL | |
| scan_id | uuid FK NULL | |
| object_key | text | path in S3/MinIO (§Object storage) |
| kind | text CHECK IN (raw_config, attestation_quote, report_pdf, credential_json, anonymized_snapshot) | |
| content_type | text | |
| sha256 | text | integrity |
| size_bytes | bigint | |
| created_at | timestamptz | |

---

## 5. Neo4j (or Apache AGE early) — the Correlation Graph [P2/P3]

> **Derived projection, not source of truth.** Built from Postgres; fully rebuildable. Start on Apache AGE; migrate to Neo4j per the CLAUDE.md §6.2 trigger. Every node carries `tenant_id` + `cluster_id` for scoping.

**Node labels (key properties):**
- `(:Cluster {id, tenant_id, name, grade})`
- `(:Node {id, tenant_id, cluster_id, role})`
- `(:GPU {id, tenant_id, cluster_id, model, cc_verified})`
- `(:DPU {id, tenant_id, cluster_id})`
- `(:FabricPartition {id, tenant_id, cluster_id, key_value, is_default})`
- `(:OrchestratorEndpoint {id, tenant_id, cluster_id, subtype, exposure, auth_enabled, port})`
- `(:Bucket {...})`, `(:IAMRole {...})`
- `(:Finding {id, tenant_id, rule_id, severity, status})`
- `(:AttestationState {id, tenant_id, evidence_level, result})`
- `(:Tenant {id})`

**Relationship types:**
- `(:Node)-[:HOSTS]->(:GPU)`
- `(:Node)-[:CONNECTED_VIA]->(:FabricPartition)`
- `(:Node)-[:EXPOSES]->(:OrchestratorEndpoint)`
- `(:Node)-[:CAN_REACH {via}]->(:Node)`
- `(:GPU)-[:ATTESTED_BY]->(:AttestationState)`
- `(asset)-[:AFFECTED_BY]->(:Finding)`
- `(:Finding)-[:ESCALATES_TO]->(:Finding)`
- `(asset)-[:BELONGS_TO]->(:Tenant)`
- `(:Node)-[:CROSSES_TENANT_TO]->(:Node)` — the killer edge

> **Isolation caveat (important):** ordinary tenant queries MUST filter `WHERE n.tenant_id = $tenant`. The `CROSSES_TENANT_TO` analysis *intentionally* spans tenants — it is an **operator-only, audited, internal** query and must NEVER be reachable through a tenant-facing API. This is the one deliberate exception to tenant isolation, and it exists only to find cross-tenant risk, never to expose it.

---

## 6. TimescaleDB (Postgres extension) — Time-Series [P2]

Hypertables (partitioned on `time`):
- `posture_score_history (time, tenant_id, cluster_id, score, grade)` — the drift/trend line.
- `attestation_drift (time, tenant_id, cluster_id, gpu_id, cc_state, drift_detected bool)` — is CC mode *still* on.
- `telemetry_samples (time, tenant_id, cluster_id, node_id, metric, value)` — L2/L3 samples.

Current-state lives in the relational tables (`clusters.current_grade`, `gpus.cc_*`); Timescale holds the history.

---

## 7. Object Storage (S3 / MinIO) — Immutable Blobs

Key layout (tenant-prefixed → per-tenant bucket policies):
```
{tenant_id}/evidence/{scan_id}/{evidence_id}.json      # raw config snapshots (metadata only)
{tenant_id}/attestation/{gpu_id}/{ts}.quote            # NRAS/DICE quotes
{tenant_id}/reports/{report_id}.pdf                    # generated trust reports
{tenant_id}/credentials/{credential_id}.json           # signed W3C VC + detached sig
anonymized/{yyyy-mm-dd}/{hash}.json                    # benchmark index — SEPARATE prefix, de-tenantized, OPT-IN only
```
The `anonymized/` prefix is physically separated from tenant data and only written when the tenant has explicitly opted in (resolves the P3↔P9 tension).

---

## 8. Redis — Ephemeral (cache / rate-limit) [P1]

Key patterns (never the system of record):
```
cache:asset:{tenant_id}:{asset_id}      # short-TTL lookups
cache:policy:{rule_set_version}         # compiled-policy cache
ratelimit:api:{tenant_id}:{window}
ratelimit:enrol:{ip}:{window}
```
Prefer NATS for durable job coordination (air-gap friendly); keep Redis for cache + rate-limit only.

---

## 9. Isolation — how it is actually enforced

The multi-tenant model is **shared database, shared tables, `tenant_id` per row** (pool model) for the SaaS tier; **dedicated instance** for single-tenant and air-gapped tiers (physical isolation). Four concentric layers:

1. **Identity** — OIDC/SSO resolves the user's `tenant_id` from session claims (never from request body/params — that would be the classic IDOR hole).
2. **Application** — a query layer refuses any query that isn't tenant-scoped.
3. **Database (primary control, not a backstop)** — Postgres RLS enforces the boundary at the engine, so even a buggy query cannot cross tenants. Per request, set the tenant on the session:
   ```sql
   -- once per table
   ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
   CREATE POLICY tenant_isolation ON findings
     USING (tenant_id = current_setting('app.current_tenant')::uuid);

   -- per request, inside the transaction, after auth resolves the tenant
   SET LOCAL app.current_tenant = '<tenant-uuid-from-session>';
   ```
4. **Storage** — object-store keys are tenant-prefixed with per-tenant access policies; collectors' mTLS certs bind to one cluster/tenant so ingest can only land in that tenant's rows.

> For a product that *sells* tenant isolation, RLS is treated as the **primary, always-on** control, not a safety net — a cross-tenant leak in this tool specifically would be fatal. Offer schema- or DB-level separation as a paid SaaS tier to buyers who demand it.

---

## 10. Minimal Phase-1 build set

If/when the Phase-0 gate is passed and the control plane is built, the smallest coherent schema is:
`tenants`, `users`, `roles`, `role_bindings`, `collectors`, `audit_log`, `clusters`, `nodes`, `gpus`, `assets`, `scans`, `findings`, `finding_events`, `rule_sets`, `rule_state`, `evidence_index`, plus reference `compliance_frameworks` / `compliance_controls` / `compliance_state`.

Everything else (`attestation_states`, `credentials`, Neo4j, Timescale, `integrations`) arrives at the phase it is actually needed — do not create it speculatively.
