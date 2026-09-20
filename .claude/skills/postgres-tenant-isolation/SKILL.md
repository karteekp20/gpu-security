---
name: postgres-tenant-isolation
description: >
  Use when creating or altering any PostgreSQL table, migration, or query in the control plane.
  Enforces the CLAUDE.md §9 / data-model.md isolation model: shared-table pool multi-tenancy with
  tenant_id on every tenant-scoped table and Row-Level Security as the PRIMARY control. This is
  Phase 1. For a product that sells tenant isolation, a cross-tenant leak here is fatal — treat
  RLS as mandatory, not optional.
---

# PostgreSQL Tenant Isolation (CLAUDE.md §9, data-model.md §9)

Model: **shared database, shared tables, `tenant_id` per row** (pool) for SaaS; dedicated instance
for single-tenant/air-gapped. RLS is the primary, always-on control — not a backstop.

## Every tenant-scoped table MUST have
```sql
id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
tenant_id   uuid NOT NULL REFERENCES tenants(id),
-- ... columns ...
created_at  timestamptz NOT NULL DEFAULT now(),
updated_at  timestamptz
```
Reference-only tables (e.g. `compliance_frameworks`, `compliance_controls`) are global and may
omit `tenant_id` — mark them clearly as global reference data.

## Enable RLS on every tenant-scoped table
```sql
ALTER TABLE <table> ENABLE ROW LEVEL SECURITY;
ALTER TABLE <table> FORCE ROW LEVEL SECURITY;   -- applies even to table owner
CREATE POLICY tenant_isolation ON <table>
  USING (tenant_id = current_setting('app.current_tenant')::uuid)
  WITH CHECK (tenant_id = current_setting('app.current_tenant')::uuid);
```
Every migration that creates a tenant-scoped table MUST include the RLS enable + policy in the
same migration. A table without an RLS policy is a bug.

## Per-request wiring (non-negotiable)
- Resolve `tenant_id` from the authenticated principal's session/OIDC claims — **never** from a
  request body, query param, or client-supplied id (that is the classic IDOR hole).
- Inside the request transaction, before any query:
  ```sql
  SET LOCAL app.current_tenant = '<tenant-uuid-from-session>';
  ```
- Collectors/agents authenticate by mTLS cert bound to exactly one cluster/tenant; ingested rows
  inherit that tenant. Never trust a tenant id sent in an ingested payload.

## Additional rules
- Hash sensitive identifiers (`hostname_hash`, `gpu_uuid_hash`) — apply the metadata-only-guard
  skill; RLS protects rows, hashing protects the values inside them.
- Put variable/heterogeneous data in `jsonb` (GIN-index where queried); keep payload out (P3).
- Add the dedupe UNIQUE constraints from data-model.md (e.g. findings uniqueness).
- **Graph caveat:** the `CROSSES_TENANT_TO` traversal deliberately spans tenants and is
  operator-only and audited — it must NEVER be reachable from a tenant-facing API or query path.

## Definition of done
- New tenant-scoped table → migration includes `tenant_id`, FK, RLS enable, and policy.
- A test proves a query under tenant A cannot return tenant B's rows even without an explicit
  WHERE clause (RLS enforces it).
