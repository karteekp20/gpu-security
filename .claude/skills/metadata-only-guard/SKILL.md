---
name: metadata-only-guard
description: >
  Use whenever writing or editing any code that touches a customer environment or persists data
  derived from it — the ray-guard scanner, collectors, the L2 DaemonSet, the ingestion gateway,
  any parser, or any DB write of scanned data. Enforces the project's P3 non-negotiable: ZERO
  payload access. This is a safety-critical, existential guarantee we sell on — a single violation
  can end the company. Consult this BEFORE writing collection, parsing, or persistence code.
---

# Metadata-Only Guarantee (CLAUDE.md P3)

We are a security product that promises customers we never read their model weights, prompts,
training data, or inference payloads. This guarantee is enforced in code and in tests — not in a
marketing page.

## Absolute prohibitions (never do these)
- Never read, buffer, log, or transmit: model weights, prompts, inference inputs/outputs, training
  data, dataset contents, KV-cache contents, file contents of customer storage.
- Never store raw hostnames, raw internal IPs, GPU serials, container names, or bucket contents.
- Never send an exploit payload or anything that executes code to a target. Detection is
  read-only and benign (see the ray-guard-scanner skill). Confirm exposure by observation, not by
  exploitation.
- Never widen a scan to fetch a resource's *contents* to "enrich" a finding. Existence, exposure,
  config state, and version are metadata; contents are payload.

## Required patterns
- **Hash identifiers at the edge.** Store `hostname_hash`, `gpu_uuid_hash`, normalized/hashed
  asset identifiers — never the raw value. (See data-model.md `nodes`, `gpus`.)
- **Strip and anonymize in the collector**, before anything leaves the customer environment.
- **Persist only metadata fields**: exposure state, port, tls_enabled, auth_enabled, versions,
  config flags, counts, hashes, timestamps. Put variable metadata in `jsonb`, never payload.
- **Evidence blobs** in object storage hold config snapshots and attestation quotes only — never
  customer content. Reference them via `evidence_index`, never inline payload.

## Definition of done (enforce in tests)
- There MUST be a test suite (`/test`) that fails the build if any payload-shaped data can cross
  the collector boundary. When you add a new collector/parser field, add a test asserting it
  cannot carry payload.
- Structured logs contain no payloads and no raw identifiers.

## When unsure
If you cannot tell whether a value is metadata or payload, treat it as payload and exclude it.
"Existence and configuration" is safe; "contents" is not. Flag the ambiguity in the PR rather
than guessing toward inclusion.
