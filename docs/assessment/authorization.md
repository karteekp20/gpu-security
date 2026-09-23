# Scope & authorization

> **This is not legal advice.** It was drafted by engineers, not lawyers, as a
> practical starting point. Have it reviewed before your first real engagement,
> and defer to whatever your counterparty's legal or procurement team requires
> instead.

Running a network scanner against another organization's production
infrastructure without clear, written, specific permission is a bad idea
legally, contractually, and professionally — and "they said yes on a call" is
not that. Get it in writing, name the targets, and bound the window.

The good news: this is a short conversation, because the tool is read-only and
you can say exactly what it does.

---

## The short version (use this first)

For an early conversation, a signed document is usually too heavy. An email
with a reply saying "confirmed" is normally enough to start, and it creates the
record you need.

> **Subject: Scope confirmation — GPU exposure assessment**
>
> Hi <name>,
>
> Confirming what we agreed before I run anything.
>
> **What I'll scan:** <hosts / CIDR ranges>
> **When:** <date, time window, timezone>
> **From:** <your source IP>
> **What it is:** `ray-guard`, an open-source read-only exposure scanner —
> https://github.com/karteekp20/gpu-security
>
> It makes one TCP connection and at most one HTTP GET request per service to
> documented health endpoints (e.g. Ray's dashboard on 8265, vLLM's
> `/v1/models`). It sends no request bodies, uses no method other than GET,
> and attempts no exploitation. It needs no credentials and installs nothing.
>
> It does not read or store your model weights, prompts, training data,
> inference content, or object contents. It records only which services are
> reachable, whether they require authentication, and their TLS state.
>
> Traffic will carry the User-Agent `ray-guard/<version> (+benign posture
> probe)` so your SOC can identify it immediately. I'm reachable on <phone>
> throughout if anyone wants it stopped.
>
> You'll get the report; I'll hold a copy for <N> days and delete it on
> request.
>
> Anything outside the list above is out of scope and won't be touched. Reply
> "confirmed" and I'll go ahead.

---

## The longer form

Use when procurement or security governance wants a document.

### 1. Parties and contacts

| | Name | Role | Contact during the window |
| :-- | :-- | :-- | :-- |
| Assessor | | | |
| Client authorizing party | | | |
| Client technical contact | | | |
| Client SOC / on-call | | | |

The authorizing party must actually have authority over the listed systems.
If the targets are a slice rented from someone else, say so here — a tenant
usually cannot authorize scanning of infrastructure their provider owns. See
the vantage note below.

### 2. Scope

| Targets (hosts / CIDR) | Ports | Vantage | Notes |
| :-- | :-- | :-- | :-- |
| | default check set | provider-side / tenant-side | |

- **Anything not listed above is out of scope** and will not be probed.
- **Vantage** (CLAUDE.md §1.5): *provider-side* means the Neocloud scanning
  its own environment; *tenant-side* means a renter scanning the slice they
  control. In the tenant case, confirm in writing that the provider's terms
  permit it — the renter's authorization does not automatically extend to the
  provider's network.

### 3. Window

| | |
| :-- | :-- |
| Start | |
| End | |
| Timezone | |
| Expected duration | minutes, not hours — a /24 completes in well under a minute |

### 4. What the tool does

`ray-guard`, an open-source L1 agentless scanner. Full detail in
[`../threat-model.md`](../threat-model.md), which is worth sending along — it
is written for exactly the person reviewing this.

- **Read-only.** Confirms exposure by observation, never exploitation. It
  proves a door is unlocked by turning the handle, not by walking in.
- **One TCP connect, and at most one HTTP GET** per service check, to
  documented health/info endpoints. No request body. No method other than GET.
  Probe paths are restricted to a reviewed allowlist enforced in CI; anything
  containing a query string, path traversal, or an execution endpoint fails the
  build.
- **No credentials, no installation, no agent.** Nothing is deployed on any
  client system.
- **Bounded.** Default 32 concurrent hosts, 4s per-probe timeout, one request
  per check with no retries against a responding host.
- **Identifiable.** Fixed User-Agent `ray-guard/<version> (+benign posture
  probe)` from a single named source IP.

### 5. What the tool never touches

No model weights, prompts, training data, inference inputs or outputs, dataset
contents, KV-cache contents, or object-storage contents are read, stored,
logged, or transmitted — at any point, including in memory.

Response bodies are discarded without being inspected or parsed. Public
object-storage exposure is determined from the HTTP status code alone; bucket
listings are never read, because object keys are client data.

This is enforced by an automated test suite that blocks the build
(`make test-p3`), not by policy alone. The code and the tests are public.

### 6. Findings and data handling

| | |
| :-- | :-- |
| Deliverable | `report.html` and `report.json` |
| Contents | reachable services, authentication state, TLS state, severities, remediation |
| Client hostnames/IPs in report | yes — it is the client's own inventory |
| Payload in report | none exists to leak |
| Assessor retention | <N> days, then deleted; deleted sooner on request |
| Storage | <where> |
| Disclosure to third parties | none without written client consent |

**Optional — anonymized benchmark data.** With explicit opt-in, an anonymized
snapshot may be retained to seed a published industry benchmark. It contains
rule IDs, service names, ports, severities and a grade, with hostnames
replaced by salted hashes using a single-use random salt. It contains no
hostnames, IPs, finding details, or client-identifying information, and is
never generated unless requested.

- [ ] Client opts in to anonymized benchmark inclusion
- [ ] Client declines

### 7. Risk and stop conditions

The assessment is read-only and designed not to disrupt running workloads.
Honestly stated: a single GET to a health endpoint is the minimum possible
probe, but no scan of a live system is entirely without risk, and a fragile or
undocumented service could in principle respond badly.

The assessor will stop immediately on request from any listed contact, by any
means, without needing a reason.

### 8. Authorization

The undersigned confirms authority over the listed systems and authorizes the
assessment described above, within the stated window and scope.

| | Client | Assessor |
| :-- | :-- | :-- |
| Name | | |
| Role | | |
| Signature | | |
| Date | | |

---

## Before you send it

- Targets are specific. "Our infrastructure" is not a scope.
- The window is short and real.
- You have named a contact who can reach you during it.
- The person signing genuinely has authority over those systems.
- You've attached or linked [`../threat-model.md`](../threat-model.md).
