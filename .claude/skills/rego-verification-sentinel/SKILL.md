---
name: rego-verification-sentinel
description: >
  Use when writing or editing any OPA/Rego security rule for the policy engine, or its tests.
  Enforces CLAUDE.md §8: every rule MUST define BOTH a finding_condition and a
  verification_condition, plus finding_metadata and a matching *_test.rego. This is Phase 1, but
  it encodes a binding convention — a finding may only auto-close when verified, which is what
  makes the trust credential trustworthy. CI rejects any rule missing either condition.
---

# Rego Verification Sentinels (CLAUDE.md §8)

Every security rule is a *sentinel*: it detects a problem AND deterministically verifies the fix.
"Verified fixed" is only ever set by the `verification_condition` passing on a later scan — never
by customer self-report. This is load-bearing for the signed credential.

## Required shape (every rule)
```rego
package gpusecurity.<domain>.<name>   # domain ∈ orchestrator|fabric|hardware|attestation|k8s|cloud

# Detection: raises the finding
finding_condition {
    # ... predicate over input ...
}

# Verification sentinel: deterministic proof the fix landed → allows auto-close
verification_condition {
    # ... predicate proving remediation ...
}

finding_metadata := {
    "id": "RG-<DOMAIN>-NNN",          # stable, unique
    "title": "...",
    "severity": "critical|high|medium|low|info",
    "cve": ["..."],                       # ONLY CVEs this tier can assert
    "cve_unconfirmed": [                  # cited but not asserted; see below
        {"id": "...", "fixed_in": "...", "why": "the check that settles it"}
    ],
    "remediation": "the corrected config, not just 'fix it'",
    "compliance": ["SOC2:CC6.6", "ISO27001:A.8.20"]   # maps to §11
}
```

## Rules for the rules
- Both `finding_condition` and `verification_condition` are mandatory. A rule with only one is
  rejected in CI. If you cannot express a deterministic verification, the check is not ready to
  ship — say so rather than shipping a half-rule.
- `verification_condition` must be *deterministic* and *specific*. Prefer several typed clauses
  (OR-ed) over a vague catch-all.
- Be honest about what "verified" means — align severity and remediation with the evidence level
  actually achievable (see the attestation evidence-level ladder in data-model.md
  `attestation_states.evidence_level`). "Config matches policy" is not "tenant isolation proven."
- Keep rules pure over `input`; no imperative logic. If a check needs imperative/ML logic, route
  it to the Python policy layer, not Rego.
- **A CVE with a published fixed version may not go in `cve`.** The scanner decides every rule
  from a status code and reads no response bodies, so it never learns a version: asserting a
  version-gated CVE is a claim about something nobody looked at, and it is refuted by an operator
  typing one command. Put it in `cve_unconfirmed` with the advisory's `fixed_in` and a `why` that
  names the check a reader can run themselves. Go/Rego parity on both lists is enforced by
  `TestGoAndRegoRuleSetsAgree`, and the asserted list is checked against an independently
  recorded table of advisory facts (`advisoryFacts` in `internal/scan/detect_test.go`) — so a new
  CVE has to be looked up before it can ship.

## Tests are mandatory
Every rule ships `<name>_test.rego` asserting BOTH:
1. a positive finding trigger (the bad state raises the finding), and
2. a positive remediation closure (the fixed state passes `verification_condition`).
Run `opa test`. CI fails on a rule without a passing test for both paths.

## Naming & placement
- ID: `RG-<DOMAIN>-NNN`, unique, never reused.
- File: `/policies/<domain>/<name>.rego` + `/policies/<domain>/<name>_test.rego`.
- The rule library is semver'd and shipped as data (air-gap: signed bundle per §13).
