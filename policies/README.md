# policies/

OPA/Rego rule library (CLAUDE.md 8). **Phase 1** — not built in Phase 0.

Every rule MUST follow the `rego-verification-sentinel` skill:
`finding_condition` + `verification_condition` + `finding_metadata` + a matching `*_test.rego`.

Planned domains: orchestrator/ fabric/ hardware/ attestation/ k8s/ cloud/
