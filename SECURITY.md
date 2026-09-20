# Security Policy

`ray-guard` is a security tool that people run against production GPU clusters.
That makes this project a high-value target in its own right, and we hold it to
a higher bar than we hold the infrastructure it assesses (CLAUDE.md P8).

## Reporting a vulnerability

Report privately — do not open a public issue.

- Use [GitHub private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
  on this repository.
- Include the version (`ray-guard -version`), what you did, and what happened.

We will acknowledge within 3 business days and keep you updated until the issue
is resolved. We will credit you in the advisory unless you prefer otherwise.

**In scope, and treated as critical regardless of exploitability:**

- Any path by which the scanner reads, stores, logs, or transmits customer
  payload — model weights, prompts, training data, inference content, or object
  contents. This is the P3 guarantee the product is sold on; see
  `docs/threat-model.md`.
- Any way to make a probe non-benign: cause it to send a request body, use a
  method other than GET, execute code on a target, or otherwise disrupt a
  running workload.
- Supply-chain issues: signature bypass, dependency confusion, release
  artifacts that do not match their SBOM or signature.

## Verifying a release

Every release artifact is signed with cosign keyless signing and ships with a
CycloneDX SBOM and SHA-256 checksums. Verify before running a binary against a
cluster:

```bash
cosign verify-blob \
  --certificate ray-guard-linux-amd64.pem \
  --signature  ray-guard-linux-amd64.sig \
  --certificate-identity-regexp '^https://github.com/karteekp20/gpu-security/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ray-guard-linux-amd64
```

## Using this tool

Only scan infrastructure you are authorized to assess. `ray-guard` is
read-only and benign by design — it confirms exposure by observation, never by
exploitation — but running any scanner against systems you do not own may
still be unlawful where you are.
