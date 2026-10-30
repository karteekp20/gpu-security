# RG-TRITON-002 - Triton metrics endpoint publicly reachable
#
# Prometheus-style endpoint: it answers 2xx on any path by design, so the
# scanner's wildcard control is deliberately not applied to it
# (docs/decision-log.md, 2026-10-10).
#
# Mirrors internal/scan/detect.go; parity is enforced by
# internal/scan/rule_parity_test.go.
package gpusecurity.orchestrator.triton_metrics

import data.gpusecurity.lib
import rego.v1

# Detection: the service answered a benign GET on its own health path with a
# 2xx and did not ask for credentials.
finding_condition if {
	input.service == "triton-metrics"
	lib.unauthenticated_http(input)
}

# Verification sentinel. Two deterministic closures, and nothing else:
#   - the port no longer accepts connections (isolation), or
#   - the service now answers 401/403 (authentication enforced).
# Both require the host to have answered in the verifying scan, so a dark
# subnet cannot close this finding. See policies/lib/evidence.rego.
verification_condition if lib.isolated(input)

verification_condition if lib.auth_enforced(input)

finding_metadata := {
	"id": "RG-TRITON-002",
	"title": "Triton metrics endpoint publicly reachable",
	"severity": "low",
	"cve": [],
	"remediation": "Restrict the metrics port (8002) to your monitoring network.",
	"compliance": ["SOC2:CC6.6", "ISO27001:A.8.20"]
}
