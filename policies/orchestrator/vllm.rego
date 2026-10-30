# RG-VLLM-001 - Unauthenticated vLLM inference API exposed
#
# Mirrors internal/scan/detect.go; parity is enforced by
# internal/scan/rule_parity_test.go.
package gpusecurity.orchestrator.vllm

import data.gpusecurity.lib
import rego.v1

# Detection: the service answered a benign GET on its own health path with a
# 2xx and did not ask for credentials.
finding_condition if {
	input.service == "vllm"
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
	"id": "RG-VLLM-001",
	"title": "Unauthenticated vLLM inference API exposed",
	"severity": "high",
	"cve": [],
	"remediation": "Place vLLM behind an authenticated gateway; do not expose the API directly.",
	"compliance": ["SOC2:CC6.1", "SOC2:CC6.6", "ISO27001:A.5.15", "ISO27001:A.8.20"]
}
