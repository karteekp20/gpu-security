# RG-TRITON-001 - Unauthenticated NVIDIA Triton server exposed
#
# Mirrors internal/scan/detect.go; parity is enforced by
# internal/scan/rule_parity_test.go.
package gpusecurity.orchestrator.triton

import data.gpusecurity.lib
import rego.v1

# Detection: the service answered a benign GET on its own health path with a
# 2xx and did not ask for credentials.
finding_condition if {
	input.service == "triton"
	lib.unauthenticated_http(input)
}

# Verification sentinel. Two deterministic closures, and nothing else:
#   - the port no longer accepts connections (isolation), or
#   - the service now answers 401/403 (authentication enforced).
#
# Both bind the service and require the host to have answered in the
# verifying scan, so neither a dark subnet nor an unrelated observation can
# close this finding. See policies/lib/evidence.rego for the precondition and
# policies/README.md for how the control plane builds this input.
verification_condition if {
	input.service == "triton"
	lib.isolated(input)
}

verification_condition if {
	input.service == "triton"
	lib.auth_enforced(input)
}

finding_metadata := {
	"id": "RG-TRITON-001",
	"title": "Unauthenticated NVIDIA Triton server exposed",
	"severity": "high",
	"cve": [],
	"remediation": "Restrict Triton HTTP/gRPC endpoints to trusted networks; add an auth proxy.",
	"compliance": ["SOC2:CC6.1", "SOC2:CC6.6", "ISO27001:A.5.15", "ISO27001:A.8.20"]
}
