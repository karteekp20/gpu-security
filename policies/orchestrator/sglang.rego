# RG-SGLANG-001 - Unauthenticated SGLang inference API exposed
#
# Mirrors internal/scan/detect.go; parity is enforced by
# internal/scan/rule_parity_test.go.
package gpusecurity.orchestrator.sglang

import data.gpusecurity.lib
import rego.v1

# Detection: the service answered a benign GET on its own health path with a
# 2xx and did not ask for credentials.
finding_condition if {
	input.service == "sglang"
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
	input.service == "sglang"
	lib.isolated(input)
}

verification_condition if {
	input.service == "sglang"
	lib.auth_enforced(input)
}

finding_metadata := {
	"id": "RG-SGLANG-001",
	"title": "Unauthenticated SGLang inference API exposed",
	"severity": "high",
	"cve": [],
	"remediation": "Place SGLang behind an authenticated gateway; bind --host to loopback or a private address rather than exposing port 30000.",
	"compliance": ["SOC2:CC6.1", "SOC2:CC6.6", "ISO27001:A.5.15", "ISO27001:A.8.20"]
}
