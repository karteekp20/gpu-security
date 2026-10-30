# RG-OLLAMA-001 - Unauthenticated Ollama API exposed
#
# Mirrors internal/scan/detect.go; parity is enforced by
# internal/scan/rule_parity_test.go.
package gpusecurity.orchestrator.ollama

import data.gpusecurity.lib
import rego.v1

# Detection: the service answered a benign GET on its own health path with a
# 2xx and did not ask for credentials.
finding_condition if {
	input.service == "ollama"
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
	"id": "RG-OLLAMA-001",
	"title": "Unauthenticated Ollama API exposed",
	"severity": "medium",
	"cve": [],
	"remediation": "Restrict the Ollama API (11434) to localhost/trusted networks.",
	"compliance": ["SOC2:CC6.1", "SOC2:CC6.6", "ISO27001:A.5.15", "ISO27001:A.8.20"]
}
