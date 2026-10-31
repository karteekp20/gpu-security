# RG-TRITON-003 - NVIDIA Triton gRPC endpoint reachable
#
# Mirrors internal/scan/detect.go; parity is enforced by
# internal/scan/rule_parity_test.go.
package gpusecurity.orchestrator.triton_grpc

import data.gpusecurity.lib
import rego.v1

# Detection: the port is open and speaks no HTTP, so reachability is the
# whole finding.
finding_condition if {
	input.service == "triton-grpc"
	lib.reachable_tcp(input)
}

# Verification sentinel: isolation only, bound to this service. There is no
# auth state to observe on a port that speaks no HTTP, so this rule
# deliberately offers one closure rather than inventing a second. Requires a
# host that answered.
verification_condition if {
	input.service == "triton-grpc"
	lib.isolated(input)
}

finding_metadata := {
	"id": "RG-TRITON-003",
	"title": "NVIDIA Triton gRPC endpoint reachable",
	"severity": "medium",
	"cve": [],
	"remediation": "Restrict the Triton gRPC port (8001) to trusted networks; front it with an auth proxy.",
	"compliance": ["SOC2:CC6.6", "ISO27001:A.8.20"]
}
