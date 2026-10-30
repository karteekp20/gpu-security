# RG-RAY-002 - Ray client server port reachable
#
# Reachability-only: the port speaks no HTTP, so there is no auth state to
# observe. Isolation is the only closure this rule can verify.
#
# Mirrors internal/scan/detect.go; parity is enforced by
# internal/scan/rule_parity_test.go.
package gpusecurity.orchestrator.ray_client

import data.gpusecurity.lib
import rego.v1

# Detection: the port is open and speaks no HTTP, so reachability is the
# whole finding.
finding_condition if {
	input.service == "ray-client"
	lib.reachable_tcp(input)
}

# Verification sentinel: isolation only. There is no auth state to observe on
# a port that speaks no HTTP, so this rule deliberately offers one closure
# rather than inventing a second. Requires a host that answered.
verification_condition if lib.isolated(input)

finding_metadata := {
	"id": "RG-RAY-002",
	"title": "Ray client server port reachable",
	"severity": "high",
	"cve": [],
	"remediation": "Restrict the Ray client port (10001) to trusted networks only.",
	"compliance": ["SOC2:CC6.6", "ISO27001:A.8.20"]
}
