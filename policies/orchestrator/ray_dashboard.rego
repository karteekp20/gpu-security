# RG-RAY-001 - Unauthenticated Ray dashboard / Jobs API exposed
#
# Ray's Jobs API accepts job submissions from anyone who can reach it; that
# is the documented design, not a hardening gap. Reachability is code
# execution on the GPUs.
#
# Mirrors internal/scan/detect.go; parity is enforced by
# internal/scan/rule_parity_test.go.
package gpusecurity.orchestrator.ray_dashboard

import data.gpusecurity.lib
import rego.v1

# Detection: the service answered a benign GET on its own health path with a
# 2xx and did not ask for credentials.
finding_condition if {
	input.service == "ray-dashboard"
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
	input.service == "ray-dashboard"
	lib.isolated(input)
}

verification_condition if {
	input.service == "ray-dashboard"
	lib.auth_enforced(input)
}

finding_metadata := {
	"id": "RG-RAY-001",
	"title": "Unauthenticated Ray dashboard / Jobs API exposed",
	"severity": "critical",
	"cve": ["CVE-2023-48022", "CVE-2025-62593"],
	"remediation": "Enable Ray authentication or bind the dashboard to loopback/a private subnet; never expose port 8265 publicly.",
	"compliance": ["SOC2:CC6.1", "SOC2:CC6.6", "ISO27001:A.5.15", "ISO27001:A.8.20"]
}
