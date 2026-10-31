# RG-TORCHSERVE-001 - Unauthenticated TorchServe management API exposed
#
# Critical for the same reason as Ray: the management API registers a model
# from any URL the caller names, so reachability is execution. TorchServe
# answers 400 when a token is required, never 2xx, so this rule can only
# fire where token auth was switched off.
#
# Mirrors internal/scan/detect.go; parity is enforced by
# internal/scan/rule_parity_test.go.
package gpusecurity.orchestrator.torchserve_mgmt

import data.gpusecurity.lib
import rego.v1

# Detection: the service answered a benign GET on its own health path with a
# 2xx and did not ask for credentials.
finding_condition if {
	input.service == "torchserve-mgmt"
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
	input.service == "torchserve-mgmt"
	lib.isolated(input)
}

verification_condition if {
	input.service == "torchserve-mgmt"
	lib.auth_enforced(input)
}

finding_metadata := {
	"id": "RG-TORCHSERVE-001",
	"title": "Unauthenticated TorchServe management API exposed",
	"severity": "critical",
	"cve": ["CVE-2023-43654"],
	"remediation": "This answered without a token, so token authorization is disabled (--disable-token-auth) or this build predates it: re-enable it, bind the management API (8081) to loopback, and set allowed_urls to the registries you actually use. Note that the official pytorch/torchserve image ships a config.properties binding inference, management, metrics and both gRPC addresses to 0.0.0.0, so a container run from it is exposed on every interface by default. Upstream TorchServe is archived and will get no further security patches, so network isolation is the durable control rather than an upgrade.",
	"compliance": ["SOC2:CC6.1", "SOC2:CC6.6", "ISO27001:A.5.15", "ISO27001:A.8.20"]
}
