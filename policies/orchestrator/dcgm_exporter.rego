# RG-DCGM-001 - NVIDIA DCGM exporter publicly reachable
#
# Medium rather than low, and the distinction is the point: unlike one
# service's counters, DCGM labels per-GPU utilization with the pod and
# namespace using each device. An exposed exporter is a workload inventory
# of every tenant on the node.
#
# Mirrors internal/scan/detect.go; parity is enforced by
# internal/scan/rule_parity_test.go.
package gpusecurity.orchestrator.dcgm_exporter

import data.gpusecurity.lib
import rego.v1

# Detection: the service answered a benign GET on its own health path with a
# 2xx and did not ask for credentials.
finding_condition if {
	input.service == "dcgm-exporter"
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
	"id": "RG-DCGM-001",
	"title": "NVIDIA DCGM exporter publicly reachable",
	"severity": "medium",
	"cve": [],
	"remediation": "Restrict port 9400 to your monitoring network (in Kubernetes, a ClusterIP service with internalTrafficPolicy: Local rather than a NodePort). The metrics name the pod and namespace using each GPU, so this enumerates tenant workloads.",
	"compliance": ["SOC2:CC6.6", "ISO27001:A.8.12", "ISO27001:A.8.20"]
}
