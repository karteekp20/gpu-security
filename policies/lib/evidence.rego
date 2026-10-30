# Shared evidence predicates for every verification sentinel.
#
# The one rule this file exists to enforce: A SENTINEL MUST NEVER BE
# SATISFIABLE BY ABSENCE OF EVIDENCE.
#
# A verification_condition that closes a finding because "the port no longer
# answers" is also satisfied by a host that was never reached - an unresolvable
# name, a dark subnet, a scan run from the wrong side of a firewall, or a
# cancelled run. The scanner already refuses to grade such a scan clean
# (docs/decision-log.md, 2026-09-25: a scan that reached nothing grades N/A,
# never A+). The same hazard is strictly worse here, because a closure feeds
# the signed credential: it would turn "we could not look" into "we attest it
# is fixed", cryptographically, over our name.
#
# So every closure predicate here requires host_reached first, and that
# requirement is tested (see evidence_test.rego and each rule's
# "dark host does not close" case).
package gpusecurity.lib

import rego.v1

# host_reached is the precondition for any closure: at least one port on this
# host gave a definitive answer in the scan being evaluated. Mirrors
# domain.HostResponded, and the collector joins it onto each observation.
host_reached(obs) if obs.host_state == "responded"

# isolated: the port no longer accepts connections, on a host we did reach.
# This is the "fixed by network isolation" path, which for several of these
# services is the only durable fix available (TorchServe is archived; Ray's
# Jobs API behaviour is by design).
isolated(obs) if {
	host_reached(obs)
	obs.state != "open"
}

# auth_enforced: the service still answers, and now demands credentials.
# Deliberately narrow - only an explicit 401 or 403 counts. A 5xx, a timeout
# or a redirect is not evidence that authentication was enabled.
auth_enforced(obs) if {
	host_reached(obs)
	obs.unauth == false
	obs.http_status == 401
}

auth_enforced(obs) if {
	host_reached(obs)
	obs.unauth == false
	obs.http_status == 403
}

# tls_terminated: the port now completes a TLS handshake.
tls_terminated(obs) if {
	host_reached(obs)
	obs.tls.enabled == true
}

# tls_chain_verified: TLS is on AND the presented chain verified cleanly.
# Both spellings of "no issue" are accepted because the field is omitempty in
# the scanner's JSON, so it arrives either absent or empty.
tls_chain_verified(obs) if {
	tls_terminated(obs)
	not obs.tls.issue
}

tls_chain_verified(obs) if {
	tls_terminated(obs)
	obs.tls.issue == ""
}

# tls_version_modern: the negotiated version is at or above the floor every
# current baseline sets (RFC 8996 deprecates 1.0 and 1.1).
tls_version_modern(obs) if {
	tls_terminated(obs)
	obs.tls.version in {"1.2", "1.3"}
}

# unauthenticated_http: the shape shared by every exposure rule - the service
# answered a benign GET without asking for credentials.
unauthenticated_http(obs) if {
	obs.unauth == true
	obs.http_status >= 200
	obs.http_status < 300
}

# reachable_tcp: an open port with no HTTP response to reason about. Used by
# the control/RPC-port rules, where reachability is the whole finding.
reachable_tcp(obs) if {
	obs.state == "open"
	obs.http_status == 0
}

# known_services is the set of services the L1 rule library can name. It
# exists for RG-TLS-002, which applies only where a *recognized* service
# demands credentials over plaintext - an unidentified port that returns 401
# is reported as an unidentified port, not as a plaintext-auth finding.
#
# This set is asserted equal to the scanner's own rule table in
# internal/scan/rule_parity_test.go: two implementations of one rule set is a
# drift risk, so the drift is a build failure rather than a surprise in a
# customer's report.
known_services := {
	"ray-dashboard",
	"ray-client",
	"vllm",
	"triton",
	"triton-grpc",
	"triton-metrics",
	"mlflow",
	"jupyter",
	"ollama",
	"slurmctld",
	"torchserve-mgmt",
	"torchserve-metrics",
	"sglang",
	"dcgm-exporter",
}

known_service(obs) if obs.service in known_services
