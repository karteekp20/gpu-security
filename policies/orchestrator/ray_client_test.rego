# Tests for RG-RAY-002. Both paths are mandatory (CLAUDE.md §8), and the third
# case protects the credential: a host nobody reached must NOT close the
# finding.
package gpusecurity.orchestrator.ray_client

import rego.v1

reachable := {
	"host": "10.0.0.5",
	"port": 10001,
	"service": "ray-client",
	"state": "open",
	"http_status": 0,
	"unauth": false,
	"tls": {"enabled": false},
	"host_state": "responded",
}

port_closed := {
	"host": "10.0.0.5",
	"port": 10001,
	"service": "ray-client",
	"state": "closed",
	"http_status": 0,
	"unauth": false,
	"tls": {"enabled": false},
	"host_state": "responded",
}

host_never_reached := {
	"host": "10.0.0.5",
	"port": 10001,
	"service": "ray-client",
	"state": "filtered",
	"http_status": 0,
	"unauth": false,
	"tls": {"enabled": false},
	"host_state": "no-response",
}

# An HTTP response on this port means a different rule applies, not this one.
speaks_http := {
	"host": "10.0.0.5",
	"port": 10001,
	"service": "ray-client",
	"state": "open",
	"http_status": 200,
	"unauth": true,
	"tls": {"enabled": false},
	"host_state": "responded",
}

test_finding_fires_on_a_reachable_control_port if {
	finding_condition with input as reachable
}

test_finding_does_not_fire_on_a_closed_port if {
	not finding_condition with input as port_closed
}

test_finding_does_not_fire_when_the_port_speaks_http if {
	not finding_condition with input as speaks_http
}

test_sentinel_closes_when_the_port_is_isolated if {
	verification_condition with input as port_closed
}

test_sentinel_does_not_close_on_a_host_we_never_reached if {
	not verification_condition with input as host_never_reached
}
