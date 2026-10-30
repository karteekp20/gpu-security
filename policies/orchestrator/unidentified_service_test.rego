# Tests for RG-EXPOSURE-001. Both mandatory paths, plus the dark-host case.
package gpusecurity.orchestrator.unidentified_service

import rego.v1

open_unidentified := {
	"host": "10.0.0.5", "port": 8080, "service": "unknown", "state": "open",
	"http_status": 0, "unauth": false, "tls": {"enabled": false},
	"host_state": "responded",
}

# The wildcard case: answers 2xx on a path that cannot exist, so the scanner
# refuses to name it. It is still an unidentified open port.
wildcard_server := {
	"host": "10.0.0.5", "port": 8265, "service": "unknown", "state": "open",
	"http_status": 200, "unauth": true, "tls": {"enabled": false},
	"host_state": "responded",
}

port_closed := {
	"host": "10.0.0.5", "port": 8080, "service": "unknown", "state": "closed",
	"http_status": 0, "unauth": false, "tls": {"enabled": false},
	"host_state": "responded",
}

host_never_reached := {
	"host": "10.0.0.5", "port": 8080, "service": "unknown", "state": "filtered",
	"http_status": 0, "unauth": false, "tls": {"enabled": false},
	"host_state": "unresolved",
}

test_finding_fires_on_an_unidentified_open_port if {
	finding_condition with input as open_unidentified
}

test_finding_fires_on_a_wildcard_server if {
	finding_condition with input as wildcard_server
}

test_finding_does_not_fire_on_a_closed_port if {
	not finding_condition with input as port_closed
}

test_sentinel_closes_when_the_port_is_isolated if {
	verification_condition with input as port_closed
}

test_sentinel_does_not_close_on_a_host_we_never_reached if {
	not verification_condition with input as host_never_reached
}
