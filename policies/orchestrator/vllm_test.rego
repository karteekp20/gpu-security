# Tests for RG-VLLM-001. Both paths are mandatory (CLAUDE.md §8): the bad state
# raises the finding, and the fixed state satisfies the sentinel.
#
# The third case is the one that protects the credential: a host nobody
# reached must NOT close the finding. "We could not look" is not "we attest
# it is fixed".
package gpusecurity.orchestrator.vllm

import rego.v1

exposed := {
	"host": "10.0.0.5",
	"port": 8265,
	"service": "vllm",
	"state": "open",
	"http_status": 200,
	"unauth": true,
	"tls": {"enabled": false},
	"host_state": "responded",
}

auth_enabled := {
	"host": "10.0.0.5",
	"port": 8265,
	"service": "vllm",
	"state": "open",
	"http_status": 401,
	"unauth": false,
	"tls": {"enabled": false},
	"host_state": "responded",
}

port_closed := {
	"host": "10.0.0.5",
	"port": 8265,
	"service": "vllm",
	"state": "closed",
	"http_status": 0,
	"unauth": false,
	"tls": {"enabled": false},
	"host_state": "responded",
}

# Same shape as port_closed, except the host never answered at all.
host_never_reached := {
	"host": "10.0.0.5",
	"port": 8265,
	"service": "vllm",
	"state": "filtered",
	"http_status": 0,
	"unauth": false,
	"tls": {"enabled": false},
	"host_state": "unresolved",
}

test_finding_fires_on_unauthenticated_exposure if {
	finding_condition with input as exposed
}

test_finding_does_not_fire_once_auth_is_enforced if {
	not finding_condition with input as auth_enabled
}

test_sentinel_closes_when_auth_is_enforced if {
	verification_condition with input as auth_enabled
}

test_sentinel_closes_when_the_port_is_isolated if {
	verification_condition with input as port_closed
}

test_sentinel_does_not_close_on_a_host_we_never_reached if {
	not verification_condition with input as host_never_reached
}
