# Tests for RG-TLS-002. The sentinel needs BOTH halves - TLS terminated and
# auth still enforced - so the case that matters is a service that got TLS
# and lost its authentication. That is not a fix; it is a worse finding.
package gpusecurity.cloud.tls_plaintext_auth

import rego.v1

auth_over_plaintext := {
	"host": "10.0.0.5", "port": 8000, "service": "vllm", "state": "open",
	"http_status": 401, "unauth": false, "tls": {"enabled": false},
	"host_state": "responded",
}

forbidden_over_plaintext := {
	"host": "10.0.0.5", "port": 8000, "service": "triton", "state": "open",
	"http_status": 403, "unauth": false, "tls": {"enabled": false},
	"host_state": "responded",
}

# An unidentified port that returns 401 is reported as an unidentified port.
unknown_service := {
	"host": "10.0.0.5", "port": 9999, "service": "unknown", "state": "open",
	"http_status": 401, "unauth": false, "tls": {"enabled": false},
	"host_state": "responded",
}

fixed := {
	"host": "10.0.0.5", "port": 8000, "service": "vllm", "state": "open",
	"http_status": 401, "unauth": false,
	"tls": {"enabled": true, "issue": "", "version": "1.3"},
	"host_state": "responded",
}

tls_but_auth_removed := {
	"host": "10.0.0.5", "port": 8000, "service": "vllm", "state": "open",
	"http_status": 200, "unauth": true,
	"tls": {"enabled": true, "issue": "", "version": "1.3"},
	"host_state": "responded",
}

host_never_reached := {
	"host": "10.0.0.5", "port": 8000, "service": "vllm", "state": "filtered",
	"http_status": 401, "unauth": false,
	"tls": {"enabled": true, "version": "1.3"},
	"host_state": "unresolved",
}

test_finding_fires_on_401_over_plaintext if {
	finding_condition with input as auth_over_plaintext
}

test_finding_fires_on_403_over_plaintext if {
	finding_condition with input as forbidden_over_plaintext
}

test_finding_does_not_fire_for_an_unidentified_service if {
	not finding_condition with input as unknown_service
}

test_finding_does_not_fire_once_tls_terminates if {
	not finding_condition with input as fixed
}

test_sentinel_closes_when_tls_terminates_and_auth_remains if {
	verification_condition with input as fixed
}

test_sentinel_does_not_close_when_auth_was_removed_instead if {
	not verification_condition with input as tls_but_auth_removed
}

test_sentinel_does_not_close_on_a_host_we_never_reached if {
	not verification_condition with input as host_never_reached
}
