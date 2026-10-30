# Tests for RG-TLS-001. Both mandatory paths, plus two cases that would be
# easy to get wrong: a replaced-but-still-bad certificate must NOT close it,
# and neither must a host we never reached.
package gpusecurity.cloud.tls_certificate_invalid

import rego.v1

self_signed := {
	"host": "10.0.0.5", "port": 8265, "service": "tls", "state": "open",
	"http_status": 0, "unauth": false,
	"tls": {"enabled": true, "issue": "self-signed", "version": "1.3", "not_after": "2027-01-01"},
	"host_state": "responded",
}

expired := {
	"host": "10.0.0.5", "port": 8265, "service": "tls", "state": "open",
	"http_status": 0, "unauth": false,
	"tls": {"enabled": true, "issue": "expired", "version": "1.2", "not_after": "2024-01-01"},
	"host_state": "responded",
}

chain_verifies := {
	"host": "10.0.0.5", "port": 8265, "service": "tls", "state": "open",
	"http_status": 0, "unauth": false,
	"tls": {"enabled": true, "issue": "", "version": "1.3"},
	"host_state": "responded",
}

still_bad := {
	"host": "10.0.0.5", "port": 8265, "service": "tls", "state": "open",
	"http_status": 0, "unauth": false,
	"tls": {"enabled": true, "issue": "hostname-mismatch", "version": "1.3"},
	"host_state": "responded",
}

host_never_reached := {
	"host": "10.0.0.5", "port": 8265, "service": "tls", "state": "filtered",
	"http_status": 0, "unauth": false,
	"tls": {"enabled": true, "issue": "", "version": "1.3"},
	"host_state": "no-response",
}

test_finding_fires_on_a_self_signed_certificate if {
	finding_condition with input as self_signed
}

test_finding_fires_on_an_expired_certificate if {
	finding_condition with input as expired
}

test_finding_does_not_fire_when_the_chain_verifies if {
	not finding_condition with input as chain_verifies
}

test_sentinel_closes_when_the_chain_verifies if {
	verification_condition with input as chain_verifies
}

test_sentinel_does_not_close_on_a_replaced_but_still_invalid_certificate if {
	not verification_condition with input as still_bad
}

test_sentinel_does_not_close_on_a_host_we_never_reached if {
	not verification_condition with input as host_never_reached
}
