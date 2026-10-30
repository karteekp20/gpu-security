# Tests for RG-TLS-003. The case worth writing down: an UNKNOWN version must
# not close the finding. The scanner records "" for a version it cannot name,
# and "we could not tell" is not "fixed".
package gpusecurity.cloud.tls_obsolete_version

import rego.v1

tls10 := {
	"host": "10.0.0.5", "port": 8265, "service": "tls", "state": "open",
	"http_status": 0, "unauth": false,
	"tls": {"enabled": true, "version": "1.0", "issue": "self-signed"},
	"host_state": "responded",
}

tls11 := {
	"host": "10.0.0.5", "port": 8265, "service": "tls", "state": "open",
	"http_status": 0, "unauth": false,
	"tls": {"enabled": true, "version": "1.1", "issue": ""},
	"host_state": "responded",
}

tls13 := {
	"host": "10.0.0.5", "port": 8265, "service": "tls", "state": "open",
	"http_status": 0, "unauth": false,
	"tls": {"enabled": true, "version": "1.3", "issue": ""},
	"host_state": "responded",
}

version_unknown := {
	"host": "10.0.0.5", "port": 8265, "service": "tls", "state": "open",
	"http_status": 0, "unauth": false,
	"tls": {"enabled": true, "version": "", "issue": ""},
	"host_state": "responded",
}

host_never_reached := {
	"host": "10.0.0.5", "port": 8265, "service": "tls", "state": "filtered",
	"http_status": 0, "unauth": false,
	"tls": {"enabled": true, "version": "1.3"},
	"host_state": "probe-failed",
}

test_finding_fires_on_tls_1_0 if finding_condition with input as tls10

test_finding_fires_on_tls_1_1 if finding_condition with input as tls11

test_finding_does_not_fire_on_tls_1_3 if not finding_condition with input as tls13

test_sentinel_closes_on_tls_1_3 if verification_condition with input as tls13

test_sentinel_does_not_close_when_the_version_is_unknown if {
	not verification_condition with input as version_unknown
}

test_sentinel_does_not_close_on_a_host_we_never_reached if {
	not verification_condition with input as host_never_reached
}
