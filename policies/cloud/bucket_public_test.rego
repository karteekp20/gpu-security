# Tests for RG-BUCKET-001. The case worth writing down: a 5xx must not close
# the finding. An outage is not a permission change, and attesting a fix on
# an outage would be a false attestation.
package gpusecurity.cloud.bucket_public

import rego.v1

public := {
	"host": "bucket.s3.amazonaws.com", "port": 0, "service": "bucket",
	"state": "open", "http_status": 200, "unauth": true,
	"tls": {"enabled": true}, "host_state": "responded",
}

restricted := {
	"host": "bucket.s3.amazonaws.com", "port": 0, "service": "bucket",
	"state": "open", "http_status": 403, "unauth": false,
	"tls": {"enabled": true}, "host_state": "responded",
}

server_error := {
	"host": "bucket.s3.amazonaws.com", "port": 0, "service": "bucket",
	"state": "open", "http_status": 503, "unauth": false,
	"tls": {"enabled": true}, "host_state": "responded",
}

unreachable := {
	"host": "bucket.s3.amazonaws.com", "port": 0, "service": "bucket",
	"state": "open", "http_status": 0, "unauth": false,
	"tls": {"enabled": true}, "host_state": "no-response",
}

test_finding_fires_on_a_public_listing if finding_condition with input as public

test_finding_does_not_fire_when_listing_is_restricted if {
	not finding_condition with input as restricted
}

test_sentinel_closes_when_the_request_is_refused if {
	verification_condition with input as restricted
}

test_sentinel_does_not_close_on_a_server_error if {
	not verification_condition with input as server_error
}

test_sentinel_does_not_close_when_the_endpoint_was_unreachable if {
	not verification_condition with input as unreachable
}
