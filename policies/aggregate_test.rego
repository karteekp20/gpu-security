package gpusecurity.aggregate

import rego.v1

exposed_ray := {
	"host": "10.0.0.5", "port": 8265, "service": "ray-dashboard", "state": "open",
	"http_status": 200, "unauth": true, "tls": {"enabled": false},
	"host_state": "responded",
}

# Auth enforced, but over plaintext: the exposure rule must stand down and
# RG-TLS-002 must take over. One observation, one finding, different rule.
auth_over_plaintext := {
	"host": "10.0.0.5", "port": 8265, "service": "ray-dashboard", "state": "open",
	"http_status": 401, "unauth": false, "tls": {"enabled": false},
	"host_state": "responded",
}

# Auth enforced over TLS: nothing is wrong here, and the library has to be
# able to say so. A rule set that cannot be quiet is not believed.
secured_over_tls := {
	"host": "10.0.0.5", "port": 8265, "service": "ray-dashboard", "state": "open",
	"http_status": 401, "unauth": false,
	"tls": {"enabled": true, "issue": "", "version": "1.3"},
	"host_state": "responded",
}

dark_host := {
	"host": "10.0.0.9", "port": 8265, "service": "ray-dashboard", "state": "filtered",
	"http_status": 0, "unauth": false, "tls": {"enabled": false},
	"host_state": "unresolved",
}

test_findings_names_the_rule_that_fired if {
	findings == {"RG-RAY-001"} with input as exposed_ray
}

test_a_fully_secured_service_fires_nothing if {
	count(findings) == 0 with input as secured_over_tls
}

# The handover case: no rule needs to know about any other rule for this to
# come out right, which is what the walk over data.gpusecurity buys.
test_plaintext_auth_replaces_the_exposure_finding if {
	findings == {"RG-TLS-002"} with input as auth_over_plaintext
}

test_verified_names_the_closures_that_hold if {
	verified == {"RG-RAY-001"} with input as auth_over_plaintext
	verified == {"RG-RAY-001", "RG-TLS-002"} with input as secured_over_tls
}

# Scoping: a sentinel may only speak about observations it applies to. Before
# the verification conditions bound their own service, a Ray observation
# returning 401 satisfied RG-BUCKET-001's closure - "the unauthenticated
# request was refused" is true of it, and completely irrelevant.
test_a_sentinel_does_not_close_an_unrelated_rule if {
	not "RG-BUCKET-001" in verified with input as auth_over_plaintext
	not "RG-EXPOSURE-001" in verified with input as auth_over_plaintext
}

# The property the credential rests on, asserted at the aggregate level too:
# an unreached host closes nothing at all, whichever rule is asked.
test_nothing_is_verified_on_a_host_we_never_reached if {
	count(verified) == 0 with input as dark_host
}

test_metadata_catalogue_is_keyed_by_rule_id if {
	metadata["RG-RAY-001"].severity == "critical"
	metadata["RG-TORCHSERVE-001"].severity == "critical"
	metadata["RG-EXPOSURE-001"].severity == "info"
	count(metadata) == 19
}
