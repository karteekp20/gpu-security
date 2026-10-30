package gpusecurity.lib

import rego.v1

# The load-bearing test in this library: a host we never reached must not
# satisfy any closure predicate. Every other test here is ordinary; this one is
# the difference between "we attest it is fixed" and "we could not look".
test_no_closure_predicate_is_satisfied_by_an_unreached_host if {
	for_each_unreached := [
		{"state": "filtered", "host_state": "unresolved", "unauth": false, "http_status": 401, "tls": {"enabled": true, "version": "1.3", "issue": ""}},
		{"state": "filtered", "host_state": "no-response", "unauth": false, "http_status": 403, "tls": {"enabled": true, "version": "1.2", "issue": ""}},
		{"state": "filtered", "host_state": "probe-failed", "unauth": false, "http_status": 401, "tls": {"enabled": true, "version": "1.3", "issue": ""}},
	]
	every obs in for_each_unreached {
		not isolated(obs)
		not auth_enforced(obs)
		not tls_terminated(obs)
		not tls_chain_verified(obs)
		not tls_version_modern(obs)
	}
}

test_isolated_requires_a_reached_host if {
	isolated({"state": "closed", "host_state": "responded"})
	isolated({"state": "filtered", "host_state": "responded"})
	not isolated({"state": "open", "host_state": "responded"})
	not isolated({"state": "closed", "host_state": "no-response"})
}

test_auth_enforced_accepts_only_401_and_403 if {
	auth_enforced({"host_state": "responded", "unauth": false, "http_status": 401})
	auth_enforced({"host_state": "responded", "unauth": false, "http_status": 403})
	not auth_enforced({"host_state": "responded", "unauth": false, "http_status": 500})
	not auth_enforced({"host_state": "responded", "unauth": false, "http_status": 302})
	not auth_enforced({"host_state": "responded", "unauth": true, "http_status": 200})
}

test_tls_chain_verified_accepts_absent_or_empty_issue if {
	tls_chain_verified({"host_state": "responded", "tls": {"enabled": true}})
	tls_chain_verified({"host_state": "responded", "tls": {"enabled": true, "issue": ""}})
	not tls_chain_verified({"host_state": "responded", "tls": {"enabled": true, "issue": "self-signed"}})
	not tls_chain_verified({"host_state": "responded", "tls": {"enabled": false}})
}

test_tls_version_modern_rejects_the_obsolete_versions if {
	tls_version_modern({"host_state": "responded", "tls": {"enabled": true, "version": "1.2"}})
	tls_version_modern({"host_state": "responded", "tls": {"enabled": true, "version": "1.3"}})
	not tls_version_modern({"host_state": "responded", "tls": {"enabled": true, "version": "1.0"}})
	not tls_version_modern({"host_state": "responded", "tls": {"enabled": true, "version": "1.1"}})
	not tls_version_modern({"host_state": "responded", "tls": {"enabled": true}})
}

test_unauthenticated_http_is_2xx_without_auth if {
	unauthenticated_http({"unauth": true, "http_status": 200})
	unauthenticated_http({"unauth": true, "http_status": 204})
	not unauthenticated_http({"unauth": false, "http_status": 401})
	not unauthenticated_http({"unauth": true, "http_status": 404})
	not unauthenticated_http({"unauth": true, "http_status": 0})
}

test_reachable_tcp_is_an_open_port_with_no_http if {
	reachable_tcp({"state": "open", "http_status": 0})
	not reachable_tcp({"state": "open", "http_status": 200})
	not reachable_tcp({"state": "filtered", "http_status": 0})
}
