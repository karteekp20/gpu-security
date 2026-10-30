# RG-TLS-002 - Authenticated service served over plaintext HTTP
#
# The good-news case that is still a finding: the service DOES enforce
# authentication, and the credentials cross the network in the clear. It is
# scoped to services the library can name, because an unidentified port that
# returns 401 is reported as an unidentified port rather than as this.
#
# Mirrors internal/scan/detect.go; parity is enforced by
# internal/scan/rule_parity_test.go.
package gpusecurity.cloud.tls_plaintext_auth

import data.gpusecurity.lib
import rego.v1

# Detection: a recognized service demands credentials, over plaintext.
finding_condition if {
	lib.known_service(input)
	input.tls.enabled == false
	input.http_status in {401, 403}
}

# Verification sentinel: TLS now terminates in front of it AND it still
# demands credentials - both halves, because a service that stopped asking
# for credentials has not fixed this finding, it has replaced it with a worse
# one. Isolation also closes it.
verification_condition if {
	lib.tls_terminated(input)
	lib.auth_enforced(input)
}

verification_condition if lib.isolated(input)

finding_metadata := {
	"id": "RG-TLS-002",
	"title": "Authenticated service served over plaintext HTTP",
	"severity": "medium",
	"cve": [],
	"remediation": "Terminate TLS in front of this service; credentials sent to it currently traverse the network in the clear.",
	"compliance": ["SOC2:CC6.7", "ISO27001:A.8.24"]
}
