# RG-BUCKET-001 - Object storage bucket lists without authentication
#
# Decided from the STATUS CODE ALONE. The response body is discarded
# unparsed: object keys are customer data, not metadata, so the scanner never
# looks at them (P3). "It listed without credentials" is provable without
# reading it - and is all we can claim: the endpoint's reachability from the
# scan vantage is not evidence that it is reachable from the internet.
#
# Mirrors internal/scan/detect.go; parity is enforced by
# internal/scan/rule_parity_test.go.
package gpusecurity.cloud.bucket_public

import data.gpusecurity.lib
import rego.v1

# Detection: an unauthenticated GET to the bucket endpoint succeeded.
finding_condition if {
	input.service == "bucket"
	lib.unauthenticated_http(input)
}

# Verification sentinel: the same unauthenticated request is now refused.
# 4xx only - a 5xx is an outage, not a permission change, and closing a
# finding on an outage would be a false attestation.
verification_condition if {
	input.service == "bucket"
	lib.host_reached(input)
	input.unauth == false
	input.http_status >= 400
	input.http_status < 500
}

finding_metadata := {
	"id": "RG-BUCKET-001",
	"title": "Object storage bucket lists without authentication",
	"severity": "high",
	"cve": [],
	"remediation": "Remove public-read/list permissions from the bucket and require authenticated access.",
	"compliance": ["SOC2:CC6.1", "ISO27001:A.5.15", "ISO27001:A.8.3"]
}
