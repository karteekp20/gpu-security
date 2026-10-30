# RG-TLS-001 - TLS certificate fails verification
#
# The scanner completes the handshake and then verifies the presented chain
# itself, so it can report WHY verification failed (self-signed, expired,
# not-yet-valid, hostname-mismatch) rather than only "no TLS". It records the
# failure class and the expiry date - never the subject, issuer, serial or
# chain bytes (P3).
#
# Mirrors internal/scan/detect.go; parity is enforced by
# internal/scan/rule_parity_test.go.
package gpusecurity.cloud.tls_certificate_invalid

import data.gpusecurity.lib
import rego.v1

# Detection: TLS is on and the chain did not verify.
finding_condition if {
	input.service == "tls"
	input.tls.enabled == true
	input.tls.issue != ""
}

# Verification sentinel: the chain now verifies, or the port is gone.
# Deliberately NOT satisfied by "TLS is still on" - a replaced certificate
# that still fails verification is not a fix.
verification_condition if lib.tls_chain_verified(input)

verification_condition if lib.isolated(input)

finding_metadata := {
	"id": "RG-TLS-001",
	"title": "TLS certificate fails verification",
	"severity": "medium",
	"cve": [],
	"remediation": "Replace the certificate with one issued by a trusted CA, matching the service hostname and within its validity window.",
	"compliance": ["SOC2:CC6.7", "ISO27001:A.8.24"]
}
