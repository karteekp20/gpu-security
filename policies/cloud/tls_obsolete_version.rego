# RG-TLS-003 - Obsolete TLS version negotiated
#
# Separate from RG-TLS-001 on purpose. A bad certificate and an obsolete
# protocol have different fixes, and they travel together in the field: the
# box serving TLS 1.0 usually has a self-signed certificate too. Collapsing
# them would mean the operator fixes the certificate, re-scans, and only then
# hears about the protocol (docs/decision-log.md, 2026-10-24).
#
# Mirrors internal/scan/detect.go; parity is enforced by
# internal/scan/rule_parity_test.go.
package gpusecurity.cloud.tls_obsolete_version

import data.gpusecurity.lib
import rego.v1

# Detection: the negotiated version is one RFC 8996 deprecates.
finding_condition if {
	input.service == "tls"
	input.tls.enabled == true
	input.tls.version in {"1.0", "1.1"}
}

# Verification sentinel: the listener now negotiates 1.2 or later, or the
# port is gone. Note that an absent version does NOT close this: the scanner
# records "" for a version it does not recognize, and treating "we could not
# tell" as "fixed" is the same error as closing a finding on a dark host.
verification_condition if lib.tls_version_modern(input)

verification_condition if lib.isolated(input)

finding_metadata := {
	"id": "RG-TLS-003",
	"title": "Obsolete TLS version negotiated",
	"severity": "medium",
	"cve": [],
	"remediation": "Disable TLS 1.0 and 1.1 on this listener and require TLS 1.2 or later (RFC 8996); on a terminating proxy this is one directive.",
	"compliance": ["SOC2:CC6.7", "ISO27001:A.8.24"]
}
