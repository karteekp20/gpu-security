# RG-EXPOSURE-001 - Unidentified service reachable on an AI-infrastructure port
#
# Reported at Info and deliberately never attributed. An open port on the
# known AI-infrastructure list whose service could not be identified is the
# honest result and the question worth asking in the room; guessing which
# orchestrator it is would be a misattribution on a customer's report, which
# costs more than a missing name (docs/decision-log.md, 2026-09-20 rev 6).
#
# Mirrors internal/scan/detect.go; parity is enforced by
# internal/scan/rule_parity_test.go.
package gpusecurity.orchestrator.unidentified_service

import data.gpusecurity.lib
import rego.v1

# Detection: the port is open and no probe named what is on it. This includes
# the wildcard case - a server that answers 2xx on a path that cannot exist
# discriminates nothing, so the scanner refuses to name it.
finding_condition if {
	input.service == "unknown"
	input.state == "open"
}

# Verification sentinel: isolation only, and that is a deliberate limitation.
#
# A later scan that *identifies* the service does not close this finding - it
# raises a different one, under the rule for whatever was found. And an
# operator saying "that is our own service, it is fine" is a risk acceptance,
# which belongs in the finding's status, not in a sentinel: a sentinel that
# accepted an explanation would put a human assertion inside a signed
# credential, which is the one thing §8 exists to prevent.
verification_condition if {
	input.service == "unknown"
	lib.isolated(input)
}

finding_metadata := {
	"id": "RG-EXPOSURE-001",
	"title": "Unidentified service reachable on an AI-infrastructure port",
	"severity": "info",
	"cve": [],
	"remediation": "Confirm what is listening on this port and whether it should be reachable from the scan vantage point.",
	"compliance": ["SOC2:CC7.1", "ISO27001:A.8.16"]
}
