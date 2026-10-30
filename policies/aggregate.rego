# The library's single entry point: evaluate one observation against every
# rule and return what fired.
#
# This exists for two reasons that happen to need the same code.
#
# 1. It is how the Phase-1 control plane will evaluate an observation. A
#    caller should not have to know the package names of 19 rules, and adding
#    a rule must not require changing the caller.
# 2. It makes a DIFFERENTIAL test possible: the structural parity test proves
#    the Go and Rego rule sets agree on severities and text, which is not the
#    same as agreeing on *behaviour*. With this, the same corpus of
#    observations can be pushed through both implementations and the firing
#    rule IDs compared. Metadata parity with divergent behaviour is the worst
#    of both worlds - a report and a credential that cite the same rule ID and
#    disagree about whether it fired.
package gpusecurity.aggregate

import rego.v1

# findings is the set of rule IDs whose finding_condition holds for input.
#
# The walk over data.gpusecurity is deliberate: a package without a
# finding_condition (lib, this one) simply yields nothing, so new rules are
# picked up with no registration step and nothing to forget to update.
findings contains id if {
	some domain, name
	rule := data.gpusecurity[domain][name]
	rule.finding_condition
	id := rule.finding_metadata.id
}

# verified is the set of rule IDs whose verification_condition holds - the
# findings this observation would auto-close. Separate from findings on
# purpose: a credential is issued off verified closures, so the two sets are
# never conflated in the API either.
verified contains id if {
	some domain, name
	rule := data.gpusecurity[domain][name]
	rule.verification_condition
	id := rule.finding_metadata.id
}

# metadata is the whole rule catalogue, keyed by ID. The control plane needs
# it to render a finding, and the air-gap bundle ships it as data (§13).
metadata[id] := meta if {
	some domain, name
	rule := data.gpusecurity[domain][name]
	meta := rule.finding_metadata
	id := meta.id
}
