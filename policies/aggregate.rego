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
#
# WHY THE DOMAIN PATHS ARE WRITTEN OUT. The obvious spelling walks
# data.gpusecurity[domain][name] over a set of domain names. OPA rejects it,
# twice over: the set is a rule, so its value "isn't known at compile time",
# and the compiler must therefore assume `domain` could be "aggregate" - this
# package - which makes `findings` depend on the tests that assert on
# `findings`. Eleven rego_recursion_errors, found by `opa check --strict` in
# CI and by nothing that runs locally.
#
# So each domain is a literal path. Adding a RULE to an existing domain still
# needs no change here. Adding a DOMAIN needs two lines per aggregate, and
# internal/scan/rule_parity_test.go fails if a domain directory exists under
# /policies and is not walked - so the wiring cannot be forgotten, which is
# the failure mode that would silently drop a whole tier of L2/L3 rules.
package gpusecurity.aggregate

import rego.v1

# rule_packages is every rule package in the library, keyed by
# "<domain>/<name>" so two domains may hold a rule of the same name. Keyed
# rather than a set because a set of objects would silently dedupe two
# identical packages.
rule_packages[key] := pkg if {
	some name
	pkg := data.gpusecurity.orchestrator[name]
	key := sprintf("orchestrator/%s", [name])
}

rule_packages[key] := pkg if {
	some name
	pkg := data.gpusecurity.cloud[name]
	key := sprintf("cloud/%s", [name])
}

# findings is the set of rule IDs whose finding_condition holds for input.
findings contains id if {
	some _, pkg in rule_packages
	pkg.finding_condition
	id := pkg.finding_metadata.id
}

# verified is the set of rule IDs whose verification_condition holds - the
# findings this observation would auto-close. Separate from findings on
# purpose: a credential is issued off verified closures, so the two sets are
# never conflated in the API either.
verified contains id if {
	some _, pkg in rule_packages
	pkg.verification_condition
	id := pkg.finding_metadata.id
}

# metadata is the whole rule catalogue, keyed by ID. The control plane needs
# it to render a finding, and the air-gap bundle ships it as data (§13).
metadata[id] := meta if {
	some _, pkg in rule_packages
	meta := pkg.finding_metadata
	id := meta.id
}
