#!/usr/bin/env python3
"""Replay the scanner's corpora through OPA and compare what fires and what closes.

Why
---
There are two implementations of the L1 rule set: Go in `internal/scan`, which
ships inside the static binary and produces every customer report, and Rego in
`/policies`, which the Phase-1 control plane evaluates and which the signed
credential is issued from. OPA cannot go into a zero-dependency air-gap binary
(CLAUDE.md §15, P4), so the duplication is deliberate.

`internal/scan/rule_parity_test.go` proves the two sides agree on rule IDs,
severities, remediation text and CVEs. That is *metadata* parity, and metadata
parity with divergent behaviour is the worst of both worlds: a report and a
credential citing the same rule ID while disagreeing about whether it fired.

Two corpora close that gap, one per half of every sentinel.

`corpus.json` - what the rules FIND. Generated from the Go detector, the side
with real traffic behind it, and replayed through `aggregate.findings`.

`closures.json` - what the rules CLOSE. Generated from the scanner's own state
vocabulary (`internal/domain`) plus each rule's declared scope, and replayed
through `aggregate.verified`. It exists because the finding half cannot see
closure drift at all: no `finding_condition` reads `host_state`, so renaming
`domain.HostResponded` left every Go gate and the finding differential green
while making all 19 verification sentinels permanently unsatisfiable. Its
negative cases are the stronger half - on a host we did not reach, nothing may
close, whatever else the observation says.

Usage
-----
    python3 policies/tools/differential.py            # needs opa on PATH
    python3 policies/tools/differential.py --opa ./opa

Stdlib only, and it shells out to `opa eval` rather than embedding anything,
so it runs wherever OPA does.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parents[2]
POLICIES = REPO / "policies"
CORPUS = POLICIES / "testdata" / "corpus.json"
CLOSURES = POLICIES / "testdata" / "closures.json"
REGENERATE = (
    "RAY_GUARD_UPDATE_CORPUS=1 go test ./internal/scan "
    "-run 'TestRegoCorpusIsCurrent|TestRegoClosureCorpusIsCurrent'"
)


def opa_eval(opa: str, input_path: pathlib.Path, query: str) -> set[str]:
    """Return the set of rule IDs `query` yields for one observation."""
    proc = subprocess.run(
        [opa, "eval", "--format", "json",
         "--data", str(POLICIES), "--input", str(input_path), query],
        capture_output=True, text=True, check=False,
    )
    if proc.returncode != 0:
        sys.exit(f"opa eval failed ({proc.returncode}):\n{proc.stderr.strip()}")
    doc = json.loads(proc.stdout)
    results = doc.get("result") or []
    if not results:
        # No result at all means the query was undefined: an empty set.
        return set()
    value = results[0]["expressions"][0]["value"]
    return set(value or [])


def load(path: pathlib.Path) -> list[dict]:
    if not path.exists():
        sys.exit(f"{path} is missing. Generate it with:\n  {REGENERATE}")
    return json.loads(path.read_text())["cases"]


def run_findings(opa: str, tmp: pathlib.Path) -> list[str]:
    """Compare the rule IDs each implementation raises. Equality, both ways."""
    failures: list[str] = []
    cases = load(CORPUS)
    print(f"findings  ({len(cases)} cases, against the shipping Go detector)")
    for case in cases:
        tmp.write_text(json.dumps(case["input"]))
        got = opa_eval(opa, tmp, "data.gpusecurity.aggregate.findings")
        want = set(case.get("expect_findings") or [])
        status = "ok  "
        if got != want:
            status = "DIFF"
            detail = []
            if want - got:
                detail.append(
                    f"the scanner raises {sorted(want - got)} and the rules do not")
            if got - want:
                detail.append(
                    f"the rules raise {sorted(got - want)} and the scanner does not")
            failures.append(f"{case['name']}: " + "; ".join(detail))
        print(f"  {status}  {case['name']:<52} {sorted(want) or '[]'}")
    return failures


def run_closures(opa: str, tmp: pathlib.Path) -> list[str]:
    """Check what the sentinels close.

    Two assertion shapes, on purpose. A positive case is a SUBSET check,
    because one isolation observation legitimately closes several rules at once
    (an isolated vLLM port closes RG-VLLM-001 and RG-TLS-002 together). A
    negative case is an EQUALITY against the empty set, because "nothing closes
    on a host we did not reach" admits no exceptions.
    """
    failures: list[str] = []
    cases = load(CLOSURES)
    print(f"closures  ({len(cases)} cases, against the sentinel contract)")
    for case in cases:
        tmp.write_text(json.dumps(case["input"]))
        got = opa_eval(opa, tmp, "data.gpusecurity.aggregate.verified")
        status = "ok  "
        if case.get("expect_verified_empty"):
            shown = "{} required"
            if got:
                status = "DIFF"
                failures.append(
                    f"{case['name']}: {sorted(got)} closed on a host the scan never "
                    "reached - absence of evidence was accepted as proof of a fix")
        else:
            want = set(case.get("expect_verified_contains") or [])
            shown = str(sorted(want))
            if not want <= got:
                status = "DIFF"
                failures.append(
                    f"{case['name']}: {sorted(want - got)} did not close although the "
                    "remediation was observed, so the finding would stay open forever")
        print(f"  {status}  {case['name']:<68} {shown}")
    return failures


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--opa", default=shutil.which("opa") or "opa")
    args = ap.parse_args()

    if not shutil.which(args.opa) and not pathlib.Path(args.opa).exists():
        sys.exit(
            "opa not found. Install it (https://www.openpolicyagent.org/docs/) "
            "or pass --opa /path/to/opa. The structural parity checks run "
            "without it in `make test`."
        )

    with tempfile.TemporaryDirectory() as td:
        tmp = pathlib.Path(td) / "input.json"
        failures = run_findings(args.opa, tmp)
        print()
        failures += run_closures(args.opa, tmp)

    total = len(load(CORPUS)) + len(load(CLOSURES))
    print()
    if failures:
        print(f"{len(failures)} of {total} cases disagree with the rule library:")
        for f in failures:
            print(f"  - {f}")
        print(
            "\nFor a findings difference the Go detector is the reference: it ships,\n"
            "and customer reports come from it. Fix the Rego rule, or - if the Go\n"
            "side is what is wrong - fix it there and regenerate the corpus:\n"
            f"  {REGENERATE}"
        )
        return 1
    print(f"{total}/{total} cases agree: the two implementations fire the same rules, "
          "and every sentinel closes only on evidence.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
