#!/usr/bin/env python3
"""Replay the scanner's corpus through OPA and compare what fires.

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

This closes that gap. The corpus is generated from the Go detector - the side
with real traffic behind it - and every case is pushed through
`data.gpusecurity.aggregate.findings`. A mismatch in either direction fails.

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
QUERY = "data.gpusecurity.aggregate.findings"


def opa_eval(opa: str, input_path: pathlib.Path) -> set[str]:
    """Return the set of rule IDs that fired for one observation."""
    proc = subprocess.run(
        [opa, "eval", "--format", "json",
         "--data", str(POLICIES), "--input", str(input_path), QUERY],
        capture_output=True, text=True, check=False,
    )
    if proc.returncode != 0:
        sys.exit(f"opa eval failed ({proc.returncode}):\n{proc.stderr.strip()}")
    doc = json.loads(proc.stdout)
    results = doc.get("result") or []
    if not results:
        # No result at all means the query was undefined: an empty finding set.
        return set()
    value = results[0]["expressions"][0]["value"]
    return set(value or [])


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
    if not CORPUS.exists():
        sys.exit(
            f"{CORPUS} is missing. Generate it with:\n"
            "  RAY_GUARD_UPDATE_CORPUS=1 go test ./internal/scan -run TestRegoCorpus"
        )

    cases = json.loads(CORPUS.read_text())["cases"]
    failures: list[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        input_path = pathlib.Path(tmp) / "input.json"
        for case in cases:
            input_path.write_text(json.dumps(case["input"]))
            got = opa_eval(args.opa, input_path)
            want = set(case.get("expect_findings") or [])
            status = "ok  "
            if got != want:
                status = "DIFF"
                only_go = sorted(want - got)
                only_rego = sorted(got - want)
                detail = []
                if only_go:
                    detail.append(f"the scanner raises {only_go} and the rules do not")
                if only_rego:
                    detail.append(f"the rules raise {only_rego} and the scanner does not")
                failures.append(f"{case['name']}: " + "; ".join(detail))
            print(f"  {status}  {case['name']:<52} {sorted(want) or '[]'}")

    print()
    if failures:
        print(f"{len(failures)} of {len(cases)} cases differ between the two implementations:")
        for f in failures:
            print(f"  - {f}")
        print(
            "\nThe Go detector is the reference: it ships, and customer reports come\n"
            "from it. Fix the Rego rule, or - if the Go side is what is wrong - fix\n"
            "it there and regenerate the corpus."
        )
        return 1
    print(f"{len(cases)}/{len(cases)} cases agree: the Go detector and the Rego library "
          "fire the same rules.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
