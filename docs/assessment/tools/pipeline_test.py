#!/usr/bin/env python3
"""Self-test for pipeline.py. Stdlib only; run it directly or via `make test-pipeline`.

Two things in this script carry consequences that no other tool here does.

The gate counter decides when Phase 1 starts (CLAUDE.md §14). The failure
mode that matters is a count that flatters the product: an unattended run
recorded as a buyer-led assessment, or "seemed keen" counted as an intent to
pay. The scanner's own grading refuses to call an unmeasured host clean; this
is the same principle applied to the commercial evidence, and it had no test.

The markdown output goes into docs/validation-log.md, which is in a PUBLIC
repository, generated from a CSV holding client names and call notes. A
regression that printed an org name without permission would publish a
client's security posture under our name. That is not recoverable by a
follow-up commit, because the repository is cloned and mirrored.

So both are pinned here, from the outside, through the real CLI.
"""

import csv
import io
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOL = Path(__file__).resolve().parent / "pipeline.py"
TEMPLATE = Path(__file__).resolve().parent / "pipeline.csv.template"
HEADER = TEMPLATE.read_text(encoding="utf-8").splitlines()[0]
COLUMNS = next(csv.reader(io.StringIO(HEADER)))


def row(**over):
    """A row that qualifies on every axis, so each test changes exactly one thing.

    The org must not begin with "example": pipeline.py's is_example() drops
    those so an untouched template reports zero rather than one. A fixture
    named "Example Ltd" is silently skipped and every count reads 0, which
    looks exactly like the tool under-counting.
    """
    base = {
        "date": "2026-11-01", "org": "Northwind GPU", "segment": "neocloud",
        "size_band": "51-200", "region": "EU", "vantage": "neocloud",
        "role_contacted": "CISO", "channel": "email", "stage": "scanned",
        "scan_completed": "y", "buyer_lead_present": "y", "would_pay": "y",
        "ask_by_name": "y", "budget_line": "security", "findings_surfaced": "3",
        "findings_disputed": "0", "asks_we_lack": "", "public_note": "",
        "name_public_ok": "n", "notes": "",
    }
    base.update(over)
    missing = [c for c in COLUMNS if c not in base]
    assert not missing, f"the template grew columns this test does not set: {missing}"
    return base


def run(rows, *args):
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "pipeline.csv"
        with path.open("w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=COLUMNS)
            w.writeheader()
            for r in rows:
                w.writerow(r)
        p = subprocess.run([sys.executable, "-I", str(TOOL), "--csv", str(path), *args],
                           capture_output=True, text=True, timeout=60)
        assert p.returncode == 0, f"pipeline.py exited {p.returncode}: {p.stderr}"
        return p.stdout


def gate(out):
    led = paid = None
    for line in out.splitlines():
        if "Buyer-led assessments" in line:
            led = int(line.split()[-3])
        if "Pay-and-name-it" in line:
            paid = int(line.split()[-3])
    assert led is not None and paid is not None, f"could not parse the gate out of:\n{out}"
    return led, paid


class GateCounting(unittest.TestCase):
    def test_a_fully_qualifying_row_counts_on_both_axes(self):
        self.assertEqual(gate(run([row()])), (1, 1))

    def test_an_unattended_scan_is_not_a_buyer_led_assessment(self):
        # docs/validation-log.md is explicit: a run the buyer's own lead did
        # not attend does not qualify, however complete the scan.
        self.assertEqual(gate(run([row(buyer_lead_present="n")])), (0, 0),
                         "a scan with no buyer lead in the room counted toward the gate")

    def test_a_row_that_was_never_scanned_counts_for_nothing(self):
        self.assertEqual(gate(run([row(stage="call_held", scan_completed="n")])), (0, 0),
                         "an unscanned row counted; enthusiasm is not evidence")

    def test_would_pay_alone_is_not_pay_and_name_it(self):
        led, paid = gate(run([row(ask_by_name="unknown")]))
        self.assertEqual((led, paid), (1, 0),
                         "'would pay' without 'would ask for it by name' counted as both")

    def test_ask_by_name_alone_is_not_pay_and_name_it(self):
        led, paid = gate(run([row(would_pay="unknown")]))
        self.assertEqual((led, paid), (1, 0))

    def test_unknown_is_never_read_as_yes(self):
        self.assertEqual(gate(run([row(buyer_lead_present="unknown")])), (0, 0),
                         "'unknown' was treated as a yes; it is the whole point of the column")

    def test_the_gate_needs_three_and_two_not_one_good_call(self):
        out = run([row(), row(date="2026-11-02", org="Harbour AI"),
                   row(date="2026-11-03", org="Fenwick Compute")])
        self.assertIn("CLEARED", out)
        self.assertEqual(gate(out), (3, 3))
        partial = run([row(), row(date="2026-11-02", org="Harbour AI")])
        self.assertIn("NOT CLEARED", partial,
                      "two assessments cleared a gate that requires three")


class PublicOutputLeaksNothing(unittest.TestCase):
    SECRET_ORG = "Zenith Compute GmbH"
    SECRET_NOTE = "CTO said their biggest customer threatened to leave"

    def test_an_org_is_anonymized_without_written_permission(self):
        out = run([row(org=self.SECRET_ORG, name_public_ok="n",
                       notes=self.SECRET_NOTE)], "--markdown")
        self.assertNotIn(self.SECRET_ORG, out,
                         "a client name reached the public block without permission")
        self.assertNotIn("Zenith", out)
        self.assertIn("51-200", out, "the anonymized label lost the size band")

    def test_private_notes_never_reach_the_public_block(self):
        out = run([row(notes=self.SECRET_NOTE)], "--markdown")
        self.assertNotIn("threatened", out,
                         "a private call note reached the public block")

    def test_an_org_is_named_only_when_the_row_says_they_agreed(self):
        out = run([row(org=self.SECRET_ORG, name_public_ok="y")], "--markdown")
        self.assertIn(self.SECRET_ORG, out,
                      "a client who gave written permission was still anonymized, "
                      "which makes the permission column meaningless")


if __name__ == "__main__":
    unittest.main(verbosity=2)
