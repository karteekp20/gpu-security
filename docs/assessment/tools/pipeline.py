#!/usr/bin/env python3
"""Compute the Phase-0 funnel from a private pipeline CSV.

Why this exists
---------------
The §14 gate is two numbers - 3 buyer-led assessments, 2 pay-and-name-it - and
the one failure mode that matters is a log that flatters the product. So the
counting is done by code, from per-row evidence, rather than by someone
remembering how a call felt. Specifically:

  * A run only counts as buyer-led when BOTH the scan completed AND the
    buyer's own security/ops lead was in the room. An unattended run is
    explicitly not gate-qualifying (docs/validation-log.md), and this script
    will not let one through however it is labelled.
  * "Would pay" and "would ask for it by name" are counted separately and
    only when both are an unambiguous yes on the same row. "Seemed keen" is
    not a yes; leave it unknown.

It also exists because the repository is public. The CSV holds client names and
conversation notes and must never be committed; this script reads it from
outside the tree and prints an ANONYMIZED block for the public log. A client is
named publicly only when their row says they agreed to it.

Usage
-----
    python3 docs/assessment/tools/pipeline.py                  # default CSV
    python3 docs/assessment/tools/pipeline.py --csv path.csv
    python3 docs/assessment/tools/pipeline.py --markdown        # paste-ready

Stdlib only, like everything else here, so it runs on an air-gapped laptop.
"""

from __future__ import annotations

import argparse
import csv
import os
import sys
from collections import Counter
from pathlib import Path

DEFAULT_CSV = Path(os.path.expanduser("~/assessments/outreach/pipeline.csv"))

# The funnel, in order. A row records the furthest stage it reached.
STAGES = [
    ("sent", "Emails sent"),
    ("replied", "Replies"),
    ("call_booked", "Calls booked"),
    ("call_held", "Calls held"),
    ("authorized", "Written authorizations"),
    ("scanned", "Scans completed"),
]
STAGE_ORDER = {name: i for i, (name, _) in enumerate(STAGES)}

# Terminal stages that are not progress but are not errors either.
#
# Convention, because it affects the counts: use `declined` only for a decline
# that arrived before a call. A prospect who took a call and then said no is
# recorded at the stage they actually reached (`call_held`), with the decline in
# notes - otherwise the funnel under-counts calls and makes the reply rate look
# worse than it is. Under-counting is the safe direction for a gate number, but
# it is the wrong direction for judging whether the OFFER is working, which is
# what the funnel is for.
TERMINAL = {"no_reply", "declined"}

YES = {"y", "yes", "true", "1"}
NO = {"n", "no", "false", "0"}

REQUIRED_COLUMNS = {
    "date",
    "org",
    "segment",
    "size_band",
    "region",
    "vantage",
    "stage",
    "scan_completed",
    "buyer_lead_present",
    "would_pay",
    "ask_by_name",
    "budget_line",
    "name_public_ok",
}


def truthy(value: str) -> bool:
    return value.strip().lower() in YES


def is_example(row: dict) -> bool:
    """Skip the template row so an untouched CSV reports zero, not one."""
    return row.get("org", "").strip().upper().startswith("EXAMPLE")


def load(path: Path) -> list[dict]:
    if not path.exists():
        sys.exit(
            f"no pipeline at {path}\n"
            "Create it from docs/assessment/tools/pipeline.csv.template, "
            "OUTSIDE this repository - it holds client names."
        )
    with path.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        missing = REQUIRED_COLUMNS - set(reader.fieldnames or [])
        if missing:
            sys.exit(f"{path} is missing column(s): {', '.join(sorted(missing))}")
        rows = [r for r in reader if r.get("org", "").strip() and not is_example(r)]
    for i, row in enumerate(rows, start=2):
        stage = row["stage"].strip().lower()
        if stage not in STAGE_ORDER and stage not in TERMINAL:
            sys.exit(
                f"{path} line {i}: stage {stage!r} is not one of "
                f"{', '.join(list(STAGE_ORDER) + sorted(TERMINAL))}"
            )
        row["stage"] = stage
    return rows


def reached(row: dict, stage: str) -> bool:
    """A row that reached a stage reached every stage before it."""
    if row["stage"] in TERMINAL:
        # A no-reply still consumed an email; a decline may have had a call.
        return stage == "sent"
    return STAGE_ORDER[row["stage"]] >= STAGE_ORDER[stage]


def gate_qualifying(row: dict) -> bool:
    """Both conditions, per CLAUDE.md §14 - neither is inferable from the other.

    A completed scan with nobody from the buyer present is a demo we ran, and
    a buyer in the room with no scan is a conversation. The gate wants both.
    """
    return truthy(row["scan_completed"]) and truthy(row["buyer_lead_present"])


def pay_and_name(row: dict) -> bool:
    return (
        gate_qualifying(row)
        and row["would_pay"].strip().lower() in YES
        and row["ask_by_name"].strip().lower() in YES
    )


def anonymous_label(rows: list[dict]) -> dict[int, str]:
    """Stable per-segment labels: Neocloud A, Neocloud B, Tenant A, ...

    Assigned in date order so a label does not move when a later row is added.
    """
    labels: dict[int, str] = {}
    counters: Counter[str] = Counter()
    for idx, row in sorted(enumerate(rows), key=lambda p: p[1]["date"]):
        kind = "Tenant" if row["vantage"].strip().lower().startswith("ten") else "Neocloud"
        counters[kind] += 1
        n = counters[kind] - 1
        suffix = chr(ord("A") + n % 26) + ("" if n < 26 else str(n // 26 + 1))
        labels[idx] = f"{kind} {suffix}"
    return labels


def public_name(row: dict, fallback: str) -> str:
    """Name a client publicly only if the row says they agreed."""
    return row["org"].strip() if truthy(row["name_public_ok"]) else fallback


def report(rows: list[dict]) -> None:
    print("Phase-0 funnel")
    print("=" * 46)
    counts = {stage: sum(1 for r in rows if reached(r, stage)) for stage, _ in STAGES}
    prev = None
    for stage, title in STAGES:
        n = counts[stage]
        rate = ""
        if prev is not None and prev[1]:
            rate = f"   ({n / prev[1]:.0%} of {prev[0].lower()})"
        print(f"  {title:<24} {n:>4}{rate}")
        prev = (title, n)

    no_reply = sum(1 for r in rows if r["stage"] == "no_reply")
    declined = sum(1 for r in rows if r["stage"] == "declined")
    print(f"  {'No reply':<24} {no_reply:>4}")
    print(f"  {'Declined':<24} {declined:>4}")

    qualifying = [r for r in rows if gate_qualifying(r)]
    converting = [r for r in rows if pay_and_name(r)]
    print()
    print("THE GATE (CLAUDE.md §14) - both conditions must be met")
    print("=" * 46)
    print(f"  Buyer-led assessments   {len(qualifying)} / 3")
    print(f"  Pay-and-name-it         {len(converting)} / 2")
    cleared = len(qualifying) >= 3 and len(converting) >= 2
    print(f"  Status                  {'CLEARED' if cleared else 'NOT CLEARED'}")

    # The discrepancy worth surfacing: scans we ran with nobody watching.
    unattended = [
        r for r in rows if truthy(r["scan_completed"]) and not truthy(r["buyer_lead_present"])
    ]
    if unattended:
        print()
        print(
            f"  Note: {len(unattended)} completed scan(s) had no buyer lead present "
            "and do NOT\n        count toward the gate. Supporting signal only."
        )

    if qualifying:
        budget = Counter(r["budget_line"].strip().lower() or "unknown" for r in qualifying)
        print()
        print("Budget line named (by qualifying buyers)")
        print("=" * 46)
        for line, n in budget.most_common():
            print(f"  {line:<24} {n:>4}")
        if budget["sales_enablement"] > budget["security"]:
            print(
                "  → sales enablement leads. That is evidence about which surface\n"
                "    matters most (Surface B, the public trust page), not small talk."
            )

    asks = [r["asks_we_lack"].strip() for r in rows if r.get("asks_we_lack", "").strip()]
    if asks:
        print()
        print("Asked for, and we do not have it (capture, do not build - P1)")
        print("=" * 46)
        for a in asks:
            print(f"  - {a}")

    if not rows:
        print()
        print("No rows yet. The gate is 0/3 and 0/2, which is the honest state.")


def markdown(rows: list[dict]) -> None:
    """Paste-ready, anonymized blocks for the PUBLIC docs/validation-log.md."""
    labels = anonymous_label(rows)
    qualifying = [(i, r) for i, r in enumerate(rows) if gate_qualifying(r)]
    converting = sum(1 for r in rows if pay_and_name(r))

    print(f"**{len(qualifying)} / 3** buyer-led assessments · "
          f"**{converting} / 2** pay-and-name-it intents.")
    print()
    print("| # | Date | Organization | Vantage (§1.5) | Who was in the room (role) "
          "| Findings surfaced | Would pay? | Would ask for it by name? | Notes |")
    print("| :-- | :-- | :-- | :-- | :-- | :-- | :-- | :-- | :-- |")
    if not qualifying:
        print("| — | — | — | — | — | — | — | — | *no runs yet* |")
    for n, (idx, row) in enumerate(qualifying, start=1):
        org = public_name(row, f"{labels[idx]} ({row['size_band']}, {row['region']})")
        print(
            f"| {n} | {row['date']} | {org} | {row['vantage']} | "
            f"{row.get('role_contacted', '').strip() or '—'} | "
            f"{row.get('findings_surfaced', '').strip() or '—'} | "
            f"{row['would_pay'] or 'unknown'} | {row['ask_by_name'] or 'unknown'} | "
            f"{row.get('public_note', '').strip() or '—'} |"
        )
    print()
    print("Supporting signal (not part of the gate):")
    print()
    print("| Date | Metric | Value |")
    print("| :-- | :-- | :-- |")
    for stage, title in STAGES:
        n = sum(1 for r in rows if reached(r, stage))
        if n:
            print(f"| {max((r['date'] for r in rows), default='—')} | {title} | {n} |")
    print()
    print("<!-- Generated by docs/assessment/tools/pipeline.py from the private")
    print("     pipeline CSV. Names appear only where the client agreed")
    print("     (name_public_ok). Do not hand-edit; re-run it. -->")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--csv", type=Path, default=DEFAULT_CSV, help=f"default: {DEFAULT_CSV}")
    ap.add_argument(
        "--markdown",
        action="store_true",
        help="print anonymized blocks for the public validation log",
    )
    args = ap.parse_args()
    rows = load(args.csv)
    if args.markdown:
        markdown(rows)
    else:
        report(rows)


if __name__ == "__main__":
    main()
