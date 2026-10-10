# Validation Log — the Phase-0 gate

> **This is the most important number in the project.** CLAUDE.md P2 says no
> large build precedes a real buyer conversation, and §14 makes that concrete:
> the Phase-1 control plane is not started until the gate below clears.
>
> Engineering readiness is not a reason to start Phase 1. This file is.

## The gate (CLAUDE.md §14, Decision Log rev 2)

Both conditions must be met:

- [ ] **≥3 completed assessment runs conducted directly alongside a Neocloud's
      own Security/Ops lead.** Buyer in the room. Not a download, not a star,
      not a run you did yourself against their public IPs.
- [ ] **≥2 of those buyers stating they would pay for the trust report and
      would ask for it by name.**

Downloads, GitHub stars, and unattended assessment counts are **supporting
signal only**. They do not count toward either condition. If the buyer-led runs
don't happen, or happen and don't convert, re-think before building the
platform — that is the gate working, not the gate failing.

## Status

**0 / 3** buyer-led assessments · **0 / 2** pay-and-name-it intents.

> How to get one: [`assessment/outreach.md`](assessment/outreach.md) — who to
> contact, what to send, and what never to do.
> How to run one: [`assessment/`](assessment/) — demo script, scope and
> authorization template, runbook, and the do-not-claim list.

## Buyer-led assessments

Record one row per run where a buyer's security or ops lead was present.
Be honest in these rows; a log that flatters the product is worse than none.

| # | Date | Organization | Vantage (§1.5) | Who was in the room (role) | Findings surfaced | Would pay? | Would ask for it by name? | Notes |
| :-- | :-- | :-- | :-- | :-- | :-- | :-- | :-- | :-- |
| — | — | — | — | — | — | — | — | *no runs yet* |

**Vantage** is Neocloud-side (landlord scanning its own environment to sell
with) or tenant-side (a regulated renter producing audit evidence). Track it —
which side leans in harder is the beachhead call, and CLAUDE.md §20 leaves that
question open deliberately.

## What to capture in each conversation

Beyond the yes/no columns, these are the things that change what gets built:

- **Did the report survive contact?** Did they dispute a finding, a severity,
  or the grade? Grade thresholds are provisional (§10.0) precisely so this
  feedback can move them.
- **What did they ask for that we don't have?** Especially anything that would
  pull L2 or L3 forward (P1) — capture the ask, do not build it yet.
- **Who would they hand the report to?** If the answer is "our customers", that
  is the public trust page (Surface B) validating itself. If it is "our
  auditor", the compliance mapping matters more.
- **What would they pay, and against which budget line?** Security, compliance,
  or sales enablement. A sales-enablement buyer behaves very differently from
  a security buyer.
- **Did they object on margin?** Thin-margin Neoclouds are the expected
  objection; note whether the FinOps framing (§14.1 H1) lands.

## Supporting signal (not part of the gate)

Stars, downloads, outreach volume, reply rates, unattended runs. Worth
tracking to see your own conversion rate — twenty conversations and zero
assessments means the *offer* needs changing, not the product — but none of it
moves the two numbers above.

| Date | Metric | Value |
| :-- | :-- | :-- |
| — | — | — |
