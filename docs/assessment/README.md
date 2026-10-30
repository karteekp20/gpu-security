# Assessment kit

Everything needed to run a buyer-led assessment. Three of these with a
Neocloud's own Security/Ops lead present is the Phase-0 gate (CLAUDE.md §14) —
the only thing that unblocks building anything else.

Use them in this order:

| | File | When |
| :-- | :-- | :-- |
| 0 | [`outreach.md`](outreach.md) | Getting the meeting at all — who to contact, what to send, and what never to do. This is the step the gate is actually blocked on. |
| 1 | [`demo.md`](demo.md) | First call. Show the tool on a cluster you broke on purpose, before asking for access to theirs. |
| 2 | [`authorization.md`](authorization.md) | Before any scan of their systems. Written scope, named targets, bounded window. Not optional. |
| 3 | [`runbook.md`](runbook.md) | The engagement itself — before, during, after. Includes the two gate questions, asked in those words. |
| 4 | [`objections.md`](objections.md) | Read before the first call. The **do-not-claim list** at the bottom matters more than the rest. |
| 5 | [`tools/pipeline.py`](tools/pipeline.py) | After every email, reply and call. Computes the funnel and the two gate numbers from a private CSV, and prints the anonymized tables for the public log. |

Results go in [`../validation-log.md`](../validation-log.md), which tracks the
gate and lists what to capture beyond yes/no.

**The tracker, and why it is split in two.** Copy
[`tools/pipeline.csv.template`](tools/pipeline.csv.template) to
`~/assessments/outreach/pipeline.csv` — **outside this repository**, which is
public — and add a row per prospect as you go. Then:

```bash
python3 docs/assessment/tools/pipeline.py              # funnel, gate, budget lines
python3 docs/assessment/tools/pipeline.py --markdown   # anonymized, for the public log
```

The private CSV holds names, contacts and notes. The public log gets counts and
`Neocloud A (51–200, EU)` unless a client has agreed in writing to be named.
The gate arithmetic is done in code so it cannot be flattered: a scan with
nobody from the buyer in the room does not count however it is labelled, and
"seemed keen" is not a yes. Pointing the script at a CSV that does not exist
tells you where to create one.

**Why this is in the repo.** Publishing how we assess — including what we
refuse to claim — is consistent with selling neutrality. A trust vendor with a
hidden playbook is a contradiction.
