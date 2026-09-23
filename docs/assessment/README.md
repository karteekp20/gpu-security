# Assessment kit

Everything needed to run a buyer-led assessment. Three of these with a
Neocloud's own Security/Ops lead present is the Phase-0 gate (CLAUDE.md §14) —
the only thing that unblocks building anything else.

Use them in this order:

| | File | When |
| :-- | :-- | :-- |
| 1 | [`demo.md`](demo.md) | First call. Show the tool on a cluster you broke on purpose, before asking for access to theirs. |
| 2 | [`authorization.md`](authorization.md) | Before any scan of their systems. Written scope, named targets, bounded window. Not optional. |
| 3 | [`runbook.md`](runbook.md) | The engagement itself — before, during, after. Includes the two gate questions, asked in those words. |
| 4 | [`objections.md`](objections.md) | Read before the first call. The **do-not-claim list** at the bottom matters more than the rest. |

Results go in [`../validation-log.md`](../validation-log.md), which tracks the
gate and lists what to capture beyond yes/no.

**Why this is in the repo.** Publishing how we assess — including what we
refuse to claim — is consistent with selling neutrality. A trust vendor with a
hidden playbook is a contradiction.
