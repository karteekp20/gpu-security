# docs

**Start outside this directory.** [`CLAUDE.md`](../CLAUDE.md) in the repo root is
the source of truth — read it first; its §0 says so and explains why. Everything
here is subordinate to it, and [`open-work.md`](open-work.md) states that
precedence about itself in its own header.

Then pick a path by what you came here to do:

| You are | Read, in this order |
| :-- | :-- |
| **Continuing engineering work** | [`CLAUDE.md`](../CLAUDE.md), then [`open-work.md`](open-work.md), then whichever document below covers your task |
| **Getting or running an assessment** | [`assessment/README.md`](assessment/README.md) — it orders its own steps 0–5 |
| **Evaluating the tool from outside** | [`assessment/plain-english.md`](assessment/plain-english.md) if you are not technical, [`threat-model.md`](threat-model.md) if you are |
| **Cutting a release** | [`publishing.md`](publishing.md) |

## What each document answers

**Engineering**

| File | The question it answers |
| :-- | :-- |
| [`architecture.md`](architecture.md) | What is actually built in this repo today, and what is not |
| [`threat-model.md`](threat-model.md) | What is the scanner's own attack surface, and which controls bound it |
| [`data-model.md`](data-model.md) | What will the datastores look like, once there are any |

**Decisions and state**

| File | The question it answers |
| :-- | :-- |
| [`open-work.md`](open-work.md) | Where does work stand, what is blocked on a decision rather than on effort, and what must not be built or rebuilt |
| [`decision-log.md`](decision-log.md) | Why is something the way it is, and what did it supersede |
| [`validation-log.md`](validation-log.md) | Has a buyer validated this, and what is still required before Phase 1 starts |

**Going to market** — [`assessment/`](assessment/) carries its own ordered index;
these are the files it orders.

| File | The question it answers |
| :-- | :-- |
| [`assessment/plain-english.md`](assessment/plain-english.md) | How do I explain all of this to someone non-technical |
| [`assessment/outreach.md`](assessment/outreach.md) | How does a buyer conversation get booked, and what must never be done to book one |
| [`assessment/demo.md`](assessment/demo.md) | What do I show on a first call, and what do I point at in what order |
| [`assessment/authorization.md`](assessment/authorization.md) | What has to be agreed in writing before anything is scanned |
| [`assessment/runbook.md`](assessment/runbook.md) | How does one engagement run, start to finish |
| [`assessment/objections.md`](assessment/objections.md) | What will I be asked, and what must I refuse to claim |
| [`assessment/tools/pipeline.py`](assessment/tools/pipeline.py) | What do the funnel and the gate numbers actually come to, counted rather than recalled |

**Shipping**

| File | The question it answers |
| :-- | :-- |
| [`publishing.md`](publishing.md) | What are the manual steps to publish or cut a release, in order |
| [`release-notes/`](release-notes/) | What changed in a given version, and why |

## What is not here

There is no control-plane, API or web-surface documentation, because none of it
is built. [`open-work.md`](open-work.md) §4 lists what is deliberately unbuilt
and why — an absence there is a decision, not an omission.
