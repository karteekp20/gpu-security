# Assessment runbook

How to run one assessment, end to end. Three of these with a buyer's
Security/Ops lead in the room is the Phase-0 gate (CLAUDE.md §14) — the thing
standing between here and building anything else.

**The gate counts assessments where the buyer was present.** A scan you ran
alone against their public IPs does not count, however good the report is.

---

## Before

- [ ] **Authorization agreed in writing.** [`authorization.md`](authorization.md).
      Not a verbal yes on a call. No exceptions — this is the one step with
      consequences outside the deal.
- [ ] **Targets confirmed in writing**, specific hosts or CIDRs. If they say
      "just scan our infrastructure", push back until you have a list.
- [ ] **Their SOC knows.** Ask explicitly whether anyone needs warning. An
      unannounced scan that triggers an incident response is a bad first
      impression even when you were authorized.
- [ ] **Confirm who will be on the call.** If their security or ops lead is
      not attending, reschedule. Running it alone converts a gate-qualifying
      assessment into a favour you did for free.
- [ ] **Build and record the version:**
      ```bash
      make build && ./bin/ray-guard -version
      ```
      Goes in the log, and answers "which version produced this report?" later.
- [ ] **Dry run against the demo stack** so you are not discovering a problem
      live: `make demo-up && make demo` ([`demo.md`](demo.md)).
- [ ] **Decide your timeout.** Default 4s is right for a datacenter. Over a
      VPN or a high-latency link, raise `-timeout`; a scan that reports
      "filtered" everywhere because you were impatient is worse than a slow
      one.

## During

**1. Restate the scope out loud before you run anything.**

> "I'm going to scan <these ranges>, now, from <this IP>. Nothing else.
> Say stop at any point and I'll stop."

Boring, and it is what a professional does. It also gives anyone in the room a
last chance to mention the host nobody told you about.

**2. Share your screen and run it.** Let them watch it happen. The tool being
unremarkable to watch is part of the reassurance.

```bash
./bin/ray-guard -cidr <their ranges> -out ~/assessments/<client>-<date>
```

For a tenant-side engagement, add `-buckets` if object storage is in scope.

> **Write the report outside this repository.** A client's findings are their
> confidential data and this repo is destined to be public. `.gitignore` has
> patterns as a backstop, but the rule is simpler: client output lives in
> `~/assessments/`, never in the working tree.

**3. Read the report together, in this order:**

- **Grade and the one-line rationale.** Let it land before moving on.
- **"Fix these first."** Walk the list. Every item has a remediation — use it,
  this is what makes it an audit-to-fix tool.
- **The Ray finding, if there is one.** Explain why it is remote code
  execution rather than a hardening gap ([`demo.md`](demo.md) has the wording).
- **The footer.** Read-only, one GET, no payload — before they ask.

**4. Do not fix anything for them.** You are not authorized to change their
systems and you do not want to be the last person who touched a cluster before
something broke. Hand them the remediation; let them run it.

**5. Write down every disagreement.** If they dispute a severity, a grade, or
whether something is even a problem — that is the most valuable output of the
whole exercise. Grade thresholds are explicitly provisional (CLAUDE.md §10.0)
so this feedback can move them.

**6. Ask the two gate questions, in these words.** Do not infer the answers
from enthusiasm:

> "Would you pay for this report?"
>
> "If you were describing this to a colleague, would you ask for it by name?"

An awkward question honestly answered is worth more than a warm meeting you
have to interpret afterwards. A "maybe" is a no — log it as a no.

**7. Ask about the benchmark snapshot.** Opt-in, and this is the moment:

> "There's an anonymized version — rule IDs and severities, hostnames replaced
> with salted hashes. It feeds an industry benchmark we want to publish. Can I
> include yours? Happy to show you the file first."

Then actually show them:

```bash
./bin/ray-guard -cidr <ranges> \
  -out ~/assessments/<client>-<date> \
  -benchmark-snapshot ~/assessments/<client>-<date>/snapshot.json
cat ~/assessments/<client>-<date>/snapshot.json
```

It is small and legible on purpose. Showing it is more persuasive than
describing it.

## After

- [ ] **Send the report** (`report.html`, one self-contained file) **plus
      [`../threat-model.md`](../threat-model.md)**. The second one is what gets
      forwarded to whoever asks "what did you let them run?"
- [ ] **Log the row in [`../validation-log.md`](../validation-log.md).** Same
      day, while you remember it. That file lists what to capture beyond the
      yes/no columns — read it before writing, not after.
- [ ] **Update the gate count** at the top of that file. It is the number the
      whole project is waiting on.
- [ ] **Log what they asked for that does not exist.** Especially anything that
      would pull L2 or L3 forward. Capture the ask; do not build it (P1).
- [ ] **Delete their report** at the retention period you committed to.

## The honest failure modes

Watch for these — each quietly turns a gate-qualifying assessment into
something that does not count:

- **They were not really in the room.** Screensharing to someone answering
  email is not a buyer-led assessment.
- **You found nothing.** A clean A+ result is a fine outcome for them and a
  weak conversation for you. Ask anyway: "if this had found an exposed Ray
  dashboard, would you have paid to know?" Log the answer as what it is —
  hypothetical.
- **You oversold.** If you claimed cross-tenant isolation proof or hardware
  attestation, you have a yes that will not survive their technical review.
  See the do-not-claim list in [`objections.md`](objections.md).
- **You logged a "maybe" as a yes.** The gate exists to tell you something you
  might not want to hear. A log that flatters the product is worse than none.
