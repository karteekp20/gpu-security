# Hard questions, honest answers

Read the **do-not-claim list at the bottom first.** It matters more than
anything above it. Every answer here is one you can defend when someone checks.

---

## "We already have Wiz / Prisma / Orca / Defender."

Good — keep them. They do a different job.

Those tools audit cloud metadata, models, data and agents through cloud APIs.
They stop at the hardware boundary, and they need a cloud management API to
connect to. Bare-metal GPU clusters largely do not have one.

What they do not see: an unauthenticated Ray dashboard on 8265, InfiniBand
partition keys, RDMA protection domains, GPU firmware state, whether
confidential-computing mode is actually on. Not because those tools are bad —
it is below the line they were built to look at.

The blunt version, if the room can take it:

> "If Wiz covered this, ShadowRay would not have worked. Those clusters
> belonged to companies with security programs."

**And the part that is about you, not the product:** Wiz is Google-owned. If
you are a Neocloud competing with GCP, a Google-owned security report is an
awkward thing to hand your own customers. Being the independent third party is
a structural advantage, not a technical one — say it as such.

Mind the edge of it, though: the signed trust credential that would *be* a
portable attestation is not built. Today you are offering a neutral
assessment, not a neutral certificate. Do not blur the two.

## "Can't we just run nmap?"

For discovery, largely yes — and if that is all you need, run nmap.

nmap tells you port 8265 is open. It does not tell you that it is a Ray
dashboard, that it answers without authentication, that this is
CVE-2023-48022, that it means remote code execution rather than an open port,
what the fix is, or where it lands against a posture grade you can show a
customer.

> "nmap gives you a port list. This gives you a finding with a fix, and a
> report you can hand to your own buyer."

The second half is the real answer. Nobody puts an nmap output in front of a
prospect during a vendor security review.

## "Is this safe to run against production?"

Fair question, and the honest answer has a caveat in it.

- One TCP connect and at most one HTTP GET per service check, to documented
  health endpoints. No request body, no method other than GET, no retries
  against a host that responded.
- Bounded concurrency and short timeouts. A /24 finishes in well under a
  minute.
- Probe paths are on a reviewed allowlist enforced in CI. A path with a query
  string, a traversal, or an execution endpoint fails the build.
- It executes nothing, deploys nothing, and needs no credentials.

The caveat, stated without being asked:

> "A single GET to a health endpoint is the smallest probe that can exist, but
> I won't tell you that scanning a live system is risk-free. A fragile service
> could in principle respond badly. That's written down in our threat model
> under T2, along with everything else we're accepting rather than pretending
> away."

Then send [`../threat-model.md`](../threat-model.md). Volunteering the
residual risk is what makes the rest of your safety claims credible.

## "What do you do with our data?"

Nothing, and it is enforced rather than promised.

The tool never reads model weights, prompts, training data, inference content,
or object contents. Response bodies are discarded without being inspected.
Public bucket exposure is decided from the HTTP status code alone — listings
are never read, because object keys are your data.

> "It's a test that blocks our build, not a policy document. We scan a server
> that deliberately serves fake secrets and assert none of it reaches any
> output — including our in-memory structures. We've also deliberately broken
> it to confirm the test actually fails."

Offer to show them: `make test-p3`, and the code is public.

## "Our margins are thin. We can't spend more on security."

The most common Neocloud objection, and arguing about security budget is the
losing frame. Move it to a number they already watch.

> "Then let's not treat it as security spend. You've got GPUs sitting idle and
> a control plane anyone can submit jobs to. That's not just a breach risk —
> that's someone else's crypto miner running on hardware you're paying for.
> Same finding, two budget lines."

Also worth raising: an exposed cluster is a deal-blocker in *their* sales
cycle. A trust report that gets them through an enterprise vendor security
review faster is revenue, not cost.

> "How many deals are stuck in someone's security review right now?"

## "Why should we trust a tool from someone we've never heard of?"

You should not, on my word. So do not:

- The source is public. Read what it sends.
- Releases are signed with cosign and ship an SBOM. Verify before running.
- The threat model is published, including what we are *not* defending against.
- It runs on your laptop, against targets you name, in a window you set, and
  sends nothing anywhere.

> "You don't have to trust us. That's rather the point of the product."

## "What if it breaks a running training job?"

Say the real answer, not the comfortable one.

> "I can't give you a guarantee. What I can tell you is what it actually does:
> one GET per service, bounded concurrency, no retries, nothing executed. If
> at any point you want it stopped, say so and I stop. And we'll agree the
> window in advance so it isn't running during anything you care about."

If they are still uneasy, offer the smaller scope: scan a subset, or a staging
environment first. An assessment on ten hosts that happens beats one on two
hundred that does not.

## "Can you prove our tenants are isolated from each other?"

**No — and this is the answer that protects you.** See below.

---

# Do not claim these

The fastest way to lose a technical buyer is to overclaim something they can
check. Every item here is a real limit of what exists today.

### Cross-tenant isolation

An L1 scan **cannot** prove tenant isolation. It sees what is reachable from
where it stands. It cannot tell you whether tenant A can reach tenant B across
the fabric.

> "No. That needs fabric-level checks — InfiniBand partition keys, RDMA
> protection domains — and that's a deeper tier we build on customer demand,
> not something this scan can show you. What I can show you today is your
> orchestrator exposure, which is where the actual incidents have come from."

CLAUDE.md §1.5 flags this explicitly. It is also the thing most likely to come
out of your mouth when a meeting is going well.

### Hardware or confidential-computing attestation

Not built. L2 will observe *claimed* CC mode; L3 will cryptographically verify
it. Today the tool does neither. Never describe an L1 finding as attestation.

### That the grades are authoritative

The A+/A/B/C/F bands are provisional until buyer feedback moves them. Say so —
it is in the report footer anyway, so claiming otherwise is a contradiction
they can see.

> "Treat the grade as a conversation starter. Tell me where you'd put the
> thresholds."

### Continuous monitoring

This is point-in-time. It tells you what was exposed when you ran it. Drift
detection — "is CC mode *still* on, did that P_Key change" — is a later phase.
Do not let "posture management" be heard as "we watch it for you".

### Compliance certification

The tool maps findings toward control frameworks. It does not certify
anything, and no auditor accepts a scanner's output as a control. It produces
evidence a human still has to submit.

### A specific roadmap date

You do not have a control plane yet, and whether you build one depends on
these very conversations. Promising a Q-whatever delivery to close a call
creates a debt you may decide not to pay.

> "I'd rather tell you what exists today and let you judge that. What's built
> next depends partly on this conversation."

---

**If you do not know, say so.** Write the question down and follow up. Every
person in these rooms has watched a vendor bluff, and they all remember which
one it was.
