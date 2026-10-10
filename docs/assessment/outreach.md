# Getting the meeting

The kit used to start at the first call. This is the step before it, and it is
the one actually standing between here and the gate: **0 / 3** buyer-led
assessments, **0 / 2** pay-and-name-it.

What outreach has to produce is narrow. Not a download, not a star, not a
"this is interesting, keep us posted". One scheduled call, with the person who
owns security or ops for a GPU cluster **in the room**, that ends with
authorization to scan something real. Anything less does not count toward the
gate, and the gate is the point.

---

## Who to contact

In a Neocloud of 20–200 people, the person who can say yes to a scan is one
of:

- **Head of Security / CISO / Security Engineer** — ideal. Owns the answer.
- **Head of Infrastructure / Platform / SRE lead** — often the real owner at
  this size, because there is no security team yet.
- **CTO / VP Engineering** — at the smaller end, this is the security team.
- **Head of Solutions / Sales Engineering** — the one who feels the pain
  *commercially*: they are the person losing weeks to enterprise vendor
  security reviews. They will route you to the owner, and they are more
  motivated than the owner is.

Avoid starting at the CEO of anything larger than ~30 people; you get a polite
forward and lose the thread.

On the tenant side (§1.5), the buyer is different: **Head of Security,
Compliance, or ML Platform** at a company *renting* GPUs to run models on
regulated data. Their question is not "are we sellable" but "can I let our
models run there".

## The cold email — Neocloud side

Short enough to read on a phone. No attachment, no deck, no calendar link in
the first email.

> **Subject:** Ray dashboards exposed on GPU clusters — free 30-min check of
> yours
>
> Hi <name>,
>
> I build an open-source scanner for AI-infrastructure exposure — exposed and
> unauthenticated Ray, vLLM, Triton, TorchServe, Jupyter, MLflow, Slurm and
> similar, plus GPU telemetry that quietly lists which tenant is on which GPU.
>
> The reason I'm writing: the ShadowRay campaign (CVE-2023-48022) found
> exposed Ray clusters by scanning the internet and used them to mine crypto
> and steal credentials. Nobody targeted those companies — they were just
> reachable. TorchServe has the same shape (CVE-2023-43654) and is no longer
> maintained upstream. CSPM tools like Wiz don't look here; they need a cloud
> management API, and bare metal doesn't have one.
>
> I'd like 30 minutes with whoever owns security for your clusters. I'll show
> you the tool against a cluster I broke on purpose, and if you want, we scan
> a range you choose, you watch it happen, and you keep the report. Read-only,
> one HTTP GET per service, no credentials, nothing installed, nothing
> transmitted anywhere. Free — I'm looking for feedback from people who run
> this hardware, not for a purchase order.
>
> Code and threat model: github.com/karteekp20/gpu-security
>
> — <name>

Why it is built this way:

- **The CVE is the hook, not the product.** They can verify it in 30 seconds,
  which is the whole reason to lead with it.
- **"Free, and I want feedback" is true.** You have no credential to sell yet
  (see the do-not-claim list in [`objections.md`](objections.md)). Saying so
  is both honest and disarming.
- **The read-only sentence appears in the first email**, because it is the
  first objection and it arrives whether or not you pre-empt it.
- **The ask is a meeting with a named role**, not "a chat". Vague asks get
  vague yeses, and a vague yes produces a call with nobody who can authorize
  anything — which is the failure mode listed at the bottom of
  [`runbook.md`](runbook.md).

## The cold email — tenant side

Same tool, different fear. These are the people who push their provider to
buy.

> **Subject:** Proving your rented GPU slice isn't exposed
>
> Hi <name>,
>
> You're running models on rented GPU capacity. Your CSPM can't see that
> environment — there's no cloud management API to connect it to — so the
> usual answer to "is this safe" is the provider's word.
>
> I build an open-source scanner that runs from inside your own slice and
> reports what's reachable and unauthenticated: Ray, vLLM, Triton, TorchServe,
> Jupyter, MLflow, and whether GPU telemetry is leaking which workloads run
> where. It writes a report you can hand your auditor.
>
> Honest about the limit: it covers *your* exposure. It cannot prove another
> tenant can't reach you across the fabric — that needs InfiniBand and
> hardware checks I haven't built. If someone tells you a scan proves tenant
> isolation, they're selling.
>
> 30 minutes, we run it against your own hosts, you keep the report. Free.
>
> Code and threat model: github.com/karteekp20/gpu-security
>
> — <name>

The disclaimer in the third paragraph is not modesty. It is the fastest way to
be believed by someone who has sat through a lot of vendor calls, and it is
the same limit written down in [`objections.md`](objections.md) so you can't
quietly drop it later.

## The warm intro

If someone will introduce you, ask them to forward three sentences, not the
email above:

> <name> built an open-source scanner that finds exposed AI orchestrators —
> Ray dashboards, inference servers — on bare-metal GPU clusters, the stuff
> CSPM tools can't see. They're offering a free 30-minute assessment and want
> feedback from people who actually run this hardware. Worth 30 minutes?

## The follow-up

One. Four to seven days later, in the same thread, two sentences:

> Following up once on this — happy to drop it if the timing's wrong.
> If it helps, the 30 minutes can be entirely me showing you the tool against
> my own broken cluster; nothing of yours needs to be touched to decide
> whether it's useful.

Then stop. A third email buys nothing and costs the relationship you might
want in six months.

## When they reply

| Reply | What to do |
| :-- | :-- |
| "Send me more info." | Repo link plus **one** paragraph, then re-ask for the 30 minutes. A thread that becomes a document exchange will not become an assessment. |
| "We already have Wiz / Prisma / Orca." | [`objections.md`](objections.md), first section. Do not argue — "keep them, they do a different job" is the honest answer and the persuasive one. |
| "Just send the scanner, we'll run it ourselves." | Say yes immediately — it is open source and you could not stop them anyway. Then: *"Can I be on the call when you run it? I mostly want to hear what it gets wrong."* An unattended run is explicitly **not** gate-qualifying ([`../validation-log.md`](../validation-log.md)), and this framing is both true and the only one that reliably works. |
| "What would this cost?" | The best reply you will get. Do not invent a number mid-call. *"I don't have pricing yet — that's partly what I'm trying to learn. What would something like this be worth to you, and which budget would it come out of?"* Log the answer; the budget line matters more than the number. |
| "Who else uses it?" | You have no customers. Say so: *"Nobody yet — you'd be among the first, which is why it's free and why I want the criticism."* Inventing a logo is the one lie that ends the relationship when it unravels, and it always unravels. |
| Silence after one follow-up. | Stop. Log it as no response. |

## What not to do

These are not etiquette notes. Each one is a way to lose the thing the whole
project is waiting on.

**Never scan their infrastructure before written authorization.** Not their
public IPs, not "just a quick look", not to make the first email more
compelling. It is unauthorized scanning, it may be unlawful where you are, and
for a company selling trust it is disqualifying in a way no finding could
offset. [`authorization.md`](authorization.md) exists precisely so this is
never a judgement call. The threat model names this (T7) as the misuse the
tool class invites.

**Don't open with third-party exposure data about them**, even though public
internet-scan datasets exist and it is tempting. "I found your exposed
dashboard" starts the relationship with the prospect feeling surveilled by
the person asking for their trust. If they ask directly whether anything of
theirs is publicly visible, answer honestly — but do not lead with it.

**Don't claim anything that doesn't exist.** No signed trust credential, no
compliance certification, no continuous monitoring, no cross-tenant isolation
proof, no customers, no funding. The full list is the bottom half of
[`objections.md`](objections.md), and outreach is where overclaiming actually
starts — a sentence written to get a reply becomes a promise you have to
defend in the room.

**Don't let the meeting happen without the right person.** A call with a
solutions engineer who finds it interesting is a nice conversation and a
zero on the gate. Ask, before confirming: *"Will whoever owns security for
the clusters be on the call?"* If not, offer to move it.

**Don't optimize for stars.** Publishing the scanner is distribution in
service of getting into rooms. GitHub stars and download counts are
explicitly not the gate (CLAUDE.md §14), and a launch that goes well can
feel like progress while the gate stays at 0 / 3.

## Then what

A yes leads straight into the kit:
[`demo.md`](demo.md) → [`authorization.md`](authorization.md) →
[`runbook.md`](runbook.md).

Log outreach volume in the supporting-signal table of
[`../validation-log.md`](../validation-log.md) if you want to see your own
conversion rate, but keep it clearly separated from the gate. Twenty
conversations and zero assessments is itself a finding — it means the offer,
not the product, is what needs changing.
