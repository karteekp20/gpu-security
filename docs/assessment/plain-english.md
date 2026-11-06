# Plain English

For a reader who does not work in security or infrastructure — a founder, a
sales or finance lead, a procurement reviewer, anyone who needs to understand
what this is before deciding whether to spend thirty minutes on it.

Everything here is something you can check. Where the tool cannot do something,
this page says so, because the alternative is being corrected in a meeting by
the one person in the room who knows.

---

## The thirty-second version

Companies rent very expensive computers — GPU clusters — to build and run AI.
The software that controls those computers was designed on the assumption that
only trusted people can reach it. It is then installed in places where that is
not true, and it often ships with its control panel open to anyone who knows the
address.

We check, from the outside, which of those control panels are open. We do not go
in. We hand over a report that says what is exposed, how serious each one is,
what the fix is, and a single grade for the whole thing.

That is it. One tool, one report, nothing installed.

---

## A picture to hold onto

Think of a GPU cluster as an **apartment building**.

| In the building | In real life |
| :-- | :-- |
| The landlord who owns it | A GPU cloud provider — the industry calls these **Neoclouds** (CoreWeave, Lambda, Nebius, RunPod…) |
| The tenants renting flats | Companies renting GPU capacity to train or run AI models |
| The building's control room | The AI control software — Ray, Jupyter, TorchServe and others |
| The doors, each with a number | **Ports** — numbered entrances on a machine. Ray's control panel is at door 8265 |
| A door that opens without a key | An **unauthenticated** service: it answers anyone who knocks |

We are the building inspector. We walk the corridors and knock once on each
door we know about. We never go inside.

This analogy carries the whole document, including the part where it breaks
down — see *"What we cannot tell you"* near the end.

---

## What is actually going wrong

The control room is not just a place to watch from. In most of these AI tools it
is a place to **submit work from** — you hand it a command and it runs that
command on the cluster.

So a control room that opens without a key is not an information leak. It is a
stranger being able to run their own programs on your hardware.

This has already happened, twice, under names you can look up:

**ShadowRay.** Attackers found Ray clusters whose control panels were reachable
from the open internet. They did not break in — the door was open. They used the
clusters to mine cryptocurrency on hardware someone else was paying for, and
they took credentials and secrets they found there. Crucially, the victims were
found by **scanning the whole internet**, not by being targeted. Nobody chose
them. They were simply reachable. The security firm Oligo reported over 230,000
exposed Ray servers.

**ShellTorch.** The identical pattern in a different AI tool, TorchServe: a
management door that registers and loads a model from any address the caller
names.

Two separate campaigns, one cause. That is the point: this is not a bug in one
project, it is a **habit** across AI infrastructure software. Which is why the
problem is worth a product rather than a patch.

### Why the Ray one cannot simply be fixed

Normally the answer to a security flaw is "upgrade to the fixed version." Here
there isn't one.

Ray's maintainers consider the open control panel **intended behaviour** —
their position is that you are supposed to run it on a trusted network. So the
vulnerability number for it (CVE-2023-48022) is formally disputed and has no
patch. There is no version to upgrade to.

Which means **whether it is reachable is the entire defence.** And reachability
is exactly what this tool measures.

A second, newer one (CVE-2025-62593) *is* version-specific, and it is on the US
government's **CISA Known Exploited Vulnerabilities** list — the official
catalogue of flaws confirmed to be used in real attacks. A thirty-second check
anyone can do.

### What it costs when it goes wrong

Three different bills, and only the first is the obvious one:

1. **Stolen compute.** Someone else's workload on GPUs you are paying for, or
   renting out.
2. **Stolen secrets.** Cloud keys, model weights, customer data reachable from a
   machine the attacker now controls.
3. **Stalled deals.** Every enterprise customer runs a vendor security review
   before signing. An exposed cluster is a review that does not finish, and a
   deal that does not close. This is usually the expensive one.

---

## "Doesn't our cloud security tool already cover this?"

This is the first question every technical buyer asks, and the honest answer is
that the big tools do a genuinely good job — of something else.

Wiz, Prisma, Orca and Microsoft Defender work by **reading the building's
paperwork at the management office.** They connect to a cloud provider's
administrative system and audit what it reports: accounts, permissions,
configuration, which machines exist.

Two things follow.

**First, bare-metal GPU clusters often have no management office to visit.** A
company renting physical GPU servers has no cloud administrative system for a
tool to log into. There is no paperwork. There is only the building.

**Second, those tools stop above the floor this problem lives on.** They audit
cloud configuration, models and data. They do not walk the corridor and knock on
door 8265 to see whether the control room opens. It is not a failing — it is
below the line they were built to look at.

The single sentence that settles it:

> If those tools covered this, ShadowRay would not have worked. The clusters
> that got compromised belonged to companies that had security programmes and
> paid for security tools.

**And one point that is not technical at all.** Wiz is owned by Google. If you
are a GPU provider competing with Google Cloud for the same customers, a
Google-owned security report is an awkward thing to hand your own prospects. An
independent third party is worth something here that has nothing to do with how
good the scanner is.

---

## How the scan actually works

The tool is called `ray-guard`. It runs on a laptop. Here is everything it does.

**It knocks. Once. On doors it already knows about.**

For each machine you name, it tries the specific door numbers where AI control
software lives — 8265 for Ray, 8888 for Jupyter, 8081 for TorchServe, and about
a dozen more. For each one it asks a single, harmless question: the equivalent of
*"what version are you?"*

Three things can happen:

- **No answer** → the door is closed or firewalled. Nothing to report.
- **It answers, and asks for a key** → good. That is how it should be.
- **It answers with no key at all** → that is a finding.

**It does not go in.** It confirms an unauthenticated Ray control panel by
getting an answer from the version page — not by submitting a job. The
difference between observing and exploiting is the whole basis of being allowed
to run this against a live system.

**It knocks on one door that does not exist.** On any port where it thinks it
found a service, it sends one more request to a made-up address
(`/ray-guard-probe-404`). Some servers are configured to say "yes, fine" to
every request. If a server says yes to a door that does not exist, we refuse to
name what it is, and report it as "something is listening here, unidentified."

This is worth volunteering to a sceptical client, because it is unusual:

> It sends one request specifically designed to catch us fooling ourselves.

**What it never does:**

- Installs nothing. No software goes onto your machines, ever.
- Needs no credentials. You give it no passwords, keys or accounts.
- Reads none of your data. Not model weights, not prompts, not training data,
  not what is inside your storage. Responses are thrown away without being
  looked at.
- Sends nothing anywhere. It talks only to the machines you named. There is no
  "phone home", no update check, no usage telemetry. This is not a policy — the
  code has no such capability, and an automated test blocks the build if anyone
  adds one.
- Changes nothing. It is read-only in the strictest sense.

**How long it takes.** A single machine: seconds. A subnet of 254 addresses
that do not answer is bounded at roughly thirty seconds — about eight times the
probe timeout, at the four-second default. Machines that do answer finish
sooner; our own demonstration cluster of 254 addresses takes about sixteen
seconds. The slow case is a machine that accepts the connection and then goes
silent, and even a whole subnet of those is minutes rather than hours.

**You can stop it.** Ctrl-C halts it instantly and still writes the report for
whatever it had already reached, clearly marked as incomplete. Nobody has to
weigh "stop this now" against "lose the run and book another window."

**We only ever scan with written permission**, naming the exact addresses and
the time window. That document comes before any scan, every time, with no
exceptions — including for addresses that are publicly visible.

---

## How to read the report

The report is a single file that opens in any browser and prints cleanly. No
login, no account, no portal. It is yours; we keep no copy of it.

It has seven parts, in this order.

### 1. The grade

A single large letter, with one sentence underneath saying why. Think of a
restaurant hygiene rating: it is not the whole story, but you know immediately
whether to worry.

Beside it: how many machines were asked, how many answered, how long it took,
and a count of findings by severity.

### 2. The coverage gap

**The most misread part of the report, so read it first.**

If the scan asked 254 addresses and 15 answered, the report says so plainly:
*"239 targets were not assessed."* It also **draws** it — a single bar split
into what answered and the several different ways the rest did not. A machine
or two that we could not assess is drawn wide enough to see rather than
rounded away, which is deliberate: the small gaps are the ones that get
missed.

A machine that did not answer is **not** a machine that is secure. It might be
switched off, firewalled, or simply on the other side of something from where we
were standing. This is why the report also records **which machine the scan ran
from** — "three of twelve didn't answer" means something entirely different when
the answer turns out to be "you were scanning from the wrong side of a firewall."

The rule: **we report what we saw, and we are explicit about what we did not
see.** A tool that quietly reports "all clear" for machines it never reached is
worse than no tool, and avoiding that has shaped a great deal of this product.

### 3. The exposure map

A grid: one row per machine that answered, one column per door number we
tried. Each square carries the worst thing found at that door, with a letter
in it as well as a colour, so it survives a black-and-white print.

This is the part that answers the question most people are actually holding,
which is **does this thing just shout at everything?** A list of findings
cannot answer it, because the machines that came back clean are not in a list
of findings. Here they are — rows of empty squares, sitting beside the bad
ones.

On our own demo cluster two of the fifteen machines that answered raise
nothing at all, and one of those is running the very software the worst finding
on the report is about. It is bound so that nothing outside that machine can
reach it, and the scan says nothing about it. Same software, same door number,
same rule, opposite answer — because the only thing that differs is whether it
can be reached from where we stood.

Two honest limits, both printed on the chart itself:

- **An empty square is not a locked door.** It means nothing we recognise
  answered there and no finding was raised. A door can be open, answer
  something we cannot identify, and still be blank here. Calling it "closed"
  would be inventing a reassurance we never established.
- **Big scans are trimmed.** Past forty machines the chart keeps the worst rows
  and states in words how many it did not draw, because a trimmed chart that
  does not admit it is worse than no chart.

### 4. Fix these first

The handful of items that matter most, in order, each with its fix. If you only
read one section, read this one. If you only act on one section, act on this
one.

### 5. Why this matters

For the serious findings, a plain explanation split into four deliberately
separate statements:

- **What we observed** — the literal fact. "The control panel answered without
  a password."
- **What that means** — the consequence. "The same panel accepts and runs
  submitted commands."
- **Why it is not theoretical** — the real campaign that used exactly this.
- **What we did not do** — the limits of our own evidence.

Keeping those apart is intentional. The observation is a fact; the consequence
is an interpretation. You are entitled to see which is which.

### 6. The findings, machine by machine

One table per machine. Each row: severity, the rule's ID, what was seen, the
door number, and the fix.

| Severity | Plain meaning | What to do |
| :-- | :-- | :-- |
| **Critical** | Someone who can reach this can run their own code on your hardware | Today |
| **High** | A service that should need a password doesn't, or a control port is open | This week |
| **Medium** | Real exposure, not direct code execution — e.g. monitoring data that reveals which customer is using which GPU | Planned work |
| **Low** | Minor, usually a monitoring endpoint that should be on a private network | Tidy-up |
| **Info** | Something is listening and we could not safely identify it. Not an accusation — a question for you | Confirm what it is |

Every finding has a stable ID like `RG-RAY-001`. Fix it, re-run the scan, and
you can point at the same ID being gone. That is what makes the report a work
item rather than an opinion.

Each finding also records **how we identified the service**: whether the
service's own API answered, or a conventional monitoring path, or only a
generic web page that any web server would have answered, or nothing more than
an open door. Two findings can carry the same severity and rest on very
different evidence, and the one resting on less is the one worth spot-checking
first. The report tells you which is which instead of leaving you to guess —
and it prints the exact path it asked for, so you can re-run the request
yourself.

### 7. How the grade was reached, and what the scan covered

The report prints the scoring table, so you can reconstruct the grade yourself
rather than taking our word for it. Above the table the same scale is drawn as
a strip of bands with the one this scan landed in filled in — including the A+
band, hatched and labelled *L3 only*, so you can see the grade that was not
available rather than having to be told it exists. There is deliberately **no
needle inside the band**: the scores below are representative of each band
rather than measurements, so a pointer at "40 out of 100" would claim a
precision we do not have.

**The worst single finding decides the grade** — first matching row wins:

| If | Score | Grade |
| :-- | :-- | :-- |
| Any critical finding | 40 | **F** |
| Otherwise, any high finding | 60 | **C** |
| Otherwise, any medium finding | 78 | **B** |
| Otherwise, nothing answered, or the scan was stopped early, or our own probing failed | — | **N/A** |
| Otherwise, any low or info finding | 90 | **A** |
| Otherwise, nothing exposed | 94 | **A** |

Three things about that table are worth understanding, because they are the
design, not accidents.

**One critical finding means F, no matter how clean everything else is.** One
open door is one way in. Nine locked doors do not offset it. Averaging would
make a cluster with one catastrophic hole look mid-table, which is precisely the
kind of reassuring number that gets people hurt.

**A is the best grade available here, and there is no A+.** A+ is reserved for
an assessment that cryptographically verifies the hardware itself and proves
network isolation between tenants — which requires access *inside* the machines
and is not what this is. A scan from outside cannot gather that evidence, so it
does not award the grade that claims it. **A clean result here is an A, and that
is the ceiling honestly.** We would rather have a lower ceiling than a grade
that means two different things in two different reports.

**N/A is not a pass.** If nothing answered, or the scan was interrupted, the
result is "no grade" — not a good one. We did not look, and that is not the same
as nothing being there.

Note the asymmetry in the ordering: a finding we *did* observe still counts even
if the scan did not finish, because an open door is an open door. The reverse
never holds — an incomplete scan can never earn a clean grade.

---

## What makes this different

Six things, in the order a client tends to care about them.

**1. It looks where the other tools stop.** Below the cloud management layer, at
the actual services running on the actual machines. That is where both real
campaigns happened.

**2. It is independent.** Not owned by a cloud provider you compete with.

**3. Every finding arrives with its fix.** A general-purpose port scanner tells
you door 8265 is open. It does not tell you that it is a Ray control panel, that
it answers without a password, that this means code execution rather than an
open port, what the fix is, or where it lands on a grade. And nobody puts a port
scanner's output in front of a customer during a security review.

**4. Your data is untouchable, and that is enforced rather than promised.** A
test suite scans a server that deliberately serves fake secrets and fails the
build if any of it reaches any output — including the tool's own internal
memory. We have deliberately broken that test to confirm it actually fails. You
can run it yourself.

**5. It works with no internet at all.** A single self-contained program, no
installation, no external services. It runs in a disconnected or
government-isolated facility exactly as it runs anywhere else — which also means
there is no mechanism by which your results could leave your laptop.

**6. You do not have to trust us.** The entire source code is public. The
published threat model lists what we are *not* defending against. Releases are
cryptographically signed. Read what it sends before you run it.

> You shouldn't trust us on our word. That is rather the point of the product.

---

## The same report, two different buyers

One tool, two directions, depending on who is holding it.

**The landlord — a GPU provider.** You scan your own environment and the report
becomes **sales material**. When an enterprise prospect's security team asks
"how do we know your cluster is safe?", you have an independent assessment
instead of a promise. The budget line is sales enablement or compliance, not
security.

**The tenant — a company renting GPUs.** You scan **your own rented slice** and
the report becomes **audit evidence** for your own auditors and your own board.
Note that an ordinary cloud security tool cannot help you here at all, because
there is no cloud management system for it to log into.

In practice these push on each other: a renter asking hard questions is often
what makes the provider go looking for an answer.

---

## What we cannot tell you

This is the most important section on this page. Everything below is a real
limit of what exists today, and we would rather you hear it here than discover
it later.

**We cannot prove your tenants are isolated from each other.** This is the
question providers most want answered, and the answer is no. The scan sees what
is reachable from where it stands. It cannot tell you whether customer A can
reach customer B across the high-speed network that connects GPUs. That needs
checks at the network-fabric level, which is a deeper tier we build when a
customer requires it. What we *can* show you today is control-panel exposure —
which is where both real campaigns actually came from.

**We do not verify your hardware.** No checking of firmware, no confirmation
that encrypted-memory features are genuinely switched on. Later tiers do that.
This one does not, and no finding here should be described as hardware
verification.

**It is a snapshot, not a watchman.** The report tells you what was exposed at
the moment you ran it. If someone opens a door tomorrow, this does not know.
Continuous monitoring is a later phase — please do not hear "posture
management" as "we are watching it for you."

**It is not a certificate, and we cannot issue one yet.** Today this is a
neutral *assessment*. The signed, independently verifiable trust credential —
the thing you could put on your website for customers to check — is designed but
not built. We will not blur those two.

**It does not certify compliance.** It produces evidence that maps toward
control frameworks like SOC 2 and ISO 27001. No auditor accepts a scanner's
output as a control. A human still submits it.

**The grades are provisional.** The A-to-F bands are a starting point, not an
industry standard, and buyer feedback is expected to move them. It says so in
the report footer, so claiming otherwise would be a contradiction you could see.

> Treat the grade as a conversation starter. Tell us where you would put the
> thresholds.

**We will not give you a delivery date for anything unbuilt.** What gets built
next depends partly on conversations like this one. A date invented to close a
call is a debt we might decide not to pay.

---

## Words you will hear, one line each

Terms that come up in these conversations, in the order they tend to appear.

| Term | In one line |
| :-- | :-- |
| **GPU** | The expensive chip that makes AI training and inference possible. A single top-end one costs more than a car. |
| **GPU cluster** | Many GPU machines wired together with very fast networking so they can work on one job. |
| **Neocloud** | A company that rents out GPU clusters. CoreWeave, Lambda, Nebius, RunPod. Not Amazon or Google — specialists. |
| **Bare metal** | Renting the physical machine itself rather than a slice of someone's cloud. Fast, and with none of the cloud's management tooling. |
| **Tenant** | A customer renting part of a shared cluster. "Multi-tenant" means several customers on the same hardware. |
| **Orchestrator / control plane** | The software that decides which GPU runs what. The control room. Ray, Slurm and Kubernetes are examples. |
| **Ray** | The most widely used of these. Its control panel sits on door 8265, and that is where ShadowRay happened. |
| **Inference server** | Software that takes a request and runs a model to answer it. vLLM, Triton, TorchServe, SGLang, Ollama. |
| **Port** | A numbered door on a machine. Software listens on a specific one; 8265 is Ray's. |
| **Endpoint** | A specific address a service answers on, like a specific window at a counter. |
| **Unauthenticated** | Answers anybody, no password required. |
| **Exposed / reachable** | Something can get to it from where we are standing. Note "from where we are standing" — reachable from inside your office is a different claim from reachable from the internet. |
| **RCE (remote code execution)** | A stranger can run their own programs on your machine. The worst category there is. |
| **CVE** | A public ID for a known vulnerability, like a case number. CVE-2023-48022 is the Ray one. |
| **CISA KEV** | A US government list of vulnerabilities confirmed to be used in real attacks. Being on it is serious and checkable in a minute. |
| **TLS / certificate** | The padlock in a browser. TLS encrypts traffic; the certificate proves the server is who it claims. Either can be missing, expired or wrong. |
| **Agentless** | Nothing is installed on your machines. The opposite is an "agent", software that has to be deployed everywhere. |
| **Read-only** | Observes, changes nothing. |
| **Payload vs. metadata** | Payload is your actual content — prompts, model weights, training data. Metadata is facts *about* the system, like "door 8265 answered". We handle metadata and never payload. |
| **Severity** | How bad one finding is: critical, high, medium, low, info. |
| **L1 / L2 / L3** | How deep an assessment goes. L1 is outside-the-machines (this). L2 is a light read-only component inside. L3 is deep hardware and network inspection. Each tier sees more and asks more of you. |
| **Coverage gap** | Machines we asked and that never answered. Unknown, not clean. |
| **Air-gapped** | A facility with no internet connection at all, usually defence or government. Our tool runs there unchanged. |
| **Attestation** | Hardware cryptographically proving what it is and what it is running. We do not do this yet. |
| **Confidential computing** | GPU memory encrypted so even the machine's owner cannot read a tenant's data. Checking whether it is genuinely on is a later tier. |
| **InfiniBand / fabric** | The very fast private network joining GPUs together. Misconfigured, it is how one tenant could reach another — and it is invisible to ordinary cloud tools. |
| **Trust credential** | The signed, independently checkable attestation a provider could show its customers. Designed, not built. |
| **Posture** | The overall security state of a system at a point in time. "Posture management" means tracking it as it changes. |

---

## Questions clients ask

### "We already use Wiz / Prisma / Defender."

Good — keep them, they do a different job. See the section above. Short version:
they read the cloud's paperwork; bare metal has no paperwork, and the doors
still need knocking on.

### "Can't we just use nmap?" (a standard free port scanner)

For finding open doors, largely yes — and if that is all you need, use it. It
will tell you door 8265 is open. It will not tell you it is a Ray control panel,
that it opens without a key, that this means code execution, what the fix is, or
how it grades. And nobody hands an nmap output to a customer's security
reviewer.

### "Is this safe to run on production?"

Mostly yes, and here is the caveat without being asked for it.

One connection and at most one simple request per service, to published status
addresses. No retries. Nothing executed. Nothing installed. No credentials.
Short timeouts and a deliberate cap on how many machines are contacted at once.
The addresses it may request are on a reviewed list enforced automatically —
anything resembling a dangerous address fails our build.

But: *"a single request to a status page is the smallest possible probe, and I
still won't tell you that scanning a live system is risk-free. A fragile service
could in principle respond badly. That is written down in our published threat
model, along with everything else we are accepting rather than pretending
away."*

Volunteering the residual risk is what makes the rest of it credible. Then send
them the threat model.

### "What happens to our data?"

Nothing, and it is enforced rather than promised. See point 4 above. The sharp
detail: storage exposure is judged **from the response code alone** — we never
read a file listing, because the names of your files are your data.

### "Our margins are thin. We can't spend more on security."

The most common objection from GPU providers, and arguing about security budget
is the losing argument. Move it:

> Then let's not call it security spend. You have GPUs sitting idle and a
> control panel anyone can submit jobs to. That is not only a breach risk —
> that is someone else's crypto miner running on hardware you are paying for.
> Same finding, two budget lines.

Then the question that actually lands:

> How many of your deals are stuck in somebody's security review right now?

As of late 2026 this matters more than it used to. The listed GPU providers took
a real market hit in October 2026 — CoreWeave, Nebius and IREN each down more
than 30% in a month — and Gartner's widely-cited projection is that over 80% of
neocloud providers may not operate independently by 2030. A company watching
that is not approving new security spend this quarter.

What it **is** doing is fighting for enterprise tenants, because those are the
customers who survive a price war, and every one of them runs a vendor security
review. So ask for the **sales-enablement or compliance** budget, never the
security one, and expect the buyer to behave like a sales leader rather than a
security officer.

Two cautions from the same facts: do not send a fear-led email to a company the
week its stock dropped, and **write down which budget line they name** — if the
answers keep coming back "sales enablement", that tells us something real about
what to build next.

### "Why should we trust a tool from someone we have never heard of?"

You should not, on our word. So don't: the source is public, releases are
signed, the threat model is published including its own gaps, and the thing runs
on your laptop against targets you name in a window you set, sending nothing
anywhere.

### "What if it breaks a running training job?"

The real answer, not the comfortable one:

> I can't give you a guarantee. What I can tell you is exactly what it does: one
> request per service, a cap on concurrency, no retries, nothing executed. If at
> any point you want it stopped, say so and I stop — and you keep the partial
> report, so stopping costs you nothing. And we agree the window in advance so
> it isn't running during anything you care about.

Still uneasy? Take the smaller scope. Ten machines, or a staging environment
first. **An assessment on ten machines that actually happens beats one on two
hundred that doesn't.**

### "Can you prove our tenants are isolated?"

No. See *What we cannot tell you*. This is the answer that protects you, and it
is the sentence most likely to escape when a meeting is going well.

### "Is this a certificate we can show customers?"

Not yet. Today it is an independent assessment. The verifiable credential is
designed and not built, and we will not describe one as the other.

### "Is it continuous?"

No. Point-in-time. Running it on a schedule is easy — it returns a result code
your own automation can act on — but nobody is watching it for you.

### "What does it cost?"

The assessment is free, and genuinely so: we want feedback from people who run
this hardware, not a purchase order. Pricing for what comes after is something
we are working out with early partners, and your view on it is part of what we
are asking for.

### How to make the case, in one paragraph

Lead with the deal that is stuck, not the breach that might happen. Offer the
smaller scope. Volunteer the limits before you are asked — every person in these
rooms has watched a vendor bluff, and they all remember which one it was.

**And if you do not know, say so.** Write the question down and follow up.

---

## Where this goes

Stated as conditional, because it is. Nothing below is promised, dated, or sold.

**Today.** A free, independent, point-in-time assessment and a report you keep.

**Next, if buyers want it.** The signed trust credential — a tamper-evident,
independently verifiable attestation, and a public page where a provider's own
prospects can check it themselves without trusting us or the provider. This is
the piece that turns a report into something that shortens a security review.
Alongside it, a low-friction read-only component that runs inside the cluster so
posture can be tracked over time instead of sampled once. "An A, holding for
forty days" is a different statement from "an A, scanned once."

**Later, on request only.** Deep verification of the hardware itself and
cryptographic proof of isolation between tenants — the thing we currently say we
cannot do. Fully isolated deployments for government and defence. And an
anonymised industry index — a "State of Neocloud Security" built from aggregate
data, never from anyone's identifiable results.

**The honest ceiling.** This is a strong specialist business or an eventual
acquisition by a larger security or GPU-infrastructure player. We are not
pitching it as the next hundred-billion-dollar company, because it isn't one,
and anyone experienced enough to be worth talking to can tell.

**What actually decides any of it** is conversations like this one. The next
thing we build is whatever the people who run this hardware tell us is worth
building — which is the real reason the assessment is free.
