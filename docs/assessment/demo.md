# The demo — showing the tool before you touch anything

No security lead grants scan access to an unfamiliar binary on a first call.
So you show it working on a cluster you broke on purpose, on your own laptop,
and let them decide afterwards whether to give you targets.

The demo environment is the same stack the integration tests use, so it is
maintained by being tested, not by being remembered.

## Before the call

```bash
make demo-up      # 1-2 min: Ray takes 30-60s to bind its dashboard
```

**Run this before you join, not while they watch.** A minute of silence on a
screenshare while containers pull is the worst possible opening.

Check it worked:

```bash
make demo         # ~15s, writes ./report
```

You should get grade **F**, 8 affected hosts, `RG-RAY-001` at the top. If you
don't, fix that before the call rather than improvising in it.

Have `./report/report.html` open in a browser tab, ready.

## The run (about 60 seconds)

> "This is a small GPU cluster I've configured the way a lot of them
> accidentally are. Nothing exotic — Ray, vLLM, Jupyter, MLflow, Ollama.
> I'll scan the subnet; I haven't told the tool what's on it."

```bash
make demo
```

Let the terminal output land first. It is short and it makes the point on its
own. Then switch to the report.

## What to point at, in this order

**1. The grade, and the sentence under it.** Not the findings list. The first
thing they should absorb is *F — and here is why, in one sentence.* If they
read nothing else, they have the answer.

**2. "Fix these first."** Five items, each with the actual remediation. This is
where you say the thing that separates you from a port scanner:

> "Every finding comes with the fix. It's an audit-to-fix tool, not an
> audit-only one."

**3. The Ray finding, and why it is different.** This is the whole pitch:

> "This one isn't a hardening gap. Ray's Jobs API takes job submissions from
> anyone who can reach it — that's the design. So an exposed dashboard means
> anybody on the network can run arbitrary code on your GPUs. It's
> CVE-2023-48022, and it's been exploited in the wild: the ShadowRay campaign
> found exposed clusters by internet-wide scanning and used them to mine
> crypto and steal credentials. Nobody targeted those companies. They were
> just reachable."

**4. The footer.** Short, and it pre-empts the question they are already
forming:

> "Read-only. It found all of that with one GET request per service — it
> never submitted a job, never executed anything, and it doesn't read model
> weights, prompts, or data. That last part is enforced by a test that blocks
> our build, not by a policy document."

## Two things to volunteer before they ask

Say both unprompted. It costs you nothing and buys the credibility you need
for everything else you claim.

- **"Two of the services in this demo are stand-ins."** vLLM and Triton ship
  GPU-only images that won't run on a laptop, so those two replay the real
  response shapes. Ray, Jupyter, MLflow and Ollama are the genuine software —
  and Ray, the one that matters, is real.
- **"The grades are provisional."** The A+ to F bands aren't validated yet.
  Ask them where they'd move the thresholds — the answer is genuinely useful
  and the question signals you are not selling them a finished opinion.

## After

```bash
make demo-down    # removes containers, network and volumes
```

Then go to [`runbook.md`](runbook.md) for the real engagement, which starts
with [`authorization.md`](authorization.md) — not with a scan.

## If it goes wrong

- **Compose says "client version is too old"** — your compose plugin predates
  the daemon: `DOCKER_API_VERSION=1.44 make demo-up`.
- **Fewer than 8 hosts found** — something didn't come up. `make demo-down &&
  make demo-up` and check the output of `wait-ready.sh`.
- **Asked something you can't answer** — say so and write it down. "I don't
  know, I'll find out" costs nothing here; a confident wrong answer to a
  security lead costs the deal. See [`objections.md`](objections.md), including
  the list of things the tool genuinely cannot do.
