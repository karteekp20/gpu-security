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

You should get grade **F**, 13 affected hosts, 21 findings, and `RG-RAY-001`
at the top of "Fix these first" with `RG-TORCHSERVE-001` second and a second
`RG-RAY-001` third - that one is the TLS-fronted dashboard (see below). If you
don't, fix that before the call rather than improvising in it.

Have `./report/report.html` open in a browser tab, ready.

## The run (about 60 seconds)

> "This is a small GPU cluster I've configured the way a lot of them
> accidentally are. Nothing exotic — Ray, vLLM, Triton, TorchServe, SGLang,
> Jupyter, MLflow, Ollama, the GPU exporter every node runs, and one service
> behind an HTTPS proxy. I'll scan the subnet; I haven't told the tool what's
> on it."

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

**3. The two criticals, and why they are different.** This is the whole pitch:

> "This one isn't a hardening gap. Ray's Jobs API takes job submissions from
> anyone who can reach it — that's the design. So an exposed dashboard means
> anybody on the network can run arbitrary code on your GPUs. It's
> CVE-2023-48022, and it's been exploited in the wild: the ShadowRay campaign
> found exposed clusters by internet-wide scanning and used them to mine
> crypto and steal credentials. Nobody targeted those companies. They were
> just reachable."

**The third critical is the same Ray dashboard behind HTTPS** (`172.31.77.50`),
and it is worth thirty seconds because it is the half-measure everybody has
tried:

> "This host is the same dashboard behind a TLS proxy. Encryption doesn't
> authenticate anybody — it's still remote code execution, just encrypted in
> transit. The scanner goes through the handshake, so a reverse proxy doesn't
> hide it. And it picked up the self-signed certificate on the way through,
> which is a separate, much smaller finding."

Then point at the second critical, because one example is a bug and two are a
pattern:

> "And here's the same shape again in a completely different project.
> TorchServe's management API registers a model from any URL you hand it —
> that's CVE-2023-43654, ShellTorch. TorchServe does enforce a token by
> default now, and this one has it switched off, which is a flag that exists
> because teams turn it off. Worth knowing: the official TorchServe container
> binds inference, management, metrics and both gRPC ports to 0.0.0.0 in its
> bundled config — their own docs say localhost, which is true of the tarball
> and not of their image. And upstream is archived, so there's no patch
> coming; the only durable control is keeping it off the network. That's the
> blind spot: not one CVE, but AI infrastructure shipping control planes that
> assume a trusted network and then getting deployed on one that isn't."

**3b. The DCGM finding, if the room is technical.** It is the one that is
*only* about GPUs:

> "That one's NVIDIA's GPU exporter, which runs on every node. Exposed, it
> hands over per-GPU utilization labelled with the pod and namespace using it
> — so it's an inventory of whose workload is on which GPU. No CVE, nothing
> exploitable. It's just a tenant list for anyone who asks."

**4. The footer.** Short, and it pre-empts the question they are already
forming:

> "Read-only. It found all of that with one GET request per service, plus one
> per port designed to catch the tool fooling itself — it
> never submitted a job, never executed anything, and it doesn't read model
> weights, prompts, or data. That last part is enforced by a test that blocks
> our build, not by a policy document."

## Two things to volunteer before they ask

Say both unprompted. It costs you nothing and buys the credibility you need
for everything else you claim.

- **"Four of the services in this demo are stand-ins."** vLLM, Triton, SGLang
  and the DCGM exporter need GPUs, so those four replay the documented
  response shapes of their health endpoints. Ray, Jupyter, MLflow, Ollama and
  TorchServe are the genuine software — and both criticals, the two that carry
  the pitch, fire against the real thing.
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
- **Fewer than 13 hosts found** — something didn't come up. `make demo-down &&
  make demo-up` and check the output of `wait-ready.sh`.
- **`N/A — INCONCLUSIVE`, nothing responded** — the stack is gone. Most
  likely you ran `make test-integration` after `make demo-up`: it brings the
  same stack up and tears it down again on exit. Re-run `make demo-up`.
  (Worth noting that the tool said "inconclusive" rather than "A+" here —
  that is the behaviour the report footer is describing.)
- **Asked something you can't answer** — say so and write it down. "I don't
  know, I'll find out" costs nothing here; a confident wrong answer to a
  security lead costs the deal. See [`objections.md`](objections.md), including
  the list of things the tool genuinely cannot do.
