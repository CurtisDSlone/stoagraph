# Security model

StoaGraph is a security control, so its guarantees — and its limits — must be explicit. This document
states what the gate protects, what it does **not**, the trust boundaries, and the operator's
responsibilities. If you are evaluating StoaGraph, read **Non-goals** as carefully as **Guarantees**.

## Reporting a vulnerability

Report suspected vulnerabilities privately. Do not open a public issue for a security problem.

The preferred channel is a GitHub private security advisory:
https://github.com/CurtisDSlone/stoagraph/security/advisories/new. You can also email curtisdslone@gmail.com.

We follow coordinated disclosure: please give us up to 90 days to ship a fix before you disclose
publicly. We will acknowledge the report, keep you updated, and credit you when the fix ships unless you
prefer to stay anonymous.

## What StoaGraph provides

A **deterministic mediation boundary** between an AI agent and the world. Every governed tool call is
evaluated against a *recipe* (a policy you author) by a model-free kernel and forwarded to the real tool
**only** if the recipe releases it. Every piece of context the agent reads crosses the same gate and is
stamped untrusted. The decision never depends on the agent or the model.

The core property: **a manipulated or mistaken agent cannot exceed the recipe.** Prompt injection, a
jailbroken model, or a confused agent can change what is *proposed* — it cannot change what is
*allowed*. A bad proposal wastes a turn; it does not breach the boundary.

## Trust model

| Component | Trust | Notes |
| --- | --- | --- |
| The agent/model, its proposals, retrieved context, the triggering event | **untrusted** | The gate assumes all of it may be adversarial. |
| The **orchestrator** (`harness`) | **semi-trusted** | It holds the model API keys and binds sessions. It is *not* trusted to approve — see below. If it is compromised, it can waste money and propose freely; it cannot exceed the recipe or self-approve. |
| The recipe, the config store, the gate (`stag`), the human operator | **trusted** | The recipe *is* your policy; the gate enforces it faithfully. |
| Downstream tool (MCP) servers | **relied-upon** | They perform the real actions. The gate controls *what reaches them*, not what they do internally. |

**The gate holds no model and no API keys — and this is enforced, not asserted.**
[`stoa-kernel/architecture_test.go`](stoa-kernel/architecture_test.go) fails the build if any gate
package, or either gate binary, imports orchestrator code.

## The trust invariant — positional labels, not taint tracking

This is the subtlety that most systems get wrong, and it must not be misread.

Context is stamped **untrusted at origin, unbypassably** — a provider cannot hand back trusted-looking
content. But that label is **positional**, not a taint tag that survives the model:

- **Into the model**, the label's only job is *placement*: untrusted content goes in the input slot,
  never the instruction slot, so it cannot rewrite the agent's goal.
- **Out of the model**, there is **no carried label at all.** An LLM launders taint — you cannot know
  which output bytes came from which input. So the gate does not try. **Every proposal is presumed
  untrusted**, and the gate re-derives trust **at the sink**, from the rule.

The only promotions from untrusted to cleared are a rule firing (`set_membership`, `numeric_range`,
`signed_equality`), each emitting a recorded release event. **Poisoned context can change what is
proposed; it cannot make the gate release a value the rule rejects.**

Do not build on the assumption that the untrusted label follows a value through the model. It does not,
by design, because that guarantee is not achievable and pretending otherwise is how systems get breached.

The mechanics — label at origin, position in the input slot, re-derive trust at the sink — are in
[docs/context-binding.md](docs/context-binding.md); the tenets in [docs/doctrine.md](docs/doctrine.md).

## Integrity, and a bounded residual

StoaGraph is primarily an **integrity** control: it stops untrusted data from *authorizing an action*.
It is not a full **confidentiality** control, and it does not pretend to be. Even when every allowed
value is a closed set, a compromised model still gets to choose *which* of the allowed values crosses,
and *whether* to act at all — a residual covert channel measured in bits per crossing.

StoaGraph's answer is to **bound and report** that channel rather than wave it away: `recipe.Leakage`
computes a signed, static number — the most a fully prompt-injected agent could exfiltrate through the
actions it is *allowed* to take — and the deployment can refuse any policy whose leak is not finite. The
residual is not zero; it is a number you can see. See [Guarantees](#guarantees) and
[Non-goals](#non-goals-what-stoagraph-does-not-protect-against).

## The orchestrator cannot approve itself

Human approval is only meaningful if the machine cannot forge it. Control-plane access is split into
**roles with separate secrets**:

| Role | May | Held by |
| --- | --- | --- |
| `approve` | Approve/deny an escalation (mints the signed release) | **a human, only** |
| `admin` | Author policy (recipes, routes, servers, providers) | a human |
| `dispatch` | Bind sessions, read the catalog, **poll** approval status | **the orchestrator process** |
| `operator` | The orchestrator's own API (models, event map, dispatch) | a human |

A single shared "admin token" handed to the orchestrator would let a hijacked orchestrator **approve its
own escalations** — the human gate would become decorative while every test still passed. The gate
rejects the `dispatch` credential on approval endpoints. What unblocks a held call is the **ed25519
signed release** the human's approval produced: a per-action signature, not a credential.

## Guarantees

- **Complete mediation, both channels.** Every governed tool call (**ACT**) and every context read
  (**READ**) crosses the gate. There is no forward path that bypasses it.
- **Forward-iff-cleared.** A call reaches the downstream only on `allow`. `deny`, `escalate`, and
  `fault` are never forwarded.
- **Reads are label + record, never denied.** Context is stamped untrusted at origin and the crossing is
  audited. A read cannot be used to smuggle authority.
- **Determinism.** No model runs in the enforcement path. The verdict is a pure function of the recipe
  and the proposed arguments.
- **Fail closed.** Unrouted tool, missing/malformed argument, unreachable downstream, un-lintable recipe,
  unknown session token, empty credential, **unconfigured auth role** → **denied**. There is no
  configuration in which uncertainty produces an allow.
- **Structural policy safety.** A recipe that could leak an untrusted value to an authoritative sink
  without a rule release is *rejected by the linter*, not a runtime surprise.
- **Bounded, computable leakage.** The residual choice channel (above) is not open-ended: `recipe.Leakage`
  emits a signed, static ceiling on it. `-require-bounded` refuses any recipe whose leak is not finite
  (a free-text field reaching an external sink), and `-crossing-budget N` caps forwarded crossings per
  session at the gate — so the per-session leak is a number, not a guess. **"Per session" means per
  *binding*, not per connection**: the budget lives on the bound token and is shared by every MCP
  transport opened under it, so an agent cannot reset `N` by reconnecting ([`docs/sessions.md`](docs/sessions.md)).
- **Tamper-evident audit.** Every decision — allow, deny, *and* escalate — is appended to a hash-chained
  log; anyone can recompute it with **`stag-verify`**, and checkpoints can be signed for offline
  verification. A non-forwarded decision **withholds the model's raw proposed value**: the log records
  *that* it was blocked and under which policy, never the attacker's bytes. Reads are recorded to a
  separate audit log.
- **One-time human approval.** An escalation is released only by a signed token bound to that exact
  action, consumed on use (a replay re-escalates).
- **Role separation.** The orchestrator cannot approve, and cannot author policy.
- **Credential isolation.** When the gate authenticates to a downstream server, the gate holds the
  credential — the agent never sees it, and every use is gated and audited.
- **Closed by default.** On first start the gate generates four distinct control-plane tokens (`0600`).
  A fresh deployment is authenticated with zero setup.

## Non-goals (what StoaGraph does **not** protect against)

Being explicit here is the point.

- **A permissive recipe.** StoaGraph enforces *your* policy faithfully; it does not invent policy. A
  recipe that allows a dangerous action will allow it. **Review recipes like firewall rules.**
- **A compromised host or config store.** Anyone who can write the config store (recipes, routes) or the
  host running the gate can change policy. Protect them as trusted infrastructure.
- **A compromised downstream tool server.** The gate controls *which calls* reach a downstream and *with
  what arguments*; it does not sandbox what that server does with a cleared call.
- **Audit tampering (prevention).** The log is tamper-**evident** (detectable), not tamper-**proof**.
  Ship checkpoints off-box.
- **Which human approved.** v1 proves that *someone holding the `approve` token* approved — **not who**.
  The signed release is per-action and unforgeable, but the token is a shared secret, not an identity.
  Real approver identity (OIDC) is a v2 item. **Do not present v1 approvals as attributable to a person.**
- **Model correctness or output quality.** StoaGraph governs *actions*, not reasoning or prose.
- **Taint propagation through the model.** See the trust invariant above. This is deliberate.
- **Eliminating the choice channel, or timing.** The gate *bounds and reports* the residual leak (see
  "Integrity, and a bounded residual"); it does not reduce it to zero. **Timing** — how long a decision
  takes, in what order calls arrive — is a separate side channel StoaGraph does not bound. And a *denied*
  leaf's reason string (`Fault`) can name an agent-chosen tool or argument: useful forensics on a private
  log, but an agent-controlled substring if you export that log to an untrusted reader.
- **Secrets at rest.** The config store is unencrypted. Prefer env-var references over stored secrets.

## Deployment requirements (operator responsibilities)

- **Protect `data/control.tokens` and `data/approval.key`.** They are the control plane and the signing
  key. Mode `0600`, never in git, never in an image. Use the `STAG_*_TOKEN` env vars for containers.
- **Never give the orchestrator the `approve` token.** It needs only `dispatch`. Handing it `approve`
  silently destroys human-in-the-loop.
- **Never run `-dev-no-auth` outside a laptop.** It disables the control plane entirely and says so,
  loudly, on every start.
- **Protect the config store and the audit log.** Write access to the config store *is* policy change.
  Ship signed audit checkpoints off-box.
- **Review recipes as policy.** Changes to recipes and routes are security changes.
- **For a bounded leak, opt in.** Run the gate with `-require-bounded` (refuse any recipe with an
  uncomputable leak) and `-crossing-budget N` (cap forwarded crossings per session). Without them the
  gate still enforces the recipe faithfully; with them the per-session leak is a bounded, signed number.
- **Keep the signed audit log private, or treat its `Fault` strings as agent-controlled.** Deny/escalate
  values are withheld, but a denied leaf's reason can carry an agent-chosen substring (see Non-goals).
- **Rotate a leaked key, do not just delete the repo.** A pushed secret is a leaked secret.
