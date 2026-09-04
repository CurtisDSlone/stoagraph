# StoaGraph doctrine

*What StoaGraph does, in plain terms, and the beliefs it is built on.*

## The one line

> **StoaGraph does not stop prompt injection. It stops prompt injection from turning into action.**

Everything below is a consequence of taking that sentence seriously.

## What it is

StoaGraph is **verifiable control for AI agents**. An agent *proposes* a tool call; a deterministic
gate *disposes* — allow, deny, or escalate — with **no model in the decision path**. A hijacked,
prompt-injected, or simply wrong model can propose anything. It cannot make the gate release a value
your policy rejects.

> The model has a flashlight. The gate has the map.

Two processes, and the split *is* the product:

- **`stag`** — the **gate**. Deterministic policy, audit, approvals. Holds no model and no API keys.
- **`harness`** — the **orchestrator**. The model connections and the agent loop. Holds the keys.

The dependency runs one way — `harness → stag`, never back — and the build fails if that is ever
violated. So a compromised orchestrator can waste money and propose freely; it cannot reach the gate's
decisions or your policy.

## The problem it solves

Agents are being handed real tools — deploy, refund, delete, reroute, email. The moment an agent can
*act*, every document it reads becomes an attack surface: a log line, a ticket, a web page, a "runbook"
can all carry an instruction, and the model cannot reliably tell an instruction it was given from one it
merely read. You cannot train this away, and you cannot allow-list your way out of it, because the
danger is not *which* tool the agent uses — it is *what argument* it passes.

StoaGraph's move is to stop trying to make the model trustworthy and instead make its **actions**
provable: a human writes a policy of exactly which values each tool may receive, and a deterministic
gate enforces it on every call, forever, regardless of what the model was talked into.

## The tenets

1. **Propose / dispose.** The model proposes; the gate disposes. The two are separate processes with a
   one-way dependency. The thing that decides is not the thing that can be fooled.

   Where a policy authorizes a *sequence*, the model does not propose even that: a recipe names the
   calls and their order, and the model may only trigger it. It picks *which* maintenance to run, not
   what maintenance means. See tenet 13.

2. **No model in the enforcement path.** A verdict is a pure function of the recipe (your policy) and the
   proposed arguments. Same inputs, same verdict, every time — auditable and reproducible.

3. **Complete mediation, both channels.** Every governed tool call (an **act**) and every context read (a
   **read**) crosses the gate. There is no forward path around it.

4. **Fail closed.** Unrouted tool, missing or malformed argument, unreachable downstream, un-lintable
   recipe, unknown token, empty credential — all **deny**. There is no configuration in which uncertainty
   produces an allow. A fresh gate permits *nothing* until you author a policy.

5. **Presume every proposal untrusted; re-derive trust at the sink.** StoaGraph does not track "taint"
   through the model — that cannot be done, and pretending otherwise is how systems get breached.
   Untrusted context is *positioned* as data going in (it can never reach the instruction slot), and every
   value coming out is presumed untrusted until a policy rule clears it at the action boundary. See
   [context-binding.md](context-binding.md).

6. **The recipe is the policy.** A human writes, per tool, the closed set of values each argument may
   take — `set_membership`, `numeric_range`, or a `signed_equality` token. Only a rule firing promotes a
   value from untrusted to released, and only the exact allowed values pass. "Close enough" does not.

7. **Coverage.** Every argument that can reach a tool is either gated by a rule or explicitly declared
   free-text. An argument that is neither is a hole — and the gate denies the call rather than forward it.

8. **Forward-iff-cleared.** A call reaches the downstream tool only on `allow`. `deny`, `escalate`, and
   `fault` never touch it.

9. **Human approval that cannot be forged.** An escalation is released only by an ed25519 signature bound
   to that exact action, minted by a human with the `approve` role and consumed on use. The orchestrator
   holds a different credential and **cannot approve itself** — otherwise the human gate would be
   decorative while every test still passed.

10. **Tamper-evident audit.** Every decision is appended to a hash-chained log; anyone can recompute it
    (`stag-verify`) and checkpoints can be signed for offline proof. The audit is the product, not a
    byproduct: "here is what was proposed, what was decided, and why" — verifiable, not asserted.

11. **A bounded, computable leak.** Even a closed-set gate leaves the model a *choice* among the allowed
    values — a residual channel. StoaGraph computes a signed number that ceilings it (`recipe.Leakage`),
    and refuses — with `-require-bounded` — to serve a policy whose leak is not bounded.

    The number is *static*: it is derived from the policy before anything runs, with no model in the
    computation, so it is a property of what you authored rather than an observation of what happened.
    It composes across a session (`SessionBound`), and it holds only under stated preconditions —
    canonical-only release, an order-only observer, a crossing cap — which [`leakage.go`](../stoa-kernel/stag/recipe/leakage.go)
    names rather than assumes. It is a per-session *rate*, not a lifetime guarantee.

    The research literature is converging on the same problem from the other side: runtime mediators
    that accumulate a leakage budget over a trajectory, several of which put a model back in the
    measurement path to judge semantic content. That buys a finer confidentiality tradeoff than a
    closed-set bound can express. It also means the ceiling is only as sound as the judgment producing
    it — which is the trade StoaGraph declines to make. We know of no other system that publishes a
    static, model-free leak bound computed from policy alone; we do not claim to be the only ones
    measuring the channel.

12. **Open by construction.** Apache-2.0, the whole product, no held-back edition. A control that asks you
    to "don't trust — verify" has to be verifiable, all the way down.

13. **Order can be policy.** Some sequences are only safe in one order: cordon before drain, write before
    restart, verify before you report. That is not a preference an operator holds, it is a property of
    the action — and out of order it is an outage, not a mistake. A recipe can therefore authorize an
    ordered sequence of calls, and the model chooses none of it.

    Authorizing a call is never authority to make it. Every call in an authorized sequence is put back
    through the gate against **that tool's own route and recipe**, so a permissive policy cannot launder
    an action by naming it. Two grants, both required.

    The kernel performs no I/O to do this. It *authorizes*; a separate executor carries the calls. An
    authorization stays a pure function of the recipe and the arguments, which is what keeps a decision
    replayable by an auditor who was not there.

14. **Do not report success for a thing that has not happened.** A drain that returned is not a node
    with no pods on it; a ConfigMap write is not a running pod holding the new value. A step that looks
    and records is a *witness*; a step that will not let the sequence continue until the world agrees is
    a *gate*. Policies can wait — bounded, every attempt judged — and a sequence that cannot reach the
    state it required **halts** rather than claiming it arrived.

15. **Reachable only when it should be.** A tool a sequence needs is not a tool the agent should hold.
    A route may exist without being advertised, and such a tool is unreachable without a one-shot grant
    minted for exactly that call and spent on use. Hiding is a convenience — an injected document cannot
    name a capability it has no way to know exists — but the grant is the enforcement, and a call that
    guesses the name is denied *and recorded*.

## What StoaGraph does *not* do

- It does **not** stop the model from being fooled. Prompt injection still happens; the model may still
  propose the wrong thing. StoaGraph makes that proposal inconsequential.
- It does **not** taint-track values through the model. That is deliberate — the guarantee would be a
  fiction. Trust is re-derived at the sink instead.
- It is **not** a model firewall, a jailbreak detector, or a content classifier. It never inspects
  meaning; it checks values against a policy.
- It does **not** defend a host whose disk or memory an attacker already controls. The recipe store, the
  keys, and the gate are trusted infrastructure. (See [SECURITY.md](../SECURITY.md) for the full
  non-goals.)

## The shape of the guarantee

Read a poisoned page, get fooled, propose the forbidden action — and the gate denies the argument on a
tool you were fully allowed to call, records it on a chain you can verify, and never lets it reach the
world. The injection changed what was *proposed*. It did not change what was *permitted*.

That is the doctrine: **stop prompt injection from turning into action.**
