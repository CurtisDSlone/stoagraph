# StoaGraph — Probabilistic Controller (feature branch)

> **This README is scoped to this branch only.** It replaces the project README for the
> duration of `feat/probabilistic-controller` so reviewers see the feature's design in one
> place. On merge to `main`, `main`'s own README is kept — this file does not get merged over
> it. For the general-purpose StoaGraph README, see `main`.

## What this branch is for

Design and prototyping space for a learned/probabilistic transition layer that sits **above**
StoaGraph's existing recipe graph, without weakening the recipe/kernel trust boundary. Status:
**design stage** — the ideas below are not yet implemented. This branch exists so that work can
happen in the open (pushed to origin) without touching `main`.

The seed and full design writeup live in
[`scratch/idea-probabilistic-transition-static-topology.md`](scratch/idea-probabilistic-transition-static-topology.md).
This README is a condensed, reviewable version of that note.

## The invariant

> **The model may determine probability; the recipe determines possibility.**

StoaGraph's existing trust boundary: the model proposes, the kernel decides what is executable.
The recipe graph — what steps can follow which — is statically verified at parse/compose time,
and that's what makes `SemanticHash` meaningful as a signed-policy identity. Everything below is
designed to sit on the **model/context side** of that boundary, not to change it.

Confirmed still true on pushed `main` (verified 2026-09-18, not just asserted from the note):

- **Bounded-leakage gate is real and fail-closed.** `stag/recipe/leakage.go` computes a
  choice-channel bit bound per recipe and flags a route `Unbounded` when a free-text passthrough
  argument voids it. `router.BuildStrict`'s `requireBounded` mode does not merely warn — an
  unbounded route is added to `res.Errors` and **no router entry is created at all**, so the gate
  denies the tool outright. Wired into real entrypoints (`stag-proxy -require-bounded`, the
  sessiond `/sessions` handler), not dead code.
- **The recipe-ID candidate-set dispatcher is real and fail-closed.** The model is handed a fixed
  enumerated `[]Recipe` list and is explicitly instructed it "never invents a recipe id."
  `dispatch.Gate` checks the picked ID against `validIDs` and a confidence floor; a miss
  (`GateFallback`) binds **no session at all** — not a fallback recipe, not a default, nothing.
  A valid-but-wrong pick still can't exceed the selected recipe's own policy, because stag's gate
  re-enforces every individual call regardless of how the recipe was chosen.

Both are the existing precedent this feature is designed to extend, not invent.

## Thesis

**The strongest case for this feature is when the input is semantically rich enough that the
right branch condition isn't knowable ahead of time, but the safe set of actions is still
knowable ahead of time.**

> The semantic compression is performed by the model. The security compression is performed by
> the recipe.

That is the actual gap between a deterministic branch and a probabilistic controller — not
"smarter" vs. "dumber," but where the authoring cost lives. It comes with an explicit decision
rule: **if you can author a good deterministic branch, use the deterministic branch.** There is
no reason to replace `if amount > $10,000: require_approval` with an LLM — that predicate is
already cheap and exact. The controller only earns its keep once converting messy reality into
predicates would mean rebuilding a semantic reasoning system out of hand-written rules — e.g. an
incident report, a support message, or "which lead is worth investigating next" — while the
*actions* available in response stay small, stable, and enumerable (`inspect_payment_errors`,
`escalate_to_human`, `REFUND`, `RESTART_SERVICE`, ...). Full worked examples (incident response,
support, research/exploration, cloud ops) are in the scratch note.

This produces two claims, and they are not the same strength — keep them separate in any pitch
of this feature:

1. **An attacker cannot escape the declared action set.** Architecturally sound, and already
   demonstrated by the existing precedent above (`requireBounded`, the candidate-set dispatcher).
   Confusing the model cannot grant it a capability the recipe never declared.
2. **An attacker cannot make the model choose badly among the actions it's allowed.** NOT yet
   demonstrated. A `context:` value used to weight transitions is typically derived from untrusted
   `read` content (see below) — an attacker who controls that content can plausibly steer the
   *weighting* toward the wrong-but-legal action, or away from escalation, without ever leaving
   the topology. This is exactly why the classification/context-gating question below has to be
   resolved before this ships for anything where the wrong legal action has real consequences
   (incident response, cloud ops) — it matters far less for pure exploration, where a bad weight
   mostly costs a wasted turn.

## The two-graph split

- **Graph A — the policy graph.** The existing StoaGraph recipe. Describes what CAN happen.
  Stays entirely deterministic and statically analyzable, exactly as it is today — unchanged by
  this feature.
- **Graph B — the context graph.** What the model can believe/observe next, over a
  **recipe-declared, finite domain** — e.g. `customer_status: unknown|verified|blocked`. The
  model assigns a probability over the next value; it does not invent a new context slot or
  value. This is the same shape `propose` already has: the model fills in a declared slot, it
  doesn't invent the slot.

Combined state `X = (S, C)` — policy step × context — is finite and enumerable ahead of a run.
`Reachable(X0)` becomes a static, precomputable property of the compiled recipe plus the declared
context domains, not an empirical claim about model behavior.

## The controller shape

The model does not generate actions. It generates a probability distribution over the **legal**
transitions the recipe already declares from the current step:

```
state REVIEW, legal = {APPROVE, REQUEST_MORE_CONTEXT, ESCALATE}
model:  APPROVE 0.18   REQUEST_MORE_CONTEXT 0.67   ESCALATE 0.15
```

`LEGAL(REVIEW, DELETE_DATABASE)` is not in the set — full stop, not a probability of zero. This
is `π_θ(a | s, c)` where `π` is learned/probabilistic but `a ∈ A(s)`, and `A(s)` is statically
declared by the recipe. Ordinary LLM inference can produce this distribution from day one; RL is
a drop-in replacement for the same interface later, with no change to the controller. Multiple
models or policies can sit behind the same interface unmodified, because StoaGraph only ever sees
`(state, proposed transition)` — never an arbitrary model-generated call.

## What this does NOT change

- No new tool authority for the model or the controller. Every actual invocation still
  re-crosses the gate exactly as it does today — the probabilistic layer is just another
  proposer, sitting entirely on the existing "untrusted agent side" of the boundary.
- No runtime recipe mutation. A recipe change is a new policy artifact with a new hash, through
  the normal authoring/audit lifecycle — never a live edit during execution.
- No free-form context invention. Context slots have recipe-declared, finite domains, the same
  way rules/slots do today.

## The context-gating gap (unresolved, load-bearing)

The `context:` slots above are not an independent new layer. StoaGraph already has a `context`
concept — untrusted, provider-sourced content read via a `read` step, stamped untrusted at origin
and audited precisely because it is not trusted (`docs/context-binding.md`). In any real recipe, a
`context:` slot's value is derived by the model FROM that untrusted content — so it is a
model-produced summarization/classification of untrusted input, not a clean new fact.

That makes a `context:` assignment structurally an attack surface, the same shape as a `propose`
step: the topology invariant still holds (the model can't reach a transition the recipe didn't
declare), but a manipulated assignment can shift the *probability distribution* over which legal
transition looks likely — the thesis's claim (2) above, not yet closed. The finite domain on a
`context:` slot is therefore not just a tractability convenience — it's the safety mechanism
against this, the same role `set_membership` already plays for a `propose`d value.

**Undecided:** must a `context:` slot's fill clear a rule before it's allowed to influence
transition weighting — the same gate discipline a `propose → invoke` argument already goes
through before reaching a tool — or can it be assigned straight from untrusted `read` content?
Given the above, it almost certainly needs the former. This should be resolved before any
implementation work starts, not discovered afterward.

## Open design questions

Not yet decided — see the scratch note for the full list:

- Where a context slot's finite domain is declared (a new `context:` block vs. reuse of existing
  slot/rule machinery with a "finite domain" constraint kind).
- Whether the transition-probability interface is a new rule `kind` (returns a distribution
  instead of a boolean) or a distinct step-level construct.
- Whether `SemanticHash` needs to bind declared context *domains* (not the probabilities/weights
  themselves) to keep "signed = what can happen" true.
- Whether `Reachable(X0)` over the combined (policy state × context) space extends the existing
  leakage-analysis code in `stag/recipe`, or wants a separate pass.
- A possible `stag analyze recipe.yaml` CLI report (state/transition counts, reachable tools,
  write-capable tools, human-approval paths, max irreversible actions, unbounded paths) — a
  natural extension of the existing bounded-leakage check, not a new philosophy.

## Why this direction, not something else

The strong claim this unlocks: different models/policies all operate over the same compiled
graph `G = StoaGraph(recipe)`. The provable statement is never "model X is safe" — it's "any
policy that can only emit transitions accepted by `G` cannot reach capability `C`," independent
of which model produced the distribution. Swapping the model doesn't invalidate the capability
analysis. StoaGraph doesn't need to make AI deterministic to make an agent's capabilities
analyzable — only the transition topology needs to be deterministic and closed.
