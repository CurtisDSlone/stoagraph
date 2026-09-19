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

## Origin intent: where branching + context alone falls short

StoaGraph already has two tools for making a decision depend on something: a `branch` step
choosing among cases via a `set_membership`-style rule over a proposed value, and a `read` step
pulling in provider-sourced context to feed that decision. Together they cover a lot of ground —
but they share one requirement: **somebody has to write the predicate.** `branch` can only choose
among cases whose *conditions* are already expressed as rules over already-known values. `read`
enriches what the recipe can see; it does not change what the recipe can *decide with*. Feeding a
branch richer context doesn't help if the branch still needs a hand-authored rule to act on it —
it just means the predicate has to work harder.

That's fine, and often better, when the deciding condition really is a predicate:
`amount > $10,000` is exact, cheap to write, and should stay a `branch`. It breaks down when the
condition itself requires *interpretation* rather than comparison — a messy incident report, an
ambiguous support message, "which of these leads is worth investigating next." Converting that
into `branch` rules means enumerating every combination of `region`, `payment_method`,
`error_rate`, `deadline_sensitive`, ... by hand — at which point you are hand-building a semantic
reasoning system one `set_membership` rule at a time, and the rule set grows combinatorially with
every new distinction someone notices matters.

**This is the exact gap this feature is built to close**: keep `branch`'s topology (a fixed,
statically-verified set of legal next steps) but let *which* legal case looks right be a learned
weighting over that same fixed set, instead of a hand-authored predicate. The recipe still decides
what's *possible* — the case list doesn't change, no new step gets invented — the model just gets
to bring judgment to which of those already-legal cases fits messy, real input, instead of an
author trying to anticipate every combination in advance. That's the whole thesis below in one
sentence: branching decides what CAN happen and does it well; it was never meant to decide what
SHOULD happen when the right answer depends on interpreting something ambiguous, and that's
exactly the seam this feature sits in.

## The invariants

> **The model may determine probability; the recipe determines possibility.**
> **The model may assign probability to transitions; it may not create transitions.**

StoaGraph's existing trust boundary: the model proposes, the kernel decides what is executable.
The recipe graph — what steps can follow which — is statically verified at parse/compose time,
and that's what makes `SemanticHash` meaningful as a signed-policy identity. Everything below is
designed to sit on the **model/context side** of that boundary, not to change it.

The sentence to hold every design decision against: **"We have a StoaGraph state machine whose
transition policy happens to be probabilistic" — not "we have a probabilistic agent whose outputs
happen to be constrained by StoaGraph."** In the first framing the recipe is the machine and the
model is a policy *over* it; in the second the model is primary and StoaGraph is demoted to a
guardrail. Every implementation choice below should be checked against which framing it moves
toward.

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

Combined state `X = (S, C)` — policy step × context — is finite and enumerable ahead of a run
**only if the context graph itself is closed**: `C' ∈ Next_C(C)` where `Next_C` is
recipe-defined, never model-defined. Given that, `Next(X)` is statically enumerable; the model
supplies `P(X' | X, E)` — a probability over already-enumerated next-states given evidence `E` —
but never defines `Next(X)` itself. `Reachable(X0)` is then a static, precomputable property of
the compiled recipe plus the declared context domains, not an empirical claim about model
behavior. This closure requirement is the mathematical core of the whole feature.

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

**Probability must never become an authorization primitive.** `confidence = .97` must never mean
"therefore authorized" — probability answers "what does the model currently believe," never "what
may the system do." Confidence can shape which transition gets *proposed*, or bias toward an
explicit `ESCALATE`/`REVIEW` transition, but authorization still runs through the deterministic
recipe topology and gate unconditionally on the confidence value:

```
model -> probability distribution -> probabilistic controller -> candidate
      -> recipe topology -> legal transition? -> no: stop
                                               -> yes: deterministic policy -> action
```

### Reuses the existing `propose` architecture — not a new trust mechanism

This doesn't need an entirely new mechanism. It extends the existing
`propose -> constrained slot -> gate -> invoke` shape from VALUES to TRANSITION PREFERENCE:

```
read -> propose context claim -> finite-domain / ReleaseRule -> probabilistic transition
     -> recipe transition -> gate -> invoke
```

Open implementation question worth resolving early: is a context claim best implemented as
literally another kind of `propose` step, rather than a new step kind? That would keep the
grammar surface smaller and inherit the existing `propose`/rule-clearance discipline for free.

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

### Three different questions, kept sharply separate

- **Provenance** — "where did this value originate?" — answered today by `TrustClass`
  (`Untrusted` / `Caller` / `Authoritative`).
- **Semantics** — "what does this evidence mean?" — answered by model inference. New; nothing
  answers this today.
- **Authority** — "what is this value allowed to influence?" — answered by the gate /
  `ReleaseRule`.

`TrustClass`/`SinkSensitivity` are real and live (`GateSink` already denies an
authoritative-sensitivity crossing unless the value's `TrustClass` is `Authoritative` or a human
explicitly released it) — but they classify **provenance**, not **semantics**. A CRM record can be
`TrustClass = Authoritative` (it genuinely came from the CRM) while the model's *classification*
of that record ("customer is suspicious") is not itself authoritative just because its source was.
`TrustClass` classifies the pipe, not the payload's meaning, so it does not close this gap on its
own — the design must not try to stretch it to cover semantics.

### Context should be a first-class CLAIM, not a promoted fact

Instead of `context.customer_status = verified` (implying a fact), model the output of
interpretation as a claim with its own epistemic status:

```
model_claim:
    slot: customer_status
    value: verified
    confidence: 0.83
    evidence: [...]
```

This distinguishes a SOURCE FACT (`customer_status = verified`, `TrustClass = Authoritative`)
from a MODEL CLAIM (same value, `derived_from = [source facts]`, `confidence = .83`) — a claim
never gets silently promoted to authoritative merely because the source facts it was derived from
were. This is the missing type between `TrustClass` and transition policy, and it's the concrete
mechanism the open question below resolves into: a `model_claim` is the thing that should need to
clear a `ReleaseRule` before it's allowed to influence weighting — not the raw value, and not an
inherited trust level.

A manipulated claim can shift the *probability distribution* over which legal transition looks
likely — the thesis's claim (2) below, not yet closed by any of this. The finite domain on a
`context:` slot is not just a tractability convenience — it's the safety mechanism against this,
the same role `set_membership` already plays for a `propose`d value. And this stays deliberately
inside claim (2)'s scope, not claim (1)'s: the topology invariant holds regardless (the model
can't reach a transition the recipe didn't declare) — what's at stake here is *which legal*
transition looks attractive, never an escape from the legal set.

**Resolved direction, still to be implemented:** a `context:`/`model_claim` fill must clear a
rule before it's allowed to influence transition weighting — the same discipline a
`propose → invoke` argument already goes through before reaching a tool — reusing
`ReleaseRule`/`set_membership` machinery rather than inheriting safety from the source value's
`TrustClass`. This should land before any implementation work starts, not be discovered
afterward.

## `SemanticHash` binds the machine, not the model's output

Sharpened from an open question into a design position: the hash should be
`Hash(topology, context domains, constraints, capabilities)` — never
`Hash(topology, model output)`. Two different models producing opposite distributions
(`VERIFY .8 / ESCALATE .2` vs. `VERIFY .2 / ESCALATE .8`) must still verify against the *same*
hash — it means "this is the machine I authorized," not "this is the probability distribution the
model will produce." Distribution is runtime behavior; the hash is a policy-artifact identity and
must stay blind to it, the same way it's already blind to which values a session happens to
propose.

## Claim B stays outside the security guarantee, on purpose

The thesis above already separates two claims of different strength. Claim A (topology can't be
escaped) is the actual security guarantee, and it's fully architectural. Claim B (the model
chooses *well* among the legal options) is deliberately left OUTSIDE that guarantee — this is a
scope boundary, not a weakness:

> "The model may be manipulated into preferring a legal but undesirable transition. However,
> manipulation cannot cause an undeclared capability."

Claim B is then improvable separately — better models, better evidence, multiple inference
passes, confidence thresholds, human review, disagreement detection, adversarial testing — without
ever needing to become part of the capability guarantee itself. This is also why the "no RL yet"
choice above is a measurement design, not just caution: the controller can be evaluated as a
**fixed policy over a changing context distribution** (run model `M` against recipe `R` over N
sampled contexts, measure calibration, transition entropy, escalation frequency, adversarial
susceptibility; swap in `M2` against the same `R`, repeat — the graph hasn't changed, so the
comparison is clean). Online RL breaks that comparison, because the measured thing changes in
response to being measured.

## `stag analyze` — likely the actual product story

Deserves more weight than a line item. Two reports, kept visibly distinct, answering two
different questions:

- **Static analysis** (`stag analyze incident-response.yaml`, compiled from the recipe alone —
  no model involved): states/transitions/context-dimension/combined-state counts, read-only vs.
  mutating vs. privileged tool counts, explicit reachability of named capabilities ("production
  restart: YES", "credential access: NO"), how many states reach human review vs. bypass it, max
  tool calls / max mutations / unbounded paths. Answers **"what can the agent ever do?"** — a
  natural extension of the existing bounded-leakage check (`requireBounded`), not a new
  philosophy.
- **Probabilistic telemetry** (runtime, per-context): the model's actual transition distribution
  given a specific context. Answers **"what does this model tend to do given this context?"**

Never conflate the two in any report/UI. The guaranteed-capability bound and the observed
behavioral tendency are different kinds of claim, and this separation — not the controller
mechanism itself — may be the most compelling reason to build this at all.

## Open design questions

Not yet decided — see the scratch note for the full list:

- Where a context slot's finite domain is declared (a new `context:` block vs. reuse of existing
  slot/rule machinery with a "finite domain" constraint kind).
- Whether the transition-probability interface is a new rule `kind` (returns a distribution
  instead of a boolean) or a distinct step-level construct.
- Whether a `model_claim` is best implemented as another kind of `propose` step or a new step
  kind.
- Whether `Reachable(X0)` over the combined (policy state × context) space extends the existing
  leakage-analysis code in `stag/recipe`, or wants a separate pass.

## Why this direction, not something else

The strong claim this unlocks: different models/policies all operate over the same compiled
graph `G = StoaGraph(recipe)`. The provable statement is never "model X is safe" — it's "any
policy that can only emit transitions accepted by `G` cannot reach capability `C`," independent
of which model produced the distribution. Swapping the model doesn't invalidate the capability
analysis. StoaGraph doesn't need to make AI deterministic to make an agent's capabilities
analyzable — only the transition topology needs to be deterministic and closed.
