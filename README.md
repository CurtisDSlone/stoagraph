# StoaGraph: Probabilistic Controller (feature branch)

> This README is scoped to this branch only. It replaces the project README for the duration of
> `feat/probabilistic-controller` so reviewers see the feature's design in one place. On merge to
> `main`, `main`'s own README is kept. This file does not get merged over it. For the
> general-purpose StoaGraph README, see `main`.

## What this branch is for

Design space for a model-interpreted transition layer above StoaGraph's recipe graph. It does
not weaken the recipe/kernel trust boundary. Status: design complete, nothing implemented. This
branch exists so the work can happen in the open without touching `main`.

The full design writeup (`scratch/idea-probabilistic-transition-static-topology.md`) and the six
external reviews it was refined against (`notes/PROBABILISTIC-CONTROLLER-REVIEW-*.md`) are local
working files and are not on this branch. This README is the complete, reviewable version; nothing
below depends on either.

Target: event-driven, autonomous, unattended operation. First shipping scope: investigative and
reversible recipe arms only, where a wrong legal choice costs a wasted turn. Anything that reaches
an irreversible action or the grant of a sequenced tool is gated behind the implementation plan at
the end of this document.

## Origin intent: where branching and context alone fall short

StoaGraph has two tools today for making a decision depend on something: `branch` chooses among
cases via a rule over a proposed value, and `read` pulls in provider-sourced context to feed that
decision. Both require an author to write the predicate. `branch` can only choose among cases
whose conditions are already expressed as rules over known values. `read` enriches what the
recipe can see. It does not change what the recipe can decide with. Feeding a branch richer
context doesn't help if the branch still needs a hand-authored rule to act on it. The predicate
just has to work harder.

That's fine when the deciding condition really is a predicate. `amount > $10,000` is exact, cheap
to write, and should stay a `branch`. It breaks down when the condition needs interpretation, not
comparison: a messy incident report, an ambiguous support message, "which lead is worth
investigating next." Turning that into `branch` rules means enumerating every combination of
`region`, `payment_method`, `error_rate`, `deadline_sensitive` by hand. At that point you're
hand-building a semantic reasoning system one rule at a time, and the rule set grows
combinatorially with every new distinction someone notices matters.

This is the gap this feature closes. Keep `branch`'s topology, a fixed, statically-verified set
of legal next steps, but let which legal case looks right be the model's interpretation over that
same fixed set, not a hand-authored predicate. The recipe still decides what's possible. The case
list doesn't change, no new step gets invented. The model brings judgment to which already-legal
case fits messy input, instead of an author trying to anticipate every combination in advance.
Branching decides what CAN happen, and does it well. It was never meant to decide what SHOULD
happen when the right answer depends on interpreting something ambiguous. That's the seam this
feature sits in.

## The invariants

> The model may determine probability. The recipe determines possibility.
> The model may assign probability to transitions. It may not create transitions.

StoaGraph's existing trust boundary: the model proposes, the kernel decides what is executable.
The recipe graph is statically verified at parse/compose time, which is what makes
`SemanticHash` meaningful as a signed-policy identity. Everything below sits on the
model/context side of that boundary. It does not change it. In this design the probability never
leaves the harness: what crosses the wire is one legal case and a confidence bucket, as two
ordinary gated slots.

Hold every design decision against this sentence: "We have a StoaGraph state machine whose
transition policy happens to be probabilistic," not "we have a probabilistic agent whose outputs
happen to be constrained by StoaGraph." In the first framing the recipe is the machine and the
model is a policy over it. In the second the model is primary and StoaGraph is a guardrail. Check
every implementation choice against which framing it moves toward.

Confirmed still true on pushed `main` (verified 2026-09-18, not just asserted):

- **Bounded-leakage gate is real and fail-closed.** `stag/recipe/leakage.go` computes a
  choice-channel bit bound per recipe and flags a route `Unbounded` when a free-text passthrough
  argument voids it. `router.BuildStrict`'s `requireBounded` mode does not just warn. An
  unbounded route is added to `res.Errors` and no router entry is created. The gate denies the
  tool outright. Wired into real entrypoints (`stag-proxy -require-bounded`, the sessiond
  `/sessions` handler), not dead code.
- **The recipe-ID candidate-set dispatcher is real and fail-closed.** The model is handed a
  fixed enumerated `[]Recipe` list and is told it never invents a recipe id. `dispatch.Gate`
  checks the picked ID against `validIDs` and a categorical confidence (`high | medium | low`).
  A miss or a `low` (`GateFallback`) binds no session at all: not a fallback recipe, not a
  default. A valid-but-wrong pick still can't exceed the selected recipe's own policy, because
  stag's gate re-enforces every individual call regardless of how the recipe was chosen.
- **Reachability is route data, and the executor re-crosses every step.** `sequenced` is a
  field on the route row (`stag/store`'s `Route`), not recipe YAML, and no recipe hash is stored
  on the route row. `executeAuthorized` (`stag/proxy/mcpgate`) mints a one-shot grant per step
  and re-crosses `Gate.Decide` against the sub-tool's own route recipe with only that call's own
  arguments. `GateSink` returns `Allow` unconditionally for a `benign` sink, so a sub-recipe with
  only a benign sink cannot refuse anything. All in `docs/dispatch-internals.md`.
- **Backend reality.** Ollama's API offers JSON-schema-constrained output and no logprobs or
  logit bias. The harness's `Proposer` interface has no logprob concept. A design that needs a
  token distribution does not run on the local backends this project targets.

All four are existing facts this feature builds on, not invents.

## The formal model

The core object is not a trained agent. It is a preference `π(a | s, c, e)` over legal
transitions, where the model supplies the preference, subject to:

```
support(π) ⊆ A(s)
```

`A(s)` comes entirely from the compiled recipe. The model cannot enlarge it. `DELETE_DATABASE`
isn't "probability zero," it isn't an element of the candidate set at all. `π` is a conceptual
object: it lives entirely in the harness and is collapsed, before anything crosses the wire, to
one element of `A(s)` plus a confidence bucket.

Three layers, each a different kind of object, worth keeping strictly separate in any writeup:

- **Layer 1, capability topology.** `G = (S, A, T)`, compiled from the recipe and the routes
  bound into a session. The security theorem: `a_t ∉ A(s_t) ⇒ execution rejected`.
  Model-independent. This is Claim A below.
- **Layer 2, semantic state.** `C = C_1 × C_2 × ... × C_n`, where every `C_i` is recipe-declared
  and finite. The model can select `customer_status ∈ {unknown, verified, blocked}` but cannot
  introduce `customer_status = "probably-fraudulent-but-not-quite"` or invent a new dimension.
  This is where the semantic-complexity problem lives (see "Context explosion" below).
- **Layer 3, probabilistic behavior.** `π_θ(a | s, c, e)`. Runtime behavior, not policy identity.
  This is why the `SemanticHash` position below is clean: hash the machine and its declared
  semantic vocabulary, never the model's runtime preferences.

Read plainly, this document is a statically closed policy machine with model-interpreted semantic
control, not a probabilistic agent wrapped in a guardrail, and not an RL or shielding proposal.
Ordinary LLM inference is sufficient. The genuinely interesting problem isn't "probabilities on
transitions," which is well-trodden ground (probabilistic finite-state control, constrained
structured prediction, probabilistic model checking, runtime enforcement and shielding all touch
it, and SayCan scores a fixed skill set by LLM likelihood). It's the separation this document
draws between semantic interpretation and policy topology, and in particular the fourth layer
below: how much a semantic distinction the model draws is allowed to matter. The narrower
prior-art question: has anyone studied a neural semantic interpreter whose output is constrained
to a statically closed semantic vocabulary, where the resulting policy operates over a separately
verified capability topology, with static analysis of the semantic claims' influence on
capabilities?

Restated with this vocabulary: the model performs semantic compression, the recipe performs
capability compression. The model takes messy evidence (an incident report, CRM text, a ticket,
a customer message) and compresses it into a small declared semantic space. The recipe then
compresses the possible consequences into a closed action topology. The research question is:
what is the maximum useful semantic compression achievable before the semantic representation
becomes an implicit second policy language? The three constraints under "Context explosion" are
the concrete shape of an answer.

### The four-layer hierarchy

```
Topology:              what CAN happen?
Semantic state:        what distinctions can the model represent?
Probabilistic policy:  what does the model prefer?
Claim influence:       how much does each semantic distinction matter?
```

Claim influence is two different things and this document keeps them apart:

- **Structural influence.** Which claims can reach which capabilities through the graph. A
  property of the triple (recipes, routes, event map). Static, model-free, belongs in the
  analyzer.
- **Empirical sensitivity.** How much varying a claim actually moves the model's preference,
  everything else fixed. A property of a specific model. Runtime telemetry, never a static
  claim. Reuse quantitative information flow and parametric model checking rather than new math.

A semantic space can be declared-finite and density-capped and still let one claim swing outcomes
disproportionately. Structural influence is what makes that visible ahead of a run; empirical
sensitivity is what measures it after one.

## Thesis

The strongest case for this feature: the input is semantically rich enough that the right branch
condition isn't knowable ahead of time, but the safe set of actions is still knowable ahead of
time.

> The semantic compression is performed by the model. The security compression is performed by
> the recipe.

That's the actual gap between a deterministic branch and a model-interpreted one. Not "smarter"
vs. "dumber," but where the authoring cost lives. Decision rule: if you can author a good
deterministic branch, use the deterministic branch. There's no reason to replace
`if amount > $10,000: require_approval` with an LLM; that predicate is already cheap and exact.
The controller earns its keep once converting messy reality into predicates means rebuilding a
semantic reasoning system out of hand-written rules, while the actions available in response stay
small, stable, and enumerable (`inspect_payment_errors`, `escalate_to_human`, `REFUND`,
`RESTART_SERVICE`).

Two claims come out of this. Keep them separate in any pitch of this feature:

1. **An attacker cannot escape the declared action set.** Architecturally sound. Already
   demonstrated by the precedent above (`requireBounded`, the candidate-set dispatcher, the
   per-step re-crossing). Confusing the model cannot grant it a capability the recipe never
   declared.
2. **An attacker cannot make the model choose badly among the actions it's allowed.** Not
   demonstrated, and not claimed. A claim used to choose a branch is typically derived from
   untrusted `read` content. An attacker who controls that content can plausibly steer the
   choice toward the wrong-but-legal case, or away from escalation, without leaving the topology.
   This is why the implementation plan gates anything reaching an irreversible action, and why
   the first shipping scope is arms where a wrong legal choice costs a turn.

## The two-graph split

- **Graph A, the policy graph.** The existing StoaGraph recipe plus the routes bound into the
  session. Describes what CAN happen. Stays entirely deterministic and statically analyzable,
  unchanged by this feature.
- **Graph B, the context graph.** What the model can believe or observe next, over a
  recipe-declared finite domain, e.g. `customer_status: unknown|verified|blocked`. The model
  picks a value. It does not invent a new context slot or value. Same shape `propose` already
  has: the model fills in a declared slot, it doesn't invent the slot.

Combined state `X = (S, C)`, policy step times context, is finite and enumerable ahead of a run
only if the context graph is closed: `C' ∈ Next_C(C)`, where `Next_C` is recipe-defined, never
model-defined. Given that, `Next(X)` is statically enumerable. The model supplies a preference
over already-enumerated next-states given evidence `E`, but never defines `Next(X)` itself.
`Reachable(X0)` is then a static, precomputable property of the compiled recipe, the bound routes,
and the declared context domains, not an empirical claim about model behavior. This closure
requirement is the mathematical core of the feature.

## The controller shape

The controller is a fixed inference policy over a statically enumerated FSM. It lives in the
harness, on the untrusted side of the wire, and there is no learning during execution:

```
untrusted evidence
       |
       v
   LLM inference                          HARNESS: holds the model, untrusted side
       |
       | one semantic claim per declared slot
       v
 bounded context C
       |
       v
 preference over LegalCases(S)            stays in the harness; never crosses
       |
       | collapse to: case ∈ LegalCases(S), confidence ∈ {high, medium, low}
=======|================================  the MCP wire: two ordinary gated slots on the trigger call
       v
 propose -> each slot clears its rule     GATE (stag): model-free
       |
       v
 branch on (case, confidence)             low -> a declared abort-and-alert case
       |
       v
 Decision.Authorized: a fixed plan        model influence ends here
       |
       v
 executeAuthorized: per step, one-shot grant + re-cross the sub-tool's own recipe
       |
       v
      action
```

The model does not generate actions. It chooses among the legal cases the recipe already declares
from the current step:

```
state REVIEW, legal = {APPROVE, REQUEST_MORE_CONTEXT, ESCALATE}
harness (internal):  APPROVE 0.18   REQUEST_MORE_CONTEXT 0.67   ESCALATE 0.15
harness submits:     case=REQUEST_MORE_CONTEXT   confidence=high
```

`LEGAL(REVIEW, DELETE_DATABASE)` is not in the set. Full stop, not a probability of zero. The
controller interface doesn't care what produces the preference: GPT, Claude, a local model, a
classifier, an ensemble, even a hand-written table. Multiple models can sit behind the same
interface unmodified, because StoaGraph only ever sees `(state, proposed case, confidence)`,
never an arbitrary model-generated call.

### The concrete mechanism: a categorical proposer

The harness submits two ordinary gated slots on the trigger call: `case`, whose rule is
`set_membership` over the branch's declared case keys, and `confidence`, whose rule is
`set_membership` over `{high, medium, low}`. No softmax, no logprobs, no distribution crosses
the wire. This is the same shape as the dispatcher gate's `RouteResult`, one level down, and it
is required rather than optional, for four reasons:

1. **The fallback is recipe-declared and gate-enforced.** The `low` case is a branch in the
   policy. A buggy or compromised harness that skips its own entropy check cannot skip the
   branch.
2. **It is statically checkable.** The linter can see that every model-branch has a `low` case
   and where it leads. A harness convention cannot be linted.
3. **It runs on every backend.** How the harness forms its preference is its own business:
   JSON-schema-constrained output, sampling, or logprobs where an API exposes them. The bucket
   is derived from whichever is available. The gate never depends on which.
4. **It is a pattern the kernel already accepts.** The controller becomes a second instance of
   the dispatcher gate's interface, not a new one, which is what keeps it inside the framing
   above.

The harness's internal preference is a measurement surface, not an authorization one. Keeping the
policy fixed at inference time is what makes the controller's behavior comparable across models:
run model `M` against recipe `R` over N sampled contexts, measure calibration, how often `low` is
reported, how often escalation is chosen, adversarial susceptibility. Swap in `M2` against the
same `R`, repeat. The graph hasn't changed, so the comparison is clean. This is deliberately not
an RL problem: training a policy through interaction would reintroduce weights, a pipeline, and
statefulness this design has no need for, and would break the comparison, because the measured
thing would change in response to being measured.

Probability must never become an authorization primitive. `confidence = high` must never mean
"therefore authorized." Confidence answers "how sure is the model," never "what may the system
do." It can shape which case gets proposed, or route to the abort case, but authorization still
runs through the deterministic recipe topology and gate regardless of confidence:

```
harness -> (case, confidence) -> propose -> rules clear both slots
        -> branch -> legal case? -> no: deny
                                 -> yes: Decision.Authorized -> executeAuthorized -> action
```

### This is a `propose`, not a new step kind

A claim is a proposed slot. Its finite domain is its `set_membership` rule. It must be named in
the trigger route's `gateArg`, it binds on the trigger call, and it clears its rule before any
`branch` reads it. That is the existing `propose -> rule -> branch` discipline, applied to two
more slots. No new step kind, no new rule kind, no rule that returns a distribution, and no
change to `stag`'s next-state logic.

## What this does NOT change

- No new tool authority for the model or the controller. Every actual invocation still
  re-crosses the gate as it does today. The controller is just another proposer, on the existing
  untrusted agent side of the boundary.
- No kernel changes for the proposer. The kernel changes in this feature are the analyzer and two
  checks (one in the linter, one at bind), described in the implementation plan.
- No runtime recipe mutation. A recipe change is a new policy artifact with a new hash, through
  the normal authoring/audit lifecycle. Never a live edit during execution.
- No free-form context invention. Context slots have recipe-declared finite domains, the same
  way rules and slots do today.

## Context gating: resolved by the existing mechanism

StoaGraph already has a `context` concept: untrusted, provider-sourced content read via a `read`
step, stamped untrusted at origin and audited because it is not trusted
(`docs/context-binding.md`). A claim is the model's summarization of that content, not a clean
new fact. Three questions, kept separate:

- **Provenance.** Where did this value originate? Answered by `TrustClass`
  (`Untrusted` / `Caller` / `Authoritative`).
- **Semantics.** What does this evidence mean? Answered by model inference. New.
- **Authority.** What is this value allowed to influence? Answered by the gate and the rule on
  the slot.

`TrustClass` classifies the pipe, not the payload's meaning. A CRM record can be
`TrustClass = Authoritative`, it genuinely came from the CRM, while the model's classification of
that record ("customer is suspicious") is not authoritative just because its source was. So a
claim must never inherit trust from its source. It doesn't: a claim is a proposed slot on the
trigger call, judged by its own `set_membership` rule like any other proposed value, and it
carries no `TrustClass` beyond what any caller-proposed value has. Distinguish in prose, always:

- **A source fact.** `customer_status = verified`, `TrustClass = Authoritative`, produced by a
  provider, not by the model.
- **A model claim.** The same value proposed by the model into a declared slot, with a
  `confidence` bucket beside it. Cleared by a rule. Never promoted.

The finite domain on a claim slot is not a tractability convenience. It is the safety mechanism,
the same role `set_membership` already plays for any proposed argument. Claim (2) still stands: a
manipulated claim can shift which legal case is chosen. What's at stake is which legal transition
looks attractive, never an escape from the legal set. The mitigations are graph-shape constraints,
below.

## Two hashes: the recipe's, and the session's

`SemanticHash` binds the machine, not the model's output. Two different models producing opposite
preferences (`VERIFY` vs. `ESCALATE` for the same evidence) must still verify against the same
hash. It means "this is the machine I authorized," not "this is the choice the model will make."
Preference is runtime behavior. The hash is a policy-artifact identity and must stay blind to it,
the same way it's already blind to which values a session happens to propose.

`SemanticHash` certifies a recipe. It does not certify the wiring around it: whether a tool is
advertised to the model or reachable only by the executor is the `sequenced` flag on the route
row, which tools a session can reach comes from the route table at bind, and a route edit can
re-point a cleared call to a different downstream with no hash change anywhere. So the analyzer
emits a second artifact: a hash over the triple (recipes, route table, event map) for one
session's bind set. That triple hash is what makes "swap the model without reopening the security
review" true. The recipe hash certifies the policy; the triple hash certifies the surface.

## Claim B stays outside the security guarantee, on purpose

Claim A (topology can't be escaped) is the actual security guarantee, and it's fully
architectural. Claim B (the model chooses well among legal options) is deliberately left outside
that guarantee. This is a scope boundary, not a weakness:

> The model may be manipulated into preferring a legal but undesirable transition. However,
> manipulation cannot cause an undeclared capability.

Claim B is then improvable separately: better models, better evidence, multiple inference
passes, confidence thresholds, human review, disagreement detection, adversarial testing, without
ever needing to become part of the capability guarantee itself.

Outside the guarantee doesn't mean no mitigation. It means the mitigation lives in graph shape,
checked statically, not in a proof about the model. The concrete attack: an attacker manipulates
`read`-sourced content so a claim misclassifies a benign situation, a regular customer reads as
`blocked`, steering toward a legal-but-undesirable case. No capability escape, but a real bad
outcome achieved entirely inside the declared action set. Two constraints, both absent from the
codebase today, both enforced by the implementation plan below:

- **Equifinality (gate 1).** No path on which a model claim is the only deciding factor may
  reach an irreversible action or mint the grant for a sequenced tool. Every such path must
  contain a fact the model does not control, or target a recipe that can refuse on its own. A
  claim may steer which investigation or review path gets taken; the irreversible step at the end
  still needs something the model didn't produce. Refused at bind, the same posture as
  `requireBounded`.
- **The low-confidence case (gate 2).** Uncertainty is a distinct state that never releases.
  Every model-branch declares a `low` case that exits deterministically with an alert and mints
  no grant. The product already holds this rule for `await`: a tool meant for `await` must emit
  one value from a small closed set, and "could not determine" must be its own value that must
  not release. This is that rule, applied to the branch.

Low confidence aborts. Irreversibility escalates or needs an authoritative fact. Those are
different triggers and the plan keeps them distinct: hold-and-wait is wrong as a response to
uncertainty in an unattended session, and required as a checkpoint on an irreversible action.

## `stag analyze`: the actual product story

The analyzer's input is the triple: recipes, the route table, and the event map, resolved for one
session's bind set. Not the recipe alone. A certificate compiled from recipe YAML can say
"credential access: NO" about a session where a route makes that access reachable, and be wrong.

Two kinds of report, kept visibly distinct, answering different questions:

- **Static analysis**, no model involved, over the triple:

  ```
  1. TOPOLOGY              what CAN happen? states, edges, tools, sequenced routes,
                           irreversible actions, reachability of named capabilities
                           ("production restart: YES", "credential access: NO"),
                           states reaching human review vs. bypassing it, max tool
                           calls, max mutations, unbounded paths, the leakage bound
  2. SEMANTIC STATE SPACE  what CAN the model mean? slots, domains, cardinality,
                           declared dependencies, the density budget
  3. STRUCTURAL INFLUENCE  what can each claim AFFECT? which claims lie on a path to
                           which capabilities; per sequenced route, every path that can
                           mint its grant, labeled deterministic-only or probabilistic
  ```

  Plus the triple hash, and the four wiring invariants from `docs/dispatch-internals.md` as
  checks rather than prose. Answers "what can the agent ever do?"

- **Probabilistic telemetry**, runtime, per model, per context: the harness's actual preference
  given specific evidence, calibration, `low` frequency, empirical sensitivity. Answers "what
  does this model tend to do given this context?"

Never conflate the two in any report or UI. The guaranteed-capability bound and the observed
behavioral tendency are different kinds of claim. This separation, not the controller mechanism
itself, is the most compelling reason to build this at all, and the analyzer has value whether or
not the controller ever ships: it is the check the kernel's docs already promise.

## Context explosion / semantic policy smuggling

The problem, in one sentence: how much semantic complexity can the model absorb before the
recipe becomes a disguised deterministic rules engine?

The closed-transition invariant protects the capability boundary. It does not protect the
authoring boundary. A recipe can have perfect topology safety, five legal transitions, fully
enumerable, no undeclared capability reachable, while still having 50 context slots at 10 values
each with thousands of interactions between them. Claim A is never violated. But static analysis
over that recipe becomes practically meaningless, and the recipe has silently become the exact
combinatorial ruleset this feature exists to avoid, with the model sitting between observations
and the graph instead of a human writing `branch` predicates by hand.

The invariant this produces, stronger than "finite domains" alone:

> Claims may vary state. Claims may not vary the state space.

Five invariants together, the checklist for any implementation:

1. The model cannot create transitions.
2. The model cannot create context dimensions.
3. The model cannot create context values.
4. The model cannot change context dependencies. An author may declare them; the model may not
   introduce one.
5. Model-derived claims cannot bypass deterministic authority checks (equifinality, gate 1).

### Three constraints

- **Declared dependency, priced.** Context domains are immutable after compilation. A claim
  selects a value within a dimension; it cannot alter the domain or introduce a dependency at
  runtime. Real distinctions do correlate, though, and forbidding declared correlation just
  pushes it somewhere unauditable: the prompt, or a redundant slot. So an author may declare
  that one slot's legal values depend on another's, and pays for it in the density budget. What
  is refused is the undeclared kind: a claim that changes another slot's domain or the topology.
- **Information-density budgets, a direct extension of code that already exists.**
  Cross-product growth is the real danger, not any single slot's size: `3 x 3 x 8 x 4 = 288` is
  fine, `12 slots x 20 values = 20^12` is not, even with no single slot looking unreasonable.
  `stag/recipe/leakage.go` already computes this shape of bound (`Σ log2(K_i)` per gated
  argument, composed across branches and sessions). The same machinery over claim domains,
  capped the way `requireBounded` already caps forwarded-choice bits, is the mechanism. The
  recipe must pay for semantic complexity at compile time. An author should not be able to hide a
  giant state machine inside "the model understands the context."
- **Structural influence, static; empirical sensitivity, telemetry.** Which claims can reach
  which capabilities is a graph property and goes in the analyzer: a claim with no path to a
  capability makes the topology guarantee legible, and a claim on every path to `human_review`
  surfaces real operational influence. How much a claim moves a given model's preference is
  measured at runtime, using existing quantitative-information-flow formulations, and reported as
  telemetry, never as a static claim. Passing the first two constraints says nothing about this
  one, which is why it is the priority investigation target.

Semantic compression, defined precisely: it should reduce the complexity of observations without
increasing the complexity of the authorized policy topology. Intended shape: 10,000 observations
to 3-10 claims to 5 transitions. Failure shape: 10,000 observations to 50 claims to 10^40
combinations to 5 transitions. Same transition count at the end, which is exactly why topology
safety alone is not sufficient to measure.

> Can we define a bounded semantic interface whose expressive power is high enough to capture
> genuinely useful model reasoning, while its dimensionality and influence remain statically
> measurable and auditable?

If yes, this is a materially more novel contribution than "put probabilities on graph edges."

## Implementation plan: two prerequisites, then three gates

Every line has an input, a check, an enforcement point, and a proof artifact, matching how the
rest of this codebase proves things. Nothing ships past the first shipping scope until all five
are green.

### Prerequisites

- **P1, the proposer contract.** The harness submits two gated slots on the trigger call:
  `case ∈` the branch's declared case keys, `confidence ∈ {high, medium, low}`. No distribution
  crosses the wire. Proof: a recipe that branches on both slots, and a scripted no-model run
  (`stag-probe`) confirming the shape end to end.
- **P2, the analyzer input.** `stag analyze` reads recipes, the route table, and the event map
  for one session's bind set together, and emits a hash over that triple. Proof: identical
  inputs produce an identical hash across repeated runs.

### Gates

1. **Equifinality, enforced at bind.** Recipe save cannot see routes, so it can only warn; bind
   is where `requireBounded` already enforces, so this matches the precedent. Graph root: the
   event map. Probabilistic edges: a `route: "model"` dispatch, and any `branch` on a
   model-supplied slot. Sensitive: every sequenced route (sensitivity exists on sinks, not
   routes; this definition matches the existing rule to sequence every tool that changes state
   and needs no schema change). The check: every path from an event to an `invoke`/`await` of a
   sequenced route that contains a probabilistic edge must either contain a deterministic factor
   on that path (a deterministic event match, an authoritative slot, a human `gate`), or target
   a route whose own recipe contains an authoritative sink or a `gate`. A sub-recipe with only a
   benign sink does not count; it cannot refuse. Also refused: any such path whose re-crossing
   would carry a nested authorized plan, which today collapses to a single forwarded call with
   no error. Enforcement: a `-require-equifinal` flag beside `-require-bounded`; a violation is a
   `RouteError` and no session binds. Proof: a Go test asserting refusal on a violating triple
   and bind on a passing one.

   The stacked-layers question (a model-selected recipe feeding a model-selected branch) is not a
   separate gate. A probabilistically-selected recipe is one more probabilistic edge on the same
   graph, covered by the same rule. "One layer must be deterministic" would forbid useful stacking
   and isn't what the check requires; "one deterministic factor on every path to a sensitive
   grant" is.

2. **A deterministic `low` case, checked at validate.** Every `branch` on a `confidence` slot
   must have a `low` case that reaches an `exit` with `status: failure`, with no `invoke`/`await`
   of a sequenced route on that path and no `gate`. An alert on the way is fine, and the alert
   tool must be bound `sequenced: false`, otherwise this gate refuses it. Distinct from gate 1
   and not in conflict with it: low confidence always aborts; irreversibility always requires an
   authoritative fact or escalation. Enforcement: the linter; a recipe missing the case does not
   save. Proof: a scripted run forcing `low`, asserting the exit, an alert leaf, zero grants
   minted, and a partial-execution report.

3. **The reachability report.** Per sequenced route: every (event, trigger recipe, path) that
   can mint its grant, each labeled deterministic-only or probabilistic with the probabilistic
   edges named. Separately listed: mutating tools bound `sequenced: false`, since the model can
   call those directly and gate 1 does not cover them. Reporting only; gate 1 is the refusal.
   Proof: a golden-file test over the `testing/` scenario's triple.

Ship P1 and P2, then the three gates, for investigative and reversible recipe arms first. Gate
everything else behind them. Gates 1 and 3 share one graph walk over the triple, and that walk is
the one the wiring invariants in `docs/dispatch-internals.md` need, so building it retires the
promised-but-absent wiring audit at the same time.

## Why this direction, not something else

The strong claim this unlocks: different models all operate over the same compiled graph
`G = StoaGraph(recipe, routes, events)`. The provable statement is never "model X is safe." It's
"any policy that can only emit cases accepted by `G` cannot reach capability `C`," independent
of which model produced the choice. Swapping the model doesn't invalidate the capability
analysis. StoaGraph doesn't need to make AI deterministic to make an agent's capabilities
analyzable. Only the transition topology needs to be deterministic and closed.
