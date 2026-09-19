# StoaGraph: Probabilistic Controller (feature branch)

> This README is scoped to this branch only. It replaces the project README for the duration of
> `feat/probabilistic-controller` so reviewers see the feature's design in one place. On merge to
> `main`, `main`'s own README is kept. This file does not get merged over it. For the
> general-purpose StoaGraph README, see `main`.

## What this branch is for

Design and prototyping space for a learned/probabilistic transition layer above StoaGraph's
recipe graph. It does not weaken the recipe/kernel trust boundary. Status: design stage, nothing
below is implemented yet. This branch exists so the work can happen in the open without touching
`main`.

Full design writeup:
[`scratch/idea-probabilistic-transition-static-topology.md`](scratch/idea-probabilistic-transition-static-topology.md).
This README is the condensed, reviewable version.

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
of legal next steps, but let which legal case looks right be a learned weighting over that same
fixed set, not a hand-authored predicate. The recipe still decides what's possible. The case list
doesn't change, no new step gets invented. The model brings judgment to which already-legal case
fits messy input, instead of an author trying to anticipate every combination in advance.
Branching decides what CAN happen, and does it well. It was never meant to decide what SHOULD
happen when the right answer depends on interpreting something ambiguous. That's the seam this
feature sits in.

## The invariants

> The model may determine probability. The recipe determines possibility.
> The model may assign probability to transitions. It may not create transitions.

StoaGraph's existing trust boundary: the model proposes, the kernel decides what is executable.
The recipe graph is statically verified at parse/compose time, which is what makes
`SemanticHash` meaningful as a signed-policy identity. Everything below sits on the
model/context side of that boundary. It does not change it.

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
  checks the picked ID against `validIDs` and a confidence floor. A miss (`GateFallback`) binds
  no session at all: not a fallback recipe, not a default. A valid-but-wrong pick still can't
  exceed the selected recipe's own policy, because stag's gate re-enforces every individual call
  regardless of how the recipe was chosen.

Both are existing precedent this feature extends, not invents.

## The formal model

The core object is not a trained agent. It is a distribution `π(a | s, c, e)`, where the model
supplies the distribution, subject to:

```
support(π) ⊆ A(s)
```

`A(s)` comes entirely from the compiled recipe. The model cannot enlarge it. This is the formal
version of what the controller-shape section above already states in prose: `DELETE_DATABASE`
isn't "probability zero," it isn't an element of the candidate set at all.

Three layers, each a different kind of object, worth keeping strictly separate in any writeup:

- **Layer 1, capability topology.** `G = (S, A, T)`, compiled from the recipe. The security
  theorem: `a_t ∉ A(s_t) ⇒ execution rejected`. Model-independent. This is Claim A below.
- **Layer 2, semantic state.** `C = C_1 × C_2 × ... × C_n`, where every `C_i` is recipe-declared
  and finite. The model can select `customer_status ∈ {unknown, verified, blocked}` but cannot
  introduce `customer_status = "probably-fraudulent-but-not-quite"` or invent a new dimension.
  This is where the semantic-complexity problem lives (see "Context explosion" below).
- **Layer 3, probabilistic behavior.** `π_θ(a | s, c, e)`. Runtime behavior, not policy identity.
  This is why the `SemanticHash` position below is clean: hash the machine and its declared
  semantic vocabulary, never the model's runtime probabilities.

Read plainly, this document is a statically closed policy machine with probabilistic semantic
control, not a probabilistic agent wrapped in a guardrail and not primarily an RL/shielding
proposal. Ordinary LLM inference is sufficient (see the concrete mechanism above); RL only ever
appears as one possible later implementation of the same fixed interface, never as the center of
the idea. The genuinely interesting problem isn't "probabilities on transitions," which is well
trodden ground (probabilistic finite-state control, constrained structured prediction,
probabilistic model checking, runtime enforcement/shielding all touch it already). It's the
separation this document draws between semantic interpretation and policy topology, and in
particular the fourth layer below: how much a semantic distinction the model draws is allowed to
matter. The narrower, more useful prior-art question: has anyone studied a neural semantic
interpreter whose output is constrained to a statically closed semantic vocabulary, where the
resulting probabilistic policy operates over a separately verified capability topology, with
static analysis of the semantic claims' influence on capabilities? That's the actual search:
LLM semantic state abstraction, constrained structured prediction, finite-state controllers,
probabilistic model checking, runtime enforcement, and capability/transition influence,
intersected. Not "probabilistic RL shield."

Restated with this vocabulary: the model performs semantic compression, the recipe performs
capability compression. The model takes messy evidence (an incident report, CRM text, a ticket,
a customer message) and compresses it into a small declared semantic space. The recipe then
compresses the possible consequences into a closed action topology. The research question
becomes: what is the maximum useful semantic compression achievable before the semantic
representation becomes an implicit second policy language? That question is the actual research
contribution of the "Context explosion" section below, not a restatement of it: the three
constraints there (dimensional independence, information-density budgets, claim-to-transition
sensitivity) are the concrete shape of an answer, not merely implementation safeguards protecting
against one.

### The four-layer hierarchy

The three layers above already give topology, semantic state, and probabilistic policy. Claim
influence deserves to stand as an explicit fourth layer, not sit as the third of three
constraints under "Context explosion" below, because it asks a different kind of question than
the other two constraints there (how big is the semantic space, how independent are its
dimensions): it asks how much any one distinction actually matters once the space exists.

```
Topology:             what CAN happen?
Semantic state:        what distinctions can the model represent?
Probabilistic policy: what does the model prefer?
Claim influence:       how much does each semantic distinction matter?
```

The first three are present in this document at least in embryonic form. Claim influence,
`Sensitivity(claim, capability)` below, is the least explored and the one most worth
investigating against prior research first: it's the layer that would tell you whether a
declared-finite, dimensionally-independent, density-capped semantic space (the other two
constraints) is actually sufficient to stop the semantic layer from becoming a hidden policy
language, or merely necessary. A space can pass both of those checks and still let one claim swing
outcomes disproportionately, which is exactly what claim influence measures and the other two
don't.

## Thesis

The strongest case for this feature: the input is semantically rich enough that the right branch
condition isn't knowable ahead of time, but the safe set of actions is still knowable ahead of
time.

> The semantic compression is performed by the model. The security compression is performed by
> the recipe.

That's the actual gap between a deterministic branch and a probabilistic controller. Not
"smarter" vs. "dumber," but where the authoring cost lives. Decision rule: if you can author a
good deterministic branch, use the deterministic branch. There's no reason to replace
`if amount > $10,000: require_approval` with an LLM; that predicate is already cheap and exact.
The controller earns its keep once converting messy reality into predicates means rebuilding a
semantic reasoning system out of hand-written rules, while the actions available in response stay
small, stable, and enumerable (`inspect_payment_errors`, `escalate_to_human`, `REFUND`,
`RESTART_SERVICE`). Full worked examples (incident response, support, research, cloud ops) are in
the scratch note.

Two claims come out of this. Keep them separate in any pitch of this feature:

1. **An attacker cannot escape the declared action set.** Architecturally sound. Already
   demonstrated by the precedent above (`requireBounded`, the candidate-set dispatcher).
   Confusing the model cannot grant it a capability the recipe never declared.
2. **An attacker cannot make the model choose badly among the actions it's allowed.** Not
   demonstrated. A `context:` value used to weight transitions is typically derived from
   untrusted `read` content. An attacker who controls that content can plausibly steer the
   weighting toward the wrong-but-legal action, or away from escalation, without leaving the
   topology. This is why the context-gating question below has to be resolved before this ships
   anywhere the wrong legal action has real consequences (incident response, cloud ops). It
   matters far less for pure exploration, where a bad weight mostly costs a wasted turn.

## The two-graph split

- **Graph A, the policy graph.** The existing StoaGraph recipe. Describes what CAN happen.
  Stays entirely deterministic and statically analyzable, unchanged by this feature.
- **Graph B, the context graph.** What the model can believe or observe next, over a
  recipe-declared finite domain, e.g. `customer_status: unknown|verified|blocked`. The model
  assigns a probability over the next value. It does not invent a new context slot or value. Same
  shape `propose` already has: the model fills in a declared slot, it doesn't invent the slot.

Combined state `X = (S, C)`, policy step times context, is finite and enumerable ahead of a run
only if the context graph is closed: `C' ∈ Next_C(C)`, where `Next_C` is recipe-defined, never
model-defined. Given that, `Next(X)` is statically enumerable. The model supplies
`P(X' | X, E)`, a probability over already-enumerated next-states given evidence `E`, but never
defines `Next(X)` itself. `Reachable(X0)` is then a static, precomputable property of the
compiled recipe plus the declared context domains, not an empirical claim about model behavior.
This closure requirement is the mathematical core of the feature.

## The controller shape

The controller is a probabilistic inference policy over a statically enumerated FSM. There is no
learning during execution:

```
untrusted evidence
       |
       v
   LLM inference
       |
       | semantic claims
       v
 bounded context C
       |
       v
 P(a | S, C, evidence)
       |
       | a in LegalTransitions(S)
       v
 deterministic StoaGraph kernel
       |
       v
      action
```

The model does not generate actions. It generates a probability distribution over the legal
transitions the recipe already declares from the current step:

```
state REVIEW, legal = {APPROVE, REQUEST_MORE_CONTEXT, ESCALATE}
model:  APPROVE 0.18   REQUEST_MORE_CONTEXT 0.67   ESCALATE 0.15
```

`LEGAL(REVIEW, DELETE_DATABASE)` is not in the set. Full stop, not a probability of zero. This
is `π_θ(a | s, c)` where `π` is a fixed inference policy but `a ∈ A(s)`, and `A(s)` is statically
declared by the recipe. The controller interface doesn't care what produces the distribution: GPT,
Claude, a local model, a classifier, an ensemble, even a hand-written probabilistic model.
Multiple models or policies can sit behind the same interface unmodified, because StoaGraph only
ever sees `(state, proposed transition)`, never an arbitrary model-generated call.

### The concrete mechanism: constrained decoding over logprobs

No custom policy training required. Modern inference engines expose a probability distribution
over legal transitions natively, via log probabilities:

1. **Legal set.** `[APPROVE, REQUEST_MORE_CONTEXT, ESCALATE]`, read straight off the recipe's
   declared transitions for the current step.
2. **The kernel constrains the vocabulary.** The inference call is constrained (token-level
   constrained decoding) to evaluate only the tokens representing those declared transition
   strings as the next generated token. The model is never free to emit anything else.
3. **The model returns logprobs.** The raw log-likelihood for each of the allowed strings, not a
   free-text response to be parsed.
4. **The controller normalizes.** A softmax over those logprobs yields the closed-domain
   distribution:

```
APPROVE: 0.18   REQUEST_MORE_CONTEXT: 0.67   ESCALATE: 0.15
```

This keeps the system stateless: no weights, no value function, no training pipeline. The code
that extracts a distribution is a plain interface wrapping an API logprob response or a local
`llama.cpp` token-evaluation loop. Swapping the underlying model, from a fast local 8B model to a
frontier model, is instant, because every model speaks the same language of token probabilities
against the same constrained vocabulary.

No learning happens during execution, and nothing here needs it to. Keeping the policy fixed at
inference time is what makes the controller's behavior measurable and comparable across models
(see below). This is deliberately not framed as an RL problem: applying RL here would mean
training a policy through interaction, which reintroduces weights, a training pipeline, and
statefulness this design has no need for. The Safe-RL/shielding literature is still the right
conceptual ancestor for the actual mechanism, a deterministic machine trapping an unpredictable
controller, just applied here to a stateless logprob interface instead of a trained policy. That
substitution is what keeps the system simple: no training state to manage, a thin Go interface
around a logprob response, and full model agnosticism.

Probability must never become an authorization primitive. `confidence = .97` must never mean
"therefore authorized." Probability answers "what does the model currently believe," never "what
may the system do." Confidence can shape which transition gets proposed, or bias toward an
explicit `ESCALATE`/`REVIEW` transition, but authorization still runs through the deterministic
recipe topology and gate regardless of confidence value:

```
model -> probability distribution -> probabilistic controller -> candidate
      -> recipe topology -> legal transition? -> no: stop
                                               -> yes: deterministic policy -> action
```

### Reuses the existing `propose` architecture

No new trust mechanism needed. This extends the existing
`propose -> constrained slot -> gate -> invoke` shape from values to transition preference:

```
read -> propose context claim -> finite-domain / ReleaseRule -> probabilistic transition
     -> recipe transition -> gate -> invoke
```

Open question worth resolving early: is a context claim best implemented as another kind of
`propose` step, rather than a new step kind? That keeps the grammar surface smaller and inherits
the existing `propose`/rule-clearance discipline for free.

## What this does NOT change

- No new tool authority for the model or the controller. Every actual invocation still
  re-crosses the gate as it does today. The probabilistic layer is just another proposer, on the
  existing untrusted agent side of the boundary.
- No runtime recipe mutation. A recipe change is a new policy artifact with a new hash, through
  the normal authoring/audit lifecycle. Never a live edit during execution.
- No free-form context invention. Context slots have recipe-declared finite domains, the same
  way rules and slots do today.

## The context-gating gap (unresolved, load-bearing)

The `context:` slots above are not an independent new layer. StoaGraph already has a `context`
concept: untrusted, provider-sourced content read via a `read` step, stamped untrusted at origin
and audited because it is not trusted (`docs/context-binding.md`). In a real recipe, a
`context:` slot's value is derived by the model from that untrusted content. It's a
model-produced summarization of untrusted input, not a clean new fact.

### Three different questions, kept separate

- **Provenance.** Where did this value originate? Answered today by `TrustClass`
  (`Untrusted` / `Caller` / `Authoritative`).
- **Semantics.** What does this evidence mean? Answered by model inference. New. Nothing
  answers this today.
- **Authority.** What is this value allowed to influence? Answered by the gate / `ReleaseRule`.

`TrustClass`/`SinkSensitivity` are real and live. `GateSink` already denies an
authoritative-sensitivity crossing unless the value's `TrustClass` is `Authoritative` or a human
released it. But they classify provenance, not semantics. A CRM record can be
`TrustClass = Authoritative`, it genuinely came from the CRM, while the model's classification
of that record ("customer is suspicious") is not itself authoritative just because its source
was. `TrustClass` classifies the pipe, not the payload's meaning. It does not close this gap on
its own. The design must not stretch it to cover semantics.

### Context should be a first-class claim, not a promoted fact

Instead of `context.customer_status = verified`, which implies a fact, model the output of
interpretation as a claim with its own epistemic status:

```
model_claim:
    slot: customer_status
    value: verified
    confidence: 0.83
    evidence: [...]
```

This distinguishes a SOURCE FACT (`customer_status = verified`, `TrustClass = Authoritative`)
from a MODEL CLAIM (same value, `derived_from = [source facts]`, `confidence = .83`). A claim
never gets silently promoted to authoritative just because the source facts it came from were.
This is the missing type between `TrustClass` and transition policy: a `model_claim` should need
to clear a `ReleaseRule` before it's allowed to influence weighting, not the raw value, and not
an inherited trust level.

A manipulated claim can shift the probability distribution over which legal transition looks
likely. That's claim (2) above, not yet closed. The finite domain on a `context:` slot is not
just a tractability convenience, it's the safety mechanism against this, the same role
`set_membership` already plays for a `propose`d value. This stays inside claim (2)'s scope, not
claim (1)'s: the topology invariant holds regardless. What's at stake is which legal transition
looks attractive, never an escape from the legal set.

Resolved direction, still to be implemented: a `context:`/`model_claim` fill must clear a rule
before it's allowed to influence transition weighting, the same discipline a `propose → invoke`
argument already goes through before reaching a tool. Reuse `ReleaseRule`/`set_membership`
machinery rather than inheriting safety from the source value's `TrustClass`. Resolve this before
any implementation work starts.

## `SemanticHash` binds the machine, not the model's output

The hash should be `Hash(topology, context domains, constraints, capabilities)`, never
`Hash(topology, model output)`. Two different models producing opposite distributions
(`VERIFY .8 / ESCALATE .2` vs. `VERIFY .2 / ESCALATE .8`) must still verify against the same
hash. It means "this is the machine I authorized," not "this is the probability distribution the
model will produce." Distribution is runtime behavior. The hash is a policy-artifact identity and
must stay blind to it, the same way it's already blind to which values a session happens to
propose.

## Claim B stays outside the security guarantee, on purpose

Claim A (topology can't be escaped) is the actual security guarantee, and it's fully
architectural. Claim B (the model chooses well among legal options) is deliberately left outside
that guarantee. This is a scope boundary, not a weakness:

> The model may be manipulated into preferring a legal but undesirable transition. However,
> manipulation cannot cause an undeclared capability.

Claim B is then improvable separately: better models, better evidence, multiple inference
passes, confidence thresholds, human review, disagreement detection, adversarial testing, without
ever needing to become part of the capability guarantee itself. This is also why keeping the
policy fixed at inference time is a measurement design, not just simplicity for its own sake. The
controller can be evaluated as a fixed policy over a changing context distribution: run model `M`
against recipe `R` over N sampled contexts, measure calibration, transition entropy, escalation
frequency, adversarial susceptibility. Swap in `M2` against the same `R`, repeat. The graph hasn't
changed, so the comparison is clean. A policy that trains against its own outputs during operation
would break that comparison, because the measured thing changes in response to being measured.

### Concrete mitigations, even though Claim B can't be proven

Outside the guarantee doesn't mean no mitigation. It means the mitigation lives in topology
design, not in a proof. The concrete attack shape: an attacker manipulates `read`-sourced content
so a `model_claim` misclassifies a benign situation, a regular customer reads as `blocked`,
maximizing the weight on a legal-but-undesirable transition. No capability escape, but a real bad
outcome achieved entirely inside the declared action set. Two mitigations, both absent from the
codebase today, both graph-shape constraints rather than new trust mechanisms:

- **Equifinality restraint.** No automated path triggered solely by a `model_claim` should reach
  an irreversible/destructive action without a separate, hard-coded checkpoint that is not itself
  probability-derived: a `TrustClass = Authoritative` value the model didn't produce, or an
  explicit human release. A `model_claim` may steer which investigation or review path gets
  taken. The irreversible step at the end of that path must still require a fact the model
  doesn't control. Likely a lint/validation rule on the recipe graph, the same way
  `requireBounded` already refuses a route shape it doesn't like.
- **Entropy trigger.** A near-uniform transition distribution
  (`APPROVE 0.34 / REQUEST_MORE_CONTEXT 0.33 / ESCALATE 0.33`) is a structural failure signal, not
  harmless uncertainty. It should force a fail-closed route to a default human-review path rather
  than letting the controller take the barely-highest-weighted option. Same fail-closed instinct
  `dispatch.Gate`'s confidence floor already applies to recipe selection, applied one level down
  to the transition itself.

Both belong in the probabilistic-controller layer's handling of a distribution, but what they
enforce should be checkable statically too. A `stag analyze` line like "states reaching an
irreversible action without a hard-coded checkpoint: 0" would make the equifinality restraint a
verifiable property of the compiled policy, not just a runtime hope.

## `stag analyze`: likely the actual product story

Two reports, kept visibly distinct, answering two different questions:

- **Static analysis** (`stag analyze incident-response.yaml`, compiled from the recipe alone, no
  model involved): states/transitions/context-dimension/combined-state counts, read-only vs.
  mutating vs. privileged tool counts, explicit reachability of named capabilities
  ("production restart: YES", "credential access: NO"), how many states reach human review vs.
  bypass it, max tool calls / max mutations / unbounded paths. Answers "what can the agent ever
  do?" A natural extension of the existing bounded-leakage check (`requireBounded`), not a new
  philosophy.
- **Probabilistic telemetry** (runtime, per-context): the model's actual transition
  distribution given a specific context. Answers "what does this model tend to do given this
  context?"

Never conflate the two in any report or UI. The guaranteed-capability bound and the observed
behavioral tendency are different kinds of claim. This separation, not the controller mechanism
itself, may be the most compelling reason to build this at all.

## Context explosion / semantic policy smuggling

This is the research question from the formal model above, made concrete: what is the maximum
useful semantic compression achievable before the semantic representation becomes an implicit
second policy language? The three constraints below are a candidate answer to that question, not
merely safeguards bolted on to prevent an edge case. If this feature has a genuine research
contribution beyond "put probabilities on graph edges," it is most likely here.

The problem, in one sentence: how much semantic complexity can the model absorb before the
recipe becomes a disguised deterministic rules engine?

The closed-transition invariant protects the capability boundary. It does not protect the
authoring boundary. A recipe can have perfect topology safety, five legal transitions, fully
enumerable, no undeclared capability reachable, while still having 50 context variables at 10
values each with thousands of interactions between them. Claim A is never violated. But static
analysis over that recipe becomes practically meaningless, and the recipe has silently become the
exact combinatorial ruleset this feature exists to avoid, just with the model sitting between
observations and the graph instead of a human writing `branch` predicates by hand. This failure
mode has a name: context explosion / semantic policy smuggling.

The formal invariant this produces, stronger than "finite domains" alone because it also rules
out cross-slot dependency:

> Claims may vary state. Claims may not vary the state space.

Five invariants together, the full checklist for any future implementation:

1. Model cannot create transitions. (established above)
2. Model cannot create context dimensions.
3. Model cannot create context values.
4. Model cannot change context dependencies.
5. Model-derived claims cannot bypass deterministic authority checks. (the equifinality
   restraint, above)

### Three constraints: the candidate answer, most direct first

- **Dimensional independence, the strongest of the three.** Context domains are immutable and
  independent after compilation. A claim selects a value within a dimension. It cannot alter the
  dimension's domain, introduce a dependency, or create a conditional domain.
  `customer_status -> transition weights` and `request_type -> transition weights`, always
  independently, never `customer_status -> changes legal values of request_type -> changes
  transition topology`. That second shape is a hidden policy compiler inside the semantic layer.
  It's the constraint most likely to be violated by accident, because it looks like ordinary
  schema design rather than a security property.
- **Information-density budgets, a direct extension of code that already exists.**
  Cross-product growth is the real danger, not any single slot's size: `3 x 3 x 8 x 4 = 288` is
  fine, `12 slots x 20 values = 20^12` is not, even with no single slot looking unreasonable.
  `stag/recipe/leakage.go` already computes this shape of bound (`Σ log2(K_i)` per gated
  argument, adversarially verified, composed across branches and sessions). The same machinery
  over context domains, capped the way `requireBounded` already caps forwarded-choice bits, is
  the likely mechanism. The recipe must pay for semantic complexity at compile time. An author
  should not be able to hide a giant state machine inside "the model understands the context."
- **Claim-to-transition sensitivity, the most novel idea here, and the fourth layer above.**
  Define an audit metric, not a security guarantee: `Sensitivity(claim, capability)` equals the
  maximum change in a capability-relevant transition probability caused by varying that claim,
  holding everything else fixed. A `0` for a claim against an unreachable capability makes the
  topology guarantee legible. A high sensitivity against something like `human_review` surfaces
  real operational influence. This measures policy influence, explicitly not `TrustClass`, a new
  metric nothing in the codebase currently produces. Unlike the two constraints above, which
  bound the semantic space itself, this measures whether the space, once bounded, still lets one
  distinction matter disproportionately. It is the priority investigation target of the four
  layers, precisely because passing the first two constraints says nothing about this one.

### `stag analyze`'s job, now three layers

```
1. TOPOLOGY             - what CAN happen? states, edges, tools, irreversible actions
2. SEMANTIC STATE SPACE - what CAN the model mean? slots, domains, cardinality, dependencies
3. CLAIM INFLUENCE      - what can each interpretation AFFECT? transition sensitivity, capability impact
```

This supersedes the earlier two-report framing above. Layers 2 and 3 are both purely structural,
no model execution required for either, they just hadn't been separated out yet. Semantic
compression, defined precisely: it should reduce the complexity of observations without
increasing the complexity of the authorized policy topology. Intended shape: 10,000 observations
to 3-10 claims to 5 transitions. Failure shape: 10,000 observations to 50 claims to 10^40
combinations to 5 transitions. Same transition count at the end, which is exactly why topology
safety alone is not sufficient to measure.

### The actual research question

> Can we define a bounded semantic interface whose expressive power is high enough to capture
> genuinely useful model reasoning, while its dimensionality and influence remain statically
> measurable and auditable?

If yes, this is a materially more novel contribution than "put probabilities on graph edges."
The interesting claim was never that a model can weight a fixed transition set. It's that the
semantic interface feeding that weighting can itself be kept small, closed, and auditable enough
that its real-world influence is measurable ahead of time, the same way its topology already is.

## Open design questions

Not yet decided. See the scratch note for the full list:

- Where a context slot's finite domain is declared: a new `context:` block, or reuse of
  existing slot/rule machinery with a "finite domain" constraint kind.
- Whether the transition-probability interface is a new rule `kind` that returns a distribution
  instead of a boolean, or a distinct step-level construct.
- Whether a `model_claim` is best implemented as another kind of `propose` step or a new step
  kind.
- Whether `Reachable(X0)` over the combined (policy state × context) space extends the existing
  leakage-analysis code in `stag/recipe`, or wants a separate pass.

## Why this direction, not something else

The strong claim this unlocks: different models and policies all operate over the same compiled
graph `G = StoaGraph(recipe)`. The provable statement is never "model X is safe." It's "any
policy that can only emit transitions accepted by `G` cannot reach capability `C`," independent
of which model produced the distribution. Swapping the model doesn't invalidate the capability
analysis. StoaGraph doesn't need to make AI deterministic to make an agent's capabilities
analyzable. Only the transition topology needs to be deterministic and closed.
