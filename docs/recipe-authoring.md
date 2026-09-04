# Writing recipes

A **recipe** is a stag policy: a small, closed graph that a proposed tool call walks through to a
verdict. It is authored in YAML, validated by a linter, and executed by a deterministic kernel —
**no model, no I/O**. Same recipe + same call → same verdict, always, which is what makes a
decision replayable by an auditor who was not there when it happened.

This page is the language reference. If you want the *why* first, read
[the doctrine](doctrine.md); for binding a tool to a policy, [routes.md](routes.md).

## The mental model

A tool call arrives as a set of named **arguments** (e.g. `namespace`, `replicas`). A recipe:

1. **proposes** those arguments as **untrusted** values — they came from the agent, and you never
   trust them,
2. optionally **branches** on them and **gates** them against rules, and
3. **sinks** them: an *authoritative* sink is the moment a value would actually reach the real
   tool.

The load-bearing invariant: **no untrusted value reaches an authoritative sink without a rule
release and a recorded crossing.** Everything else serves that guarantee.

The verdict of the whole recipe is the AND of its steps: **allow** only if every crossing was
released; otherwise **deny**, **escalate**, or **fault**.

### A recipe judges a call; it can also authorize a sequence

Most recipes decide one call. A recipe with [`invoke`](#invoke) steps does more: it **authorizes
an ordered sequence** of calls — fix, then rebuild, then verify — so a model may trigger the work
without choosing what runs, in what order, or with what arguments.

The kernel still performs no I/O. It authorizes; a separate executor carries the calls, putting
**every one of them back through the gate** against that tool's own route and recipe. Authorizing
a call is never authority to make it.

## Anatomy

```yaml
recipe: my_policy       # name (also the id you route tools to)
version: 1
                        # (an optional `passthrough:` list declares arguments knowingly
                        #  forwarded UNGATED — omit the key to gate every argument)
rules:                  # named predicates, referenced by id — the only reuse mechanism
  ns.safe:  {kind: set_membership, set: ["dev", "staging"]}
  count.ok: {kind: numeric_range, min: 0, max: 5}
steps:                  # the graph, top to bottom; edges only ever point forward
  - {id: propose_ns, kind: propose, out: namespace}
  - {id: propose_n,  kind: propose, out: replicas}
  - {id: g_ns,  kind: gate, in: namespace, rule: ns.safe, on_fail: deny}
  - {id: apply, kind: sink, in: replicas, field: k8s.scale.apply,
     sensitivity: authoritative, rule: count.ok, actor: "policy:platform"}
```

Two hashes are derived from every recipe. The **artifact hash** is the bytes of the file; the
**semantic hash** is the policy's *identity* — what it accepts, which tool it authorizes, which
rule clears which argument, how long it will wait. Reformatting a recipe or editing a comment
leaves the semantic hash unchanged; widening a set, renaming an argument's rule, or raising an
`await`'s attempts changes it, and the signed audit record says so.

## Rules — the three closed predicates

A rule decides whether a value is **released**. There are exactly three kinds, and the set is
closed on purpose: a policy language with an open predicate set is one whose accepted values
nobody can enumerate, and "what exactly does this allow?" stops having an answer.

| Kind | Passes when | Example |
| --- | --- | --- |
| `set_membership` | the value is one of a fixed set | `{kind: set_membership, set: ["dev", "staging"]}` |
| `numeric_range` | the value is an **integer** in `[min, max]` (canonical form only) | `{kind: numeric_range, min: 0, max: 5}` |
| `signed_equality` | the value byte-equals a pinned/approved value | `{kind: signed_equality, signed: "$approved"}` |

Rules live in a named registry and are referenced by id, which is the only reuse mechanism —
YAML anchors and aliases are rejected. A rule that is declared and never referenced is a
**rejected recipe**: dead policy reads like a control and isn't one.

To DENY everything, use an unsatisfiable set: `{kind: set_membership, set: ["__never__"]}`.

### `set_membership` is byte-exact

There is no trimming, no case folding, no pattern matching. `"none"` and `"none\n"` are different
values, and a rule that quietly normalized them would have a real accepted set larger than the
one written down.

This has a practical consequence: **a tool whose output shape is undeclared cannot be gated by
equality.** If you intend to match a tool's output — with [`await`](#await), say — the tool must
emit a stable, declared value. Fix the shape in the tool, not by loosening the rule.

Set members may not contain control characters (a newline included), because those values ride
verbatim into signed audit fields.

### `numeric_range` is integer-only, on purpose

It requires canonical integer form, so the accepted set stays finite and enumerable. A decimal
like `45.50` does not pass and is denied. It cannot express a money range (`0.00–10000.00`). For
a monetary or otherwise-decimal value, gate by equality to the authoritative amount, or express
the range in integer minor units (cents) if a range is truly what you need.

### A range is not integrity for a value the attacker can set

If an attacker who has poisoned the context can choose *any* value inside your range, the range
does not protect the action — it just bounds how bad the chosen value is. A refund `amount` gated
`numeric_range {0, 10000}` still lets a hijacked call send €9,999.

Gate a value the attacker controls by **equality to the authoritative source** (`set_membership`
over the one verified value, or `signed_equality` against a signed fact), not by a range, unless
the range itself is the whole policy. This was found by replaying an external red-team suite
against the gate; see the project transcripts.

## Steps — the nine node kinds

The graph is built from a **closed set** of node kinds. There is no ninth, and no escape hatch:
a policy language you can extend at will is a policy language whose accepted set nobody can
enumerate. Edges are **forward-only** — a `goto` always points to a later step — so a recipe is
a DAG that always terminates.

| kind | what it does | keys |
| --- | --- | --- |
| [`propose`](#propose) | bind a tool argument as an untrusted value | `out`, `goto` |
| [`gate`](#gate) | halt the recipe unless a value clears a rule | `in`, `rule`, `on_fail` |
| [`branch`](#branch) | route to one of several steps by rule | `in`, `cases`, `default` |
| [`sink`](#sink) | the crossing: release a value to the tool, and record it | `in`, `field`, `sensitivity`, `rule`, `actor`, `goto` |
| [`invoke`](#invoke) | authorize one tool call in a sequence | `tool`, `args`, `actor`, `goto` |
| [`await`](#await) | do not proceed until a tool's output satisfies a rule | `tool`, `args`, `until`, `attempts`, `every_ms`, `actor`, `goto` |
| [`read`](#read) | fetch context the recipe chose, with a gated question | `provider`, `query`, `goto` |
| [`foreach`](#foreach) | gate every element of a runtime list | `in`, `as`, `goto` |
| [`exit`](#exit) | a terminal: halt this path | — |

Every step needs an `id`, unique within the recipe. Any key not in a kind's row is **rejected**,
not ignored: a typo that silently did nothing would be a policy that does not do what it says.

---

### `propose`

Binds one tool argument into a named slot, **untrusted**.

```yaml
- {id: p_ns, kind: propose, out: namespace}
```

`out` is the *argument name*: `propose out: namespace` binds whatever the agent sent as
`namespace`. Every value enters this way, and every value enters untrusted — there is no syntax
for proposing something trusted, because the whole model is that trust is re-derived at the sink
from the rule that fires, never carried in from the proposer.

An absent argument binds the empty string, which fails every rule. Fail closed.

---

### `gate`

A checkpoint. If the value fails `rule`, the recipe **stops here**.

```yaml
- {id: g_ns, kind: gate, in: namespace, rule: ns.safe, on_fail: deny}
```

`on_fail` is `deny` (the default) or `escalate`. It is the difference between "no" and "ask a
person" — see [human approval](#multiple-arguments-and-human-approval).

A gate protects everything downstream of it, and the linter enforces that: the authoritative
sinks a gate guards must be reachable **only** through it. A gate you could walk around is
decoration.

Use a gate when a value must be right for the rest of the recipe to make sense at all. Use a
[`branch`](#branch) when different values should do different things.

---

### `branch`

Routing, never enforcement. The first case whose rule releases wins; if none does, `default`.

```yaml
- id: route
  kind: branch
  in: namespace
  cases:
    - {rule: ns.safe, goto: apply}      # dev/staging → act
    - {rule: ns.prod, goto: escgate}    # prod        → escalate
  default: block                        # anything else → deny
```

Every edge is explicit — including `default`, which is required. A branch on a value that was
never bound is a **fault**, not a fall-through: routing on uncertainty is refused.

A branch **selects which path is authorized**, so it composes with sequences: "if prod, authorize
the careful sequence; otherwise the quick one" is a branch whose cases `goto` different `invoke`
chains.

`branch` reads a value the *caller proposed*. It cannot read what a previous call returned — see
[Not in v1](#not-in-v1).

---

### `sink`

The crossing. This is the step where an untrusted value would actually reach the tool.

```yaml
- {id: apply, kind: sink, in: replicas, field: k8s.scale.apply,
   sensitivity: authoritative, rule: count.ok, actor: "policy:platform"}
```

- **`sensitivity: authoritative`** — a real release. It releases *only* if `rule` passes, and the
  same step that clears the crossing records it. That coupling is structural: there is no path
  that releases without recording, so the audit cannot disagree with what happened.
- **`sensitivity: benign`** — a non-authoritative read. Not release-gated, so a `rule` here is
  **rejected**: a rule that is never consulted is dead policy pretending to be a control.
- **`field`** names the crossing in the audit. Two authoritative sinks may not share one — aliased
  fields collapse the event-to-crossing correspondence.
- **`actor`** is who is accountable, and is required whenever a rule is present.

---

### `invoke`

Authorizes **one tool call** as part of a sequence. Several `invoke` steps express a whole
remediation arc in a fixed order, with no model choosing that order.

```yaml
- {id: drain, kind: invoke, tool: k8s__drain_node,
   args: {node: {slot: node, rule: node.worker}},
   actor: "policy:maintenance"}
```

**`tool` is the advertised name** (`<server>__<tool>`) — the same name the agent would call and
the name the audit records.

**`args` is optional.** A tool that takes none — restart, status, list — is authorized by the step
being in the recipe, exactly as an empty `gateArg` on a route means *no arguments to judge*.
Requiring one would force a decorative argument into the policy, gating a value the tool never
receives. An `args: {}` mapping is still rejected: omit the key.

**Every argument carries its own rule.** `args` maps an argument name to the slot that supplies
it *and* the rule that must clear it.

Per-argument rules bound each argument; they cannot express a relationship *between* them. Gating
`key` in `{log_level, max_workers}` and `value` in `{info, debug, 2, 4, 8}` clears
`max_workers=debug` — each argument is legal and the pair is nonsense. When two arguments'
value spaces depend on each other, that is a sign the recipe is covering two operations: write
one recipe per key, and let the rule be the values *that* key accepts. This is required, not optional: an invoke's arguments are
usually different *kinds* of value — a target, an operation, a payload — and one rule shared
across them could only be the union of what each may be, which is a flat set of permitted strings
with no idea which argument it is looking at.

Full detail in [Sequencing several tools](#sequencing-several-tools).

---

### `await`

Do not proceed until a tool's output satisfies a rule.

```yaml
- {id: settle, kind: await, tool: k8s__pods_on_node,
   args: {node: {slot: node, rule: node.worker}},
   until: pods.none, attempts: 6, every_ms: 5000,
   actor: "policy:maintenance"}
```

Without it a verify step is a **witness, not a gate**: it runs, its output is recorded, and the
next step proceeds regardless. `await` is what turns "we looked" into "we did not continue until
it was true."

`until` names a rule the *output* must satisfy. `attempts` and `every_ms` are bounded by the
kernel and a recipe cannot raise them. Full detail in
[Waiting for a condition](#waiting-for-a-condition).

---

### `read`

Fetches context from a source **the recipe names**, asking a question **the recipe bounds**.

```yaml
- {id: brief, kind: read, provider: runbooks,
   query: {slot: topic, rule: topic.allowed}}
```

A bound provider is also advertised to the agent as a `context__<name>` tool, and that leaves
both decisions to the model: which source to consult, and what to ask it. The question is then
free text flowing *outward*, which is the read-side of the leakage problem. A `read` step moves
both to the author — and the gain is that **the query is gated**: the policy bounds what may be
*asked*, not only what may be read back.

**It is not an action, and the differences are deliberate:**

- **it can never deny.** A query that fails its rule authorizes no read, and that is all — the
  rest of the policy decides on its own terms. Context is how an agent finds out *why* an action
  was refused, and a read that could cause the refusal would remove it exactly when it is needed.
- **it records no crossing**, mints no grant and spends no budget. The read channel has its own
  evidence — a `ReadEvent` carrying the query, the sources, and a hash of the exact bytes served.
- **its result survives a refusal.** A denied action still returns the context the recipe read.

The content arrives as untrusted, framed as data, whatever the provider claims about itself. See
[the context channel](context-binding.md).

**How much comes back is bounded by the gate, not the recipe.** A gated query narrows the
question; without a bound on the answer it is still unbounded. Measured on a 15-file runbook
library, the query `drain` matched 13 files and 10,697 characters. So a read returns at most
`k` documents and `max_chars` of text — `STOA_READ_K` and `STOA_READ_MAX_CHARS`, defaulting to
**2** and **4000**, with a ceiling an operator cannot exceed.

The defaults are low deliberately. A read has already narrowed twice — the author named the
provider and enumerated the queries — so a large `k` is not more relevant material, it is the
rest of the corpus arriving because nobody chose. Truncation is by whole documents: half a
document is worse than one fewer, because the model cannot tell it was cut.

**What a read will fetch is knowable before it runs.** The provider is named and the query rule
is a closed set, so the whole space of retrievals is finite and can be enumerated — including the
failure nothing else surfaces: a query the author *permitted* that retrieves nothing.

**Refused by the linter:** a missing `provider`, a `query` without both `slot` and `rule` (an
unbounded question is an outbound channel), an undeclared query slot, two reads of one provider,
and a `read` inside a `foreach` — an attacker-chosen list length would multiply the outbound
queries.

---

### `foreach`

Gates **every element** of a runtime list against the same rule.

```yaml
- {id: p,  kind: propose, out: plan}          # e.g. ["restart","scale"]
- {id: fe, kind: foreach, in: plan, as: item}
- {id: apply, kind: sink, in: item, field: exec.action,
   sensitivity: authoritative, rule: action.allowed, actor: "policy:x"}
```

`in` is a slot holding a **JSON array of strings**; anything else is a fault. `as` names the slot
each element is bound to, freshly and untrusted, on every iteration.

- **One deny denies the batch.** The verdict is the AND of every element's.
- **At most 64 elements** — an author-unraisable kernel bound. A longer list faults.
- **At most one foreach per recipe**, and no nesting.
- **It is a tail construct**: it consumes the rest of the path.
- **No `invoke` or `await` inside it.** This is the one construct where an *attacker-chosen* list
  length would multiply author-written calls (64 elements × 3 invokes = 192 actions from one
  proposal). Everywhere else the count is fixed by the recipe source. Refused, not tuned.

`foreach` and `invoke` both fan out, and they answer different questions — see
[`invoke` vs `foreach`](#invoke-vs-foreach).

---

### `exit`

A terminal. Halts this path, adds no verdict, records no crossing.

```yaml
- {id: done, kind: exit}
```

Needed because steps fall through by default: without an `exit`, a branch target would run on
into whatever step happens to be written next.

## Verdicts

| Verdict | Meaning | Forwarded to the tool? |
| --- | --- | --- |
| `allow` | every crossing released | **yes** |
| `deny` | a crossing was refused | no |
| `escalate` | a gate deferred to a human (approval queue) | no (until approved) |
| `fault` | the recipe or call was malformed | no (fail closed) |

## The linter (why a recipe is safe by construction)

Before a recipe runs it must pass structural checks. **A policy that could leak is a rejected
file, not a runtime surprise** — and a rejected recipe is never hashed or compiled, so it cannot
be signed, routed, or referenced.

### Structure

- **declare-before-use** — a slot must be `propose`d before it is read, including inside an
  `invoke`'s `args`.
- **definite-assignment** — every value a sink reads is guaranteed to be bound on every path.
- **forward-only edges** — `goto` points forward; no cycles; the graph terminates.
- **unique ids** — no two steps share one.
- **unique fields** — no two authoritative sinks claim the same `field`; aliased fields collapse
  the event-to-crossing correspondence.
- **gate-protection** — the authoritative sinks a gate guards are reachable only *through* that
  gate.

### Dead policy

A rule that reads like a control but can never fire is rejected, because it is worse than no rule
at all — it tells a reviewer the value is bounded when it is not.

- an **unreferenced rule** in the registry
- a **rule on a `benign` sink** (release is never consulted there)
- an **`until` on an `invoke`** (an invoke is one call; there is nothing to poll)
- an **`actor` with no rule** on a sink

### Bounds an author cannot raise

These are the kernel's, mirrored into the linter so you are told at author time rather than at
runtime:

| bound | limit | why |
| --- | --- | --- |
| `foreach` elements | 64 | the list is attacker-chosen |
| `foreach` per recipe | 1, no nesting | nesting multiplies the fan-out |
| `invoke` + `await` steps | 16 | a sequence longer than a reviewer reads in one sitting is not reviewed |
| `await` attempts | 1–32 | wall-clock an agent can spend by triggering a sequence |
| `await` interval | 0–30 000 ms | as above |
| `await` total | attempts × interval ≤ 5 min | as above |
| `passthrough` args | 64 | |
| sub-recipe references | 64 | |

**Over the cap is a rejection, never a clamp.** An author who writes `attempts: 1000` believes
they will get 1000; silently substituting 32 would be a policy that does not do what it says.

### Refusals specific to sequences

- an **`invoke` or `await` inside a `foreach` body** — the one construct where an attacker-chosen
  list length would multiply author-written calls (and, for an await, the *waiting*).
- **two steps authorizing the same tool** — one action, one authorizing step.
- an **argument with no rule** — an argument nobody wrote a rule for is not thereby permitted.
- a **step-level `rule:` on an invoke** — rules belong to arguments, not to the step.

### YAML hygiene

The parser is deliberately strict about the *file*, not just the policy:

- **no anchors or aliases** — the rules registry is the only reuse mechanism
- **no custom tags**, no duplicate keys
- **no ambiguous YAML 1.1 scalars.** `yes`, `no`, `on`, `off`, `y`, `n` and friends must be
  quoted if you mean the strings. A slot named `n` is rejected, because another YAML reader would
  parse it as the boolean `false` and see a different policy than you wrote.
- **caps on size, depth and node count**

A recipe is a security document. Two files that look the same must mean the same thing, and a
clever YAML feature that makes them differ is a liability, not a convenience.

### Cautions (warn, do not block)

Some things are legal but worth a reviewer's attention, so the console and CLI surface them
without refusing the save:

- a `passthrough` argument that **looks authoritative** (`amount`, `to`, `path`, `cmd`, …)
- an `invoke` on a tool whose name **looks destructive** (`delete`, `purge`, `transfer`, …)

You may have a reason. The point is that it is written down and seen.

## Worked examples

**Hard deny** — deleting a namespace is never routine:

```yaml
recipe: k8s_delete_ns_policy
version: 1
rules:
  never: {kind: set_membership, set: ["__never__"]}
steps:
  - {id: propose_ns, kind: propose, out: ns}
  - {id: attempt, kind: sink, in: ns, field: k8s.delete_namespace,
     sensitivity: authoritative, rule: never, actor: "policy:platform"}
```

**Tiered by namespace** — dev/staging auto, prod escalates, everything else denied:

```yaml
recipe: k8s_restart_policy
version: 1
rules:
  ns.safe:  {kind: set_membership, set: ["dev", "staging"]}
  ns.prod:  {kind: set_membership, set: ["prod"]}
  ns.never: {kind: set_membership, set: ["__never__"]}
steps:
  - {id: propose_ns, kind: propose, out: ns}
  - id: route
    kind: branch
    in: ns
    cases:
      - {rule: ns.safe, goto: apply}      # dev/staging -> release
      - {rule: ns.prod, goto: escgate}    # prod        -> escalate
    default: block                         # else        -> deny
  - {id: apply,  kind: sink, in: ns, field: k8s.restart.apply,   sensitivity: authoritative, rule: ns.safe, actor: "policy:platform", goto: exit_ok}
  - {id: exit_ok, kind: exit}
  - {id: block,  kind: sink, in: ns, field: k8s.restart.blocked, sensitivity: authoritative, rule: ns.safe, actor: "policy:platform", goto: exit_deny}
  - {id: exit_deny, kind: exit}
  - {id: escgate, kind: gate, in: ns, rule: ns.never, on_fail: escalate}
  - {id: exit_esc, kind: exit}
```

## Sequencing several tools

An **`invoke`** step authorizes a tool call. One recipe can authorize several, so a policy
expresses a whole sequence — drain, then verify, then notify — with **no model anywhere in it**.

```yaml
recipe: drain_policy
version: 1
rules:
  ns.safe:   {kind: set_membership, set: ["dev", "staging"]}
  mode.safe: {kind: set_membership, set: ["graceful"]}
steps:
  - {id: p_ns,   kind: propose, out: ns}
  - {id: p_mode, kind: propose, out: mode}
  - {id: drain, kind: invoke, tool: k8s.drain,
     args: {node: {slot: ns,   rule: ns.safe},
            mode: {slot: mode, rule: mode.safe}}, actor: "policy:platform"}
  - {id: check, kind: invoke, tool: k8s.status,
     args: {node: {slot: ns, rule: ns.safe}}, actor: "policy:platform"}
```

**Every argument carries its own rule.** `args` maps an argument name to the slot that supplies
it and the rule that must clear it. This is required, not optional: an invoke's arguments are
usually different *kinds* of value — a target, an operation, a payload — and a single rule shared
across them could only be the union of what each may be. That union is a flat set of permitted
strings with no idea which argument it is looking at, so it would clear a payload sitting in the
target's slot. Per-argument rules make the policy state what it means, and the audit then records
*which rule cleared which argument*.

**Authorization and transport are separate.** The kernel performs no I/O. An `invoke` step
resolves its arguments from slots, clears each against its `rule` exactly as an authoritative
sink does — recording a crossing per argument — and emits an *authorized call*. A separate
executor carries it. So `Eval` stays a pure function of the recipe and the arguments, and an
auditor can replay an authorization offline and get the same answer.

**An authorized call is re-gated before it is made.** The executor puts every call back through
the gate against **that tool's own route and its own recipe**. Authorizing a call is not
authority to make it. A recipe that names `k8s.delete_namespace` in an `invoke` still meets that
tool's own hard-deny policy and stops there — a policy cannot launder an action by naming it.

**All-or-nothing per call, and per recipe.** One unreleased argument authorizes no call at all —
and no crossing is recorded for the arguments that *did* clear, because that call never happened.
A recipe that later denies, escalates or faults retracts *every* call it authorized: the executor
is handed nothing it may run.

**It halts; it does not roll back.** The sequence stops at the first call the gate refuses or
the transport cannot carry. Steps that already ran stay run, and the result names the step it
stopped on. StoaGraph does not claim a transaction it cannot provide over third-party tools.

### What the linter refuses

Every refusal in [the linter](#the-linter-why-a-recipe-is-safe-by-construction) applies, and
these are the ones specific to sequences: an undeclared argument slot, an argument with no rule,
a step-level `rule:`, two steps authorizing the same tool, more than 16 sequence steps, and an
`invoke` or `await` inside a `foreach` body.

Authorizing a destructive-looking tool (`delete`, `purge`, `transfer`, …) raises a **caution**,
not a rejection — same discipline as `passthrough`: the reviewer sees it, which is the point.

### `invoke` vs `foreach`

They both fan out, and they answer different questions:

| | `foreach` | `invoke` |
| --- | --- | --- |
| what varies | the **value** — one tool, N elements | the **tool** — N tools, named in the source |
| how many calls | **one** gated tool call, whose payload is a list | **N** calls, each with its own audit leaf |
| who picks the count | the agent (the list is untrusted; hence the cap) | the author (fixed at lint time) |

`foreach` asks *"is every value in this payload allowed?"*. `invoke` asks *"may this sequence of
actions run?"*.

### Waiting for a condition

An **`await`** step polls a tool until its output satisfies a rule, or until its attempts run
out. It is how a sequence says *do not proceed until this holds*:

```yaml
  - {id: settle, kind: await, tool: k8s__pods_on_node,
     args: {node: {slot: node, rule: node.worker}},
     until: pods.none, attempts: 6, every_ms: 5000, actor: "policy:drain"}
```

Without it, a verify step is a **witness, not a gate**: it runs, its output is recorded, and the
next step proceeds regardless. `await` is what turns "we looked" into "we did not continue until
it was true."

**The kernel does not poll.** An `await` authorizes a bounded poll — the tool, the arguments, the
condition, and the limits — and the executor performs it. `Eval` stays a pure function of the
recipe and the arguments.

**The bounds are the kernel's, and a recipe cannot raise them**: at most 32 attempts, at most 30s
between them, and at most 5 minutes of waiting in one step. `attempts × every_ms` is wall-clock an
agent can spend by triggering the sequence, so it is capped at both ends and in the product. A
recipe that asks for more is a **rejected file**, not a clamped value — an author who writes 1000
attempts believes they will get 1000.

**Every attempt re-crosses the gate** and consumes a crossing from the session budget. A poll is
not a licence to call a tool repeatedly unjudged, and a revocation mid-poll stops it.

**The output is read only to decide continue-or-halt.** It never becomes an argument to a later
call and never reaches a sink. A downstream's response is external untrusted content; letting it
parameterize a subsequent action would be a new injection path *into* the gate — the one component
that must stay uninfluenceable.

**Exhaustion halts**, like any other refusal: the steps that depend on the condition do not run,
and the record says the condition was never met (which is distinct from the tool having failed).

### Not in v1

- **branching on a result.** An invoke's arguments come from `propose` slots, never from an
  earlier call's response, and an `await` reads output only to decide continue-or-halt. The whole
  sequence is therefore knowable *before* anything runs — which is what lets a human review it.
  You can still `branch` to select *which* sequence is authorized.
- **compensating steps.** There is no declared undo. A denial mid-sequence halts and stops.

**Brief before you act** — the recipe chooses the source and bounds the question, so the model
gets exactly the context the author decided it needs:

```yaml
recipe: maint_with_brief
version: 1
rules:
  topic.allowed: {kind: set_membership, set: ["drain", "rollout"]}
  node.worker:   {kind: set_membership, set: ["kind-worker", "kind-worker2"]}
steps:
  - {id: p_topic, kind: propose, out: topic}
  - {id: p_node,  kind: propose, out: node}
  # the recipe reads; the model neither picked the source nor wrote the question
  - {id: brief, kind: read, provider: runbooks, query: {slot: topic, rule: topic.allowed}}
  - {id: act, kind: sink, in: node, field: k8s.maintenance,
     sensitivity: authoritative, rule: node.worker, actor: "policy:maint"}
```

If the node is refused, the runbook still comes back — the agent is told *why* it was refused,
not merely that it was.

**A maintenance sequence** — the order *is* the policy. Cordon, drain, wait for the node to
actually empty, then uncordon. Out of order this is not a mistake, it is an outage: drain before
cordon and the scheduler puts the evicted pods straight back onto the node you are about to work
on.

```yaml
recipe: k8s_drain_sequence
version: 1
rules:
  node.worker: {kind: set_membership, set: ["kind-worker", "kind-worker2"]}
  pods.none:   {kind: set_membership, set: ["none"]}
steps:
  - {id: p_node, kind: propose, out: node}

  # 1. stop new work landing on it
  - {id: cordon, kind: invoke, tool: k8s__cordon_node,
     args: {node: {slot: node, rule: node.worker}}, actor: "policy:maint"}

  # 2. evict what is there
  - {id: drain, kind: invoke, tool: k8s__drain_node,
     args: {node: {slot: node, rule: node.worker}}, actor: "policy:maint"}

  # 3. do NOT proceed until it is actually empty. As an `invoke` this step would be a
  #    witness — it would look, record what it saw, and uncordon regardless.
  - {id: verify, kind: await, tool: k8s__pods_on_node,
     args: {node: {slot: node, rule: node.worker}},
     until: pods.none, attempts: 6, every_ms: 5000, actor: "policy:maint"}

  # 4. end the maintenance window
  - {id: uncordon, kind: invoke, tool: k8s__uncordon_node,
     args: {node: {slot: node, rule: node.worker}}, actor: "policy:maint"}
```

A model may trigger this and choose *which node*. It cannot choose the steps, cannot reorder
them, and cannot reach `k8s__drain_node` on its own — those tools are bound as **sequenced**
routes, so they are never advertised and are unreachable without the one-shot grant this sequence
mints. If the node never empties, the sequence halts with it still cordoned: a half-finished
maintenance window someone must notice, which is the honest outcome. It is not safe to hand a
node back to the scheduler on the assumption that a drain worked.

## The coverage contract (`passthrough`)

**Every argument a tool takes must be accounted for: gated, or declared.** An argument that is
neither is *unaccounted for*, and the gate denies the call.

This is complete mediation finished at the argument level. Gating the arguments you listed says
nothing about the ones you didn't — and an unlisted argument is forwarded to the tool verbatim.
A policy that gates `to` on `wire_transfer(to, amount)` looks complete: the tool is routed, the
listed path clears, and *any* `amount` goes through.

So a recipe declares what it knowingly forwards ungated:

```yaml
recipe: notify_policy
version: 1
passthrough: ["text"]        # notify(channel, text): `text` is the body, forwarded ungated
rules:
  channel.allowed: {kind: set_membership, set: ["support", "general", "incidents"]}
steps:
  - {id: p_ch, kind: propose, out: channel}
  - {id: post, kind: sink, in: channel, field: notify.channel,
     sensitivity: authoritative, rule: channel.allowed, actor: "policy:notify"}
```

`passthrough` is **not** an escape hatch, it is a signature. Two things enforce it:

- **At bind**, the tool's own schema is checked against the policy. A schema argument that is
  neither gated nor declared means the tool is **not advertised** — it stays unrouted, and unrouted
  is denied. You cannot leave a hole you didn't know about.
- **At decide**, the arguments the agent *actually sent* are checked. A permissive schema (or one
  that simply lies) cannot smuggle an argument past the policy.

**It lives in the recipe, not the route, because it is part of the policy's identity.** Adding an
argument to `passthrough` changes the recipe's semantic hash, so the signed record can always tell a
gated argument from one that was waved through. A route-side declaration would leave two different
policies producing the same audit trail.

**Declaring an authoritative-looking argument (`amount`, `path`, `to`, `cmd`) raises a caution** in
the console and the CLI. It does not block the save — you may have a reason — but the reviewer sees
it, which is the entire point of writing it down.

**Honest scope:** this is an *integrity* control. It guarantees every argument that parameterizes an
action was judged, or knowingly wasn't. It is not a confidentiality control: a gated argument can
still carry information out within its allowed set, and a declared passthrough carries whatever the
model puts in it. Bounding *where* an action lands is not the same as bounding *what it says*.

## Multiple arguments, and human approval

- **Multi-argument gating** — route a tool to several arguments at once (e.g. `namespace,replicas`);
  each `propose out: X` binds the argument named `X`, so one recipe decides from the whole action
  (e.g. "scaling *prod* escalates regardless of the count"). A path may reach into the payload
  (`files[].path`), and every value it selects must clear. Anything you do not gate must appear in
  `passthrough` (above), or the call is denied.
- **Human approval** — a `signed_equality` gate whose `signed:` value is `"$approved"` escalates until
  a human approves; approval mints a signed release for that exact action, and the retried call passes.
  The approval fingerprint binds the **whole** action, including passthrough arguments — so a human
  approving a `scale_deployment` sees the `deployment` even when the policy does not gate it.
- **Conflict between two trusted sources** — when a workflow reads the same fact from two authoritative
  places and they disagree (a claim document says one account, the verified record says another), do
  not silently pick one. Gate the value with `on_fail: escalate` so the mismatch goes to a human with
  the full recorded action, rather than denying abruptly or trusting the wrong source. Escalate *is*
  the review path; there is no separate "conflict" verdict, and none is needed.

## Quick reference

Every form, with `<...>` placeholders. Not a runnable recipe — the ids repeat.

```text
recipe: <name>          # required; the id a tool is routed to
version: 1              # required
passthrough: [a, b]     # optional; arguments knowingly forwarded UNGATED
rules:                  # named predicates, referenced by id
  <id>: {kind: set_membership,  set: ["a", "b"]}
  <id>: {kind: numeric_range,   min: 0, max: 5}
  <id>: {kind: signed_equality, signed: "$approved"}
steps:
  - {id: <id>, kind: propose, out: <arg>}
  - {id: <id>, kind: gate,    in: <slot>, rule: <id>, on_fail: deny|escalate}
  - {id: <id>, kind: branch,  in: <slot>, cases: [{rule: <id>, goto: <id>}], default: <id>}
  - {id: <id>, kind: sink,    in: <slot>, field: <name>,
     sensitivity: authoritative|benign, rule: <id>, actor: "policy:<who>"}
  - {id: <id>, kind: invoke,  tool: <server>__<tool>,
     args: {<arg>: {slot: <slot>, rule: <id>}}, actor: "policy:<who>"}
  - {id: <id>, kind: await,   tool: <server>__<tool>,
     args: {<arg>: {slot: <slot>, rule: <id>}},
     until: <id>, attempts: 1..32, every_ms: 0..30000, actor: "policy:<who>"}
  - {id: <id>, kind: read,    provider: <name>, query: {slot: <slot>, rule: <id>}}
  - {id: <id>, kind: foreach, in: <slot>, as: <slot>}
  - {id: <id>, kind: exit}
```

**Choosing a step**

| you want to | use |
| --- | --- |
| accept an argument | `propose` |
| refuse the whole call unless a value is right | `gate` |
| do different things for different values | `branch` |
| let one value reach the tool, and record it | `sink` |
| run several tools in a fixed order | `invoke` × N |
| not proceed until something is true | `await` |
| fetch context, choosing the source and bounding the question | `read` |
| check every element of a list the agent sent | `foreach` |
| stop this path | `exit` |

## Tips

- YAML 1.1 gotcha: a bare slot named `n`, `y`, or `no` parses as a boolean — quote it or rename it
  (e.g. use `replicas`, not `n`).
- Prefer explicit `exit` nodes per branch — it makes the graph (and the linter) unambiguous.
- Validate a draft before routing it: `POST /api/recipes` returns `{valid, error}`; the console shows
  the linter result live.
