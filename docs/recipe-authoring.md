# Writing recipes

A **recipe** is a stag policy: a small, closed graph that a proposed tool call walks through to a
verdict. It is authored in YAML, validated by a linter, and executed by a deterministic kernel — no
model, no I/O. Same recipe + same call → same verdict, always.

## The mental model

A tool call arrives as a set of named **arguments** (e.g. `namespace`, `replicas`). A recipe:

1. **proposes** those arguments as **untrusted** values (they came from the agent — you never trust them),
2. optionally **branches** on them and **gates** them against rules, and
3. **sinks** them: an *authoritative* sink is the moment a value would actually reach the real tool.

The load-bearing invariant: **no untrusted value reaches an authoritative sink without a rule release
and a recorded crossing.** Everything below serves that guarantee.

The verdict of the whole recipe is the AND of its steps: **allow** only if every crossing was
released; otherwise **deny**, **escalate**, or **fault**.

## Anatomy

```yaml
recipe: my_policy       # name (also the id you route tools to)
version: 1
rules:                  # named, reusable predicates
  ns.safe: {kind: set_membership, set: ["dev", "staging"]}
  count.ok: {kind: numeric_range, min: 0, max: 5}
steps:                  # the graph, top to bottom
  - {id: propose_ns,   kind: propose, out: namespace}
  - {id: propose_n,    kind: propose, out: replicas}
  - {id: apply, kind: sink, in: replicas, field: k8s.scale.apply,
     sensitivity: authoritative, rule: count.ok, actor: "policy:platform"}
```

## Rules — the three closed predicates

A rule decides whether a value is **released**. There are exactly three kinds (a closed set keeps the
policy language auditable):

| Kind | Passes when | Example |
| --- | --- | --- |
| `set_membership` | the value is one of a fixed set | `{kind: set_membership, set: ["dev", "staging"]}` |
| `numeric_range` | the value is an **integer** in `[min, max]` (canonical form only) | `{kind: numeric_range, min: 0, max: 5}` |
| `signed_equality` | the value byte-equals a pinned/approved value | `{kind: signed_equality, signed: "$approved"}` |

To DENY everything, use an unsatisfiable set: `{kind: set_membership, set: ["__never__"]}`.

> **`numeric_range` is integer-only, on purpose.** It requires canonical integer form (the accepted
> set stays finite and enumerable, invariant 6), so a decimal like `45.50` does not pass and is
> denied. It cannot express a money range (`0.00–10000.00`). For a monetary or otherwise-decimal
> value, gate by equality to the authoritative amount (below), or express the range in integer minor
> units (cents) if a range is truly what you need.

> **A range is not integrity for a value the attacker can set.** If an attacker who has poisoned the
> context can choose *any* value inside your range, the range does not protect the action — it just
> bounds how bad the chosen value is. A refund `amount` gated `numeric_range {0, 10000}` still lets a
> hijacked call send €9,999. Gate a value the attacker controls by **equality to the authoritative
> source** (`set_membership` over the one verified value, or `signed_equality` against a signed
> fact), not by a range, unless the range itself is the whole policy. This was found by replaying an
> external red-team suite against the gate; see the project transcripts.

## Steps — the seven node kinds

The graph is built from a closed set of node kinds. Edges are **forward-only** (a `goto` always
points to a later step), so a recipe is a DAG that always terminates.

- **`propose`** — bind a tool argument as an untrusted value.
  `{id: p, kind: propose, out: <slot>}`  (`out` is the argument name)
- **`branch`** — route on a value; first matching case wins, else `default`.
  ```yaml
  {id: route, kind: branch, in: namespace,
   cases: [{rule: ns.safe, goto: apply}, {rule: ns.prod, goto: escalate_gate}],
   default: deny_sink}
  ```
- **`gate`** — guard the steps that follow. If the value fails `rule`, the recipe stops with
  `on_fail`.
  `{id: g, kind: gate, in: namespace, rule: never, on_fail: escalate}`  (`on_fail`: `escalate` | `deny`)
- **`sink`** — the crossing. `sensitivity: authoritative` is a real release to the tool (releases only
  if `rule` passes; records a crossing); `benign` is a non-authoritative read.
  `{id: apply, kind: sink, in: replicas, field: k8s.scale.apply, sensitivity: authoritative, rule: count.ok, actor: "policy:platform", goto: done}`
- **`exit`** — a terminal node. `{id: done, kind: exit}`
- **`foreach`** — iterate a body over elements (advanced; see the composed examples).
- **`invoke`** — authorize a tool call. See [Sequencing several tools](#sequencing-several-tools).

## Verdicts

| Verdict | Meaning | Forwarded to the tool? |
| --- | --- | --- |
| `allow` | every crossing released | **yes** |
| `deny` | a crossing was refused | no |
| `escalate` | a gate deferred to a human (approval queue) | no (until approved) |
| `fault` | the recipe or call was malformed | no (fail closed) |

## The linter (why a recipe is safe by construction)

Before a recipe runs, it must pass structural checks — a policy that could leak is a **rejected
recipe**, not a runtime surprise:

- **declare-before-use** — a slot must be `propose`d before it is read.
- **definite-assignment** — every value a sink reads is guaranteed to be bound on every path.
- **forward-only edges** — `goto` points forward; no cycles; the graph terminates.
- **unique fields** — no two authoritative sinks claim the same field.
- **gate-protection** — the authoritative sinks a gate guards are only reachable *through* that gate.

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
  ns.safe: {kind: set_membership, set: ["dev", "staging"]}
steps:
  - {id: p, kind: propose, out: ns}
  - {id: drain, kind: invoke, tool: k8s.drain,  args: {node: ns}, rule: ns.safe, actor: "policy:platform"}
  - {id: check, kind: invoke, tool: k8s.status, args: {node: ns}, rule: ns.safe, actor: "policy:platform"}
```

**Authorization and transport are separate.** The kernel performs no I/O. An `invoke` step
resolves its arguments from slots, clears each against its `rule` exactly as an authoritative
sink does — recording a crossing per argument — and emits an *authorized call*. A separate
executor carries it. So `Eval` stays a pure function of the recipe and the arguments, and an
auditor can replay an authorization offline and get the same answer.

**An authorized call is re-gated before it is made.** The executor puts every call back through
the gate against **that tool's own route and its own recipe**. Authorizing a call is not
authority to make it. A recipe that names `k8s.delete_namespace` in an `invoke` still meets that
tool's own hard-deny policy and stops there — a policy cannot launder an action by naming it.

**All-or-nothing per call, and per recipe.** One unreleased argument authorizes no call at all,
and a recipe that later denies, escalates or faults retracts *every* call it authorized: the
executor is handed nothing it may run.

**It halts; it does not roll back.** The sequence stops at the first call the gate refuses or
the transport cannot carry. Steps that already ran stay run, and the result names the step it
stopped on. StoaGraph does not claim a transaction it cannot provide over third-party tools.

### What the linter refuses

- **an undeclared argument slot** — declare-before-use reaches inside `args:`.
- **two invokes naming the same tool** — one action, one authorizing step.
- **more than 16 invokes** — a sequence longer than a reviewer reads in one sitting is not a
  reviewed sequence.
- **an invoke inside a `foreach` body** — this is the one construct where an *attacker-chosen*
  list length would multiply author-written calls (64 elements × 3 invokes = 192 actions from one
  proposal). Everywhere else the count is fixed by the recipe source. Refused, not tuned.

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

### Not in v1

- **branching on a result.** An invoke's arguments come from `propose` slots, never from an
  earlier call's response. The whole sequence is therefore knowable *before* anything runs — which
  is what lets a human review it. You can still `branch` to select *which* sequence is authorized.
- **compensating steps.** There is no declared undo. A denial mid-sequence halts and stops.

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

## Tips

- YAML 1.1 gotcha: a bare slot named `n`, `y`, or `no` parses as a boolean — quote it or rename it
  (e.g. use `replicas`, not `n`).
- Prefer explicit `exit` nodes per branch — it makes the graph (and the linter) unambiguous.
- Validate a draft before routing it: `POST /api/recipes` returns `{valid, error}`; the console shows
  the linter result live.
