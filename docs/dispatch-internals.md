# Dispatch internals — how a recipe's sequence actually executes

[recipe-authoring.md](recipe-authoring.md) covers what a recipe means. [routes.md](routes.md) covers
what a route binds. [sessions.md](sessions.md) covers what a session grants. This document covers the
**seams between them**: what happens between an agent calling a trigger tool and a recipe's `invoke`
steps reaching a downstream server, and the invariants the three surfaces must jointly satisfy.

Every requirement here is load-bearing, and the failure mode when one is violated is silent — routes
still report `valid:true`, recipes still parse, and nothing logs a warning. The scenario simply
halts at runtime, or worse, appears to work while enforcing nothing.

`tools/audit_wiring.py` in a deployed instance checks the invariants in this document mechanically.

---

## The execution path

An agent calls one tool. Depending on the recipe bound to that tool's route, one of two things
happens.

**An ordinary call.** `Gate.Decide` (`stag/proxy/proxy.go`) resolves the route, evaluates the
recipe, and forwards the call downstream iff the verdict is Allow.

**A sequence.** If the recipe has `invoke`/`await` steps, evaluation produces `Decision.Authorized`
— an ordered list of `AuthorizedCall`s. The kernel performs **no I/O**: it decides, it does not
call. The tool the agent called is a *trigger* and is **not forwarded** downstream. Instead
`executeAuthorized` (`stag/proxy/mcpgate/mcpgate.go`) walks the authorized list, and for each entry:

1. reserves a crossing from the session budget,
2. **mints a one-shot grant** keyed to `(fingerprint(tool, args), run)`, owned by this session,
3. **re-crosses `Gate.Decide`** for that sub-call — against the sub-tool's *own* route and *own*
   recipe,
4. looks up the route with `gate.Routes[c.Tool]`, resolves the live downstream connection via
   `fleet.Lookup(route.Server, route.Tool)`, and calls the tool under its downstream name
   `route.Tool` — a route whose server is not connected halts the sequence here, a distinct cause
   from anything the gate decided,
5. for an `await`, treats step 4's call as the first attempt and then polls: each *subsequent*
   attempt sleeps, re-reserves a crossing, re-mints the grant, and re-crosses `Gate.Decide` (which
   records its own leaf), until the output satisfies `until` or the authorized attempts run out.

When the sequence ends — completed or halted — any unspent grant from that run is swept.

> Only `sd.Forward` and `sd.Verdict` are read from the re-crossing (`mcpgate.go`) — `sd.Authorized`
> is never touched, so a sub-decision that itself carries an authorized plan has that plan
> **silently discarded** and the sub-call is simply forwarded. Sequences do not nest; see invariant
> 1 for why this matters. `sd.RuleFault` is not rendered into the sequence report either, which is
> why a sub-call denial inside a sequence shows only a bare verdict.

Two consequences follow from step 3, and they are the source of most wiring defects:

- The re-crossing evaluates the **sub-tool's route recipe**, not the orchestrating recipe. A plan's
  clearance is never the target's clearance; a policy cannot launder an action by naming it.
- The re-crossing carries **only that sub-call's own arguments**. It does not inherit the trigger
  call's proposed slots.

**Halt, no rollback.** The first refusal or downstream error stops the sequence. Earlier steps stay
done. The result reports which steps were made and where it stopped, because an agent that cannot
see a partial execution will retry one, and a retry of a half-done sequence is worse than the halt.

---

## Where a session's routes come from

In daemon mode the agent gets **only** the routes bound into its session (`POST /sessions`). For
event-driven dispatch, `governedRun` (`cmd/harness-serve/dispatch.go`) builds that set from the
matching `event_map.json` entry as the **union** of two lookups (`harness/dispatch/wiring.go`):

- `RoutesForRecipe(entry.recipe)` — every route whose `recipe` field equals that name.
- `RoutesForTools(entry.tools)` — every route matching a listed tool, by bare name or by the
  qualified `server__tool` form.

Deduplicated by `(server, tool)`; recipe-sourced routes take precedence on conflict.

**Both lookups silently drop invalid routes.** `valid` is not stored — it is recomputed per request
as whether the bound recipe resolves (loads, parses, and passes the linter). A broken recipe
therefore removes its tools from every session that would have bound them. If *some* routes survive,
the bind succeeds and the sequence halts later at the first missing tool; if *none* do, `Bind`
fails outright with `no routes to bind`. Check `GET /api/routes` for `valid:false` before debugging
either.

`RoutesForRecipe` matches on the route's `recipe` field — **not** on which tools a recipe invokes. A
tool invoked by recipe `R` but routed to a different recipe is *not* returned by
`RoutesForRecipe(R)`, and must therefore be listed in `tools[]`. This is the most common wiring
defect, and it interacts directly with the next section.

> **Warning.** Every struct that copies a route must carry `Sequenced`, and the compiler will not
> tell you when one does not. It is a `bool` whose zero value *disables* the control: drop it, and a
> grant-only route silently becomes an ordinary advertised one — visible in `tools/list`, directly
> callable, still reporting `valid:true`, with no error anywhere.
>
> This has been introduced independently in four places: `RouteSpec` on the dispatcher path (which
> also omitted the struct field, so `sessiond` — which trusts the POST body and does not re-derive
> from `config.db` — received `false` for every bound route), and the `router.Spec` literals in the
> stdio gate and in `stag-serve`'s live gate. No path is inherently safe; each one copies the route
> field by field. `stag/router/sequenced_guard_test.go` fails the build on any `router.Spec` literal
> that copies a route without it.

---

## Sequenced routes and the two reachability surfaces

`sequenced` decouples two things an ordinary route couples:

|                        | advertised in `tools/list` | reachable by the model | reachable by `executeAuthorized` |
|------------------------|---------------------------|------------------------|----------------------------------|
| `sequenced: false`     | yes                       | yes                    | yes                              |
| `sequenced: true`      | **no**                    | **no** (denied)        | yes, via a live grant            |
| not bound in session   | no                        | no — denied, unrouted   | **no** — sequence halts       |

Advertisement is filtered on `!rt.Sequenced` (`mcpgate.go`). Reachability is checked *before* the
recipe is consulted (`proxy.go`): a sequenced route with no live grant is denied outright, so an
agent that guesses the name is refused and recorded.

The distinction that matters: **listing a tool in an event map's `tools[]` makes it reachable by the
executor, not by the model** — provided it is sequenced. Binding widens what the sequence can reach
downstream; it does not widen what the agent can call.

> **Warning.** That guarantee holds *only* for `sequenced: true`. A mutating tool listed in
> `tools[]` with `sequenced: false` is advertised and directly callable by the model, in any order,
> with no obligation to complete the arc. Sequence every tool that changes state; the exceptions
> should be deliberate and few (trigger tools, which must be advertised, and genuinely agent-driven
> edit surfaces gated per-argument instead).

---

## The four wiring invariants

### 1. A sub-tool's route must not point at the recipe that invokes it

The re-crossing re-evaluates the sub-tool's route recipe from scratch with only that call's own
arguments. A `propose` always binds: an argument the sub-call does not send binds the **empty
string** rather than leaving the slot absent (`stag/stag.go`). So pointing a sub-tool's route at its
orchestrating recipe re-runs that whole recipe with `""` standing in for every slot the sub-call
does not supply, and the outcome depends on what those slots feed. **Both outcomes are defects:**

- **`""` reaches something that can deny** — an authoritative sink or a `gate`. The sub-call is
  denied even with a valid grant, and the sequence halts. `Decision.Fault` is empty here (a rule
  denial sets `RuleFault` instead, and `DecisionRecord` has no `RuleFault` field), so the audit leaf
  carries a deny with no fault text. Worse, `RuleFault` is frequently empty too: an `invoke`/`await`
  argument-rule failure records its outcome with no argument name or rule id, and `firstRuleFault`
  returns on the *first* denying outcome — so it yields `""` and never reaches a later real sink
  that would have named the culprit. Most live misroutes deny with **both** fields blank.
- **Nothing that can deny is reached** — every proposed slot is either supplied with a value that
  clears its rule, or feeds only a construct that cannot deny: a `read` (a failed query rule drops
  the read and does not affect the verdict) or a benign sink (which cannot carry a rule at all — the
  linter rejects one as dead policy). The re-crossing then **allows and forwards**, and since
  `sd.Authorized` is never read, the nested plan that re-evaluation authorized is silently
  discarded.

`k8s_drain_sequence` is the second shape in the live instance: it proposes only `node`, and
`cordon_node`, `drain_node` and `uncordon_node` all gate `node`, so a misroute re-binds the slot from
the sub-call's own argument and returns `verdict=allow` with four authorized calls thrown away.

Matching slot names is necessary but not sufficient — the forwarded *value* must also clear the
orchestrating recipe's rule. Here `node` must be in `{kind-worker, kind-worker2}`; a sub-call
carrying `kind-control-plane` denies instead. Which branch a given misroute takes therefore depends
on runtime values, not on the wiring alone.

> **Warning.** Do not rely on the deny to catch a misroute. The failure is conditional, and the
> condition under which it *passes* is the more dangerous one — a sequence whose ordering is
> supposed to be policy silently degrades into a single forwarded call.

Sub-tools get their own self-contained recipe that proposes **exactly what the sub-call supplies and
nothing more**: one `propose`/`sink` pair per gated argument for a route with a `gateArg`
(`gateArg: "key,value"` needs both slots proposed — see `k8s_config_policy`), and a single
`propose`/`sink` pair for a route with an empty `gateArg`, where the route itself is the
authorization and the pair exists so the recipe can still run and still deny.

```yaml
# k8s_rollout_policy — the shape a sequenced sub-tool's route should point at
recipe: k8s_rollout_policy
version: 1
steps:
  - {id: p, kind: propose, out: v}
  - {id: s, kind: sink, in: v, field: k8s.rollout, sensitivity: benign}
```

Correct: `k8s_config_change` invokes `k8s__set_config`, whose route points at `k8s_config_policy`.
Wrong: routing `k8s__set_config` back at `k8s_config_change`.

### 2. Every tool a recipe invokes must be bound in the session

`executeAuthorized` resolves the downstream server via `gate.Routes[c.Tool]`, which contains only
the session's routes. A tool named by an `invoke`/`await` that is neither routed to the recipe nor
listed in `tools[]` halts the sequence at that step.

Note where the diagnostic goes. `Gate.Decide` sets `Fault` to `no recipe for tool <X>` and
`g.record` sends it to the **audit sink**; the gate-decision line of the sequence report prints only
`sd.Verdict` — `  <step>  <tool>  NOT MADE (deny)`. An unbound tool and a policy denial render
*identically* there, so within a sequence, `decisions.jsonl` is what distinguishes them.

Other report lines do carry detail: a crossing-budget overflow prints its `Fault`, and a
`fleet.Lookup` miss or a downstream error prints as `FAILED (...)` with the underlying message — so
"the report shows only a verdict" holds for the gate-refusal line specifically, not the whole
report. A **direct** refusal to the agent is also more informative than the in-sequence case: it
renders `stag gate: deny — "<tool>" not forwarded`, appends `(<ruleFault>)` when a rule was the
cause, and carries `verdict`/`tool`/`ruleFault` in `_meta.stag`.

Note the interaction with invariant 1: satisfying it means sub-tools are routed to *other* recipes,
which means `RoutesForRecipe` will not return them, which means they **must** appear in `tools[]`.
The two invariants together determine the wiring — neither alone is sufficient.

### 3. One `invoke`/`await` per tool per recipe

The linter rejects a recipe naming the same tool in more than one `invoke`/`await` step: *"tool %q
is authorized by more than one invoke"* (`stag/recipe/recipe.go`). One action, one authorizing step,
so no action is claimed by two.

A sequence needing the same underlying operation twice with different arguments needs **two distinct
tools**, not one tool invoked twice. A pair of thin no-argument wrappers around one script is the
usual answer, and has a second benefit: the argument is fixed by the tool rather than proposed, so
the model chooses nothing.

### 4. A sequenced route needs some recipe to invoke it

Sequenced means unadvertised *and* grant-only, and only an `invoke`/`await` mints a grant. A
sequenced route no recipe names is unreachable by every path — permanently dead, while still
reporting `valid:true`.

> **Warning.** This is how a scenario's mutating tool goes missing without anything failing. A
> recipe whose header prose describes an arc its `steps:` do not implement will diagnose and stop:
> the mutation never runs, the sink still reports authoritative, and the transcript reads like a
> completed remediation. **Read every recipe's steps against its header.** Comments are not
> enforcement; only steps the gate walks are.

---

## Writing tools for sequences

**Arguments to an `invoke` are `{slot, rule}` mappings, never literals.** Every argument carries its
own rule; a step-level `rule:` is refused. A value that should be fixed rather than chosen belongs
in the tool, not in the step:

```yaml
# rejected — invoke args must bind a slot and a rule
- {id: scale_up, kind: invoke, tool: k8s__scale_workload, args: {replicas: "4"}}

# accepted — the value is fixed inside scale_up.sh, so there is no argument to gate
- {id: scale_up, kind: invoke, tool: k8s__scale_up, actor: "policy:fix"}
```

**`await` needs an exact control value.** Rules are exact-match only — `set_membership`,
`signed_equality`, `numeric_range`. There is no substring or pattern predicate, so a tool whose
output is a human-readable diagnostic report cannot be awaited on. A tool intended for `await` must
emit one value from a small closed set, and nothing else.

**Report three states, not two.** `complete` / `progressing` / `failed`, or
`reachable` / `blocked` / `unknown`. "Could not determine" must be its own value and must not
release: an await that reads it as failure spins until it times out, and one that reads it as
success reports a fix on no evidence.

**Keep the value classes separate.** A recipe shared by routes that gate *different kinds* of value
will judge one against the other's rule and deny it. Two routes gating `tag` cannot share a recipe
whose only rule enumerates base images. Route topology can be entirely correct while the value
classes are incompatible — the route reports `valid:true` and the call is denied at the re-crossing.

**Size `await` bounds to the real worst case.** The first attempt fires immediately (it is the
invoke's own call) and the executor sleeps only *between* attempts, so the wall-clock ceiling is
`(attempts − 1) × every_ms`, not `attempts × every_ms`. That budget must exceed how long the
condition legitimately takes, or the await exhausts while the operation is still succeeding and
halts a sequence that was about to complete. The kernel's ceilings are author-unraisable
(`stag/stag.go`): 32 attempts, 30 s per poll, 5 minutes total per step. A workload with a 60 s
readiness probe rolling pods one at a time needs bounds measured against *that*, not a default.

---

## Operational notes

Several caches are point-in-time snapshots. After changing a tool surface:

1. Restart the `stag-tools` process serving that config — it reads `tools.yaml` at startup.
2. Re-`POST` the server to `/api/mcp-servers` — tool discovery is a snapshot taken at registration.
   Registering a route for an undiscovered tool is then refused with
   `server X does not expose a tool named Y` (unquoted identifiers). Note the check is guarded on
   the server having a non-empty tool list: if discovery never ran, **any** tool name is accepted,
   so a route can be created for a tool that does not exist.
3. Restart `stag-proxy` — its downstream connection and tool list are established at process start.

Omitting step 3 produces bind errors for tools that steps 1 and 2 clearly succeeded in adding.

A route's recipe binding, its `gateArg`, and its `sequenced` flag are **data** in `config.db`, not
properties derived from recipe YAML. Adding an `invoke` step to a recipe does not create or change a
route. Prefer `POST /api/routes` over writing the table directly: it checks that the named server
exposes the tool, and refuses an *empty* `gateArg` for a tool whose schema shows it takes arguments.
It does **not** syntax-check a non-empty `gateArg` — a path naming a slot the recipe never proposes,
or a malformed path, is accepted and fails only at call time. (No recipe hash is stored on the
route; the `route` table is exactly `tool_name, server_name, recipe_name, gate_arg, sequenced`, and
hashes are computed at evaluation.)

**A trigger tool's `gateArg` must name every slot its recipe proposes** — whatever consumes it
downstream: a sink, an `invoke`/`await` argument rule, a `read` query, or a `branch`. The trigger
call is the only place those values enter, and a proposed slot the call does not supply binds `""`.

Whether that `""` denies depends on what judges it: an authoritative sink or a `gate` denies, and
the sequence is refused before any step runs; a `read` query rule merely drops the read; a benign
sink cannot deny at all. So an under-specified `gateArg` may fail loudly, or may quietly strip the
recipe's context reads while still reporting success.

Two further requirements apply to the same call:

- **The tool must declare every argument**, or the agent cannot send it.
- **Every argument the agent sends must be accounted for** — gated by a `gateArg` path or declared
  passthrough. `coverage()` denies a call carrying an argument that is neither
  (`argument %q is neither gated nor declared passthrough`), so adding an argument to a tool without
  adding it to the route's `gateArg` denies every call to it.

So a recipe proposing `name` and `topic` needs `gateArg: "name,topic"`, a tool declaring both, and
no third argument the route does not account for.

---

## See also

- [recipe-authoring.md](recipe-authoring.md) — node kinds, rules, the linter
- [routes.md](routes.md) — route fields, `gateArg` paths, sequenced routes
- [sessions.md](sessions.md) — bind-time tool surface, grants, revocation
- [mcp-gating-proxy.md](mcp-gating-proxy.md) — the wire protocol, refusals, a sequence over MCP
