# AGENTS.md — orientation for AI agents working in this repo

**StoaGraph**: verifiable control for AI agents. An agent proposes; a deterministic gate disposes, with
no model in the decision path. This repo is the whole product, Apache-2.0, with no held-back edition.
New here as a human? Start with [README.md](README.md); the threat model is [SECURITY.md](SECURITY.md).

## After "get context": where to go next

Having read this file you have the shape. Offer the operator these, and say which you would pick:

| ask for | you will get |
| --- | --- |
| **basic concepts** | propose/dispose, the four things a policy can do, and why the split is the product — this file plus [doctrine](docs/doctrine.md) |
| **advanced concepts** | sequences and ordering-as-policy, one-shot grants, the read channel, the leakage bound — [doctrine](docs/doctrine.md) tenets 11-15 and [recipe authoring](docs/recipe-authoring.md) |
| **review docs** | a coverage pass: what each page claims, and whether the code still does it |
| **browse code index** | `tools/find.sh <keywords>` and `INDEX.md` — the keyword index, not grep |
| **the threat model** | [SECURITY.md](SECURITY.md), non-goals read as carefully as guarantees |
| **write a policy** | [recipe authoring](docs/recipe-authoring.md), then [routes](docs/routes.md) to bind it |
| **run it** | `tools/up.sh`, then [examples/custom-tool/](examples/custom-tool/) — about five minutes |
| **what is untested** | say so plainly; do not infer coverage from a passing suite |

If the operator has not said what they are doing, ask. "Adding a step kind", "debugging a denial"
and "reviewing the threat model" want different starting points, and guessing wastes a turn.

## The one thing to hold

Two processes, and the split IS the product:

- **`stag`** is the GATE: the deterministic kernel, the MCP gating proxy, policy, audit, and approvals.
  It holds NO model and NO API keys.
- **`harness`** is the ORCHESTRATOR: the dispatcher, the agent loop, and the model connections. It holds
  the keys.

The dependency runs ONE WAY: `harness -> stag`, never the reverse. This is enforced, not intended.
`stoa-kernel/architecture_test.go` fails the build if any gate package, or either gate binary, imports
orchestrator code. If that test is red, the product's central claim (the gate cannot reach your keys) is
false and the build must not ship. Do not weaken it to make something compile.

## The load-bearing invariant

No untrusted value reaches an authoritative sink without BOTH a gate verdict AND a recorded ReleaseEvent.
A path that violates this is a product-defining bug, not a mere test failure. Trust classes are an
ordered scalar (untrusted < caller < authoritative) compared at the sink; there is no taint propagation
through the model. Every proposal is presumed untrusted and its trust is re-derived at the sink from the
policy rule that fires.

## The four things a policy can do

A recipe is a small graph a proposed call walks to a verdict. It has nine step kinds
([the language reference](docs/recipe-authoring.md)), and they do four distinct jobs:

- **judge one call** — `propose`, `gate`, `branch`, `sink`. The original shape: an argument is
  released to the tool iff a rule clears it, and the same step records the crossing.
- **authorize a sequence** — `invoke`. Several calls in a fixed order, no model choosing the order.
  The kernel performs NO I/O: it authorizes, and an executor carries each call back through the gate
  against that tool's OWN route and recipe. Authorizing a call is never authority to make it.
- **wait for the world** — `await`. Poll until a tool's output satisfies a rule. Without it a verify
  step is a witness, not a gate: it looks, records, and the next step proceeds regardless.
- **fetch context** — `read`. The recipe names the source and gates the QUERY, so the policy bounds
  what may be asked, not only what may be read back. A read is label+record, never allow/deny.

Three bounds are the kernel's and an author cannot raise them: 64 `foreach` elements, 16 sequence
steps, and an `await`'s attempts x interval. Over the cap is a REJECTED RECIPE, never a clamp.

## Two authorizations, both required

A **sequenced** route is not advertised to the agent and is unreachable without a one-shot **grant**
the executor mints immediately before the call it authorizes. Hiding is a convenience; the grant is
the enforcement — guessing the name is denied AND recorded.

A grant is the same primitive as a human approval: bound to `Fingerprint(tool, args)`, spent on use,
replay refused. It carries the session and the run that minted it, so one agent cannot spend another's
and two concurrent sequences do not collide. A grant that outlived its sequence would be a standing
authorization; sweeping is scoped to the run for that reason.

Approvals are the same shape with a person as the minter. Only a `gate` produces an Escalate verdict —
a `$approved` rule anywhere else is a DENY, which blocks the action and asks nobody.

## Layout

```
stoa-kernel/   one Go module, the whole backend
  stag/        the GATE         (kernel, policy, proxy, auth, audit, approvals)
  harness/     the ORCHESTRATOR (dispatch, agent loop, models)
  cmd/         stag-serve, stag-proxy, harness-serve, stag-tools, stoagraph, harness, healthcheck
  architecture_test.go   the one-way-dependency guard
config/        event map + model config        data/  runtime state (gitignored)
docs/          doctrine, context-binding, recipe authoring, routes, the MCP proxy, docker, development
examples/      custom-tool (start here), local-tools, oauth-profiles
tools/         build, up, down, check, hygiene, sbom, find, index
```

## Finding your way

```bash
tools/find.sh escalation approval    # the keyword index — NOT grep. Start here.
```

Every source file carries a `// file-kw:` marker and every notable symbol a `// kw:`; `INDEX.md` and
`.index/code.json` are generated from them. `find.sh` searches those markers, so it answers "where is
the code that does X" rather than "where does this string appear".

| you want | read |
| --- | --- |
| why the product exists, and its tenets | [docs/doctrine.md](docs/doctrine.md) |
| the threat model and the NON-goals | [SECURITY.md](SECURITY.md) |
| the policy language, every step kind | [docs/recipe-authoring.md](docs/recipe-authoring.md) |
| binding a tool to a policy | [docs/routes.md](docs/routes.md) |
| how untrusted context is positioned | [docs/context-binding.md](docs/context-binding.md) |
| what a session is (a grant, not a connection) | [docs/sessions.md](docs/sessions.md) |
| how the gate speaks MCP | [docs/mcp-gating-proxy.md](docs/mcp-gating-proxy.md) |
| how a sequence executes, and why a wired-up scenario still halts | [docs/dispatch-internals.md](docs/dispatch-internals.md) |
| layout, ports, running from source | [docs/development.md](docs/development.md) |

## Working here

```bash
tools/build.sh      # build every binary into stoa-kernel/bin/
tools/up.sh         # run the whole product locally
tools/check.sh      # gofmt, vet, test, ARCHITECTURE, typecheck, index, hygiene (run before every commit)
tools/find.sh <kw>  # keyword code index, not grep
```

- Run Go commands from `stoa-kernel/` (`go build ./...`, `go test ./...`, `go vet ./...`).
- Every source file carries a `// file-kw:` marker that feeds `tools/find.sh` and `INDEX.md`; add one to
  any new file or `tools/check.sh` fails. `INDEX.md` is generated: do not hand-edit it, run `tools/index.sh`.

## Changing the gate

Some rules here are not preferences.

- **Never weaken `architecture_test.go` to make something compile.** If the gate imports orchestrator
  code the product's central claim is false, and the build must not ship.
- **A new step kind, rule kind or verdict is a closed set being widened.** The sets are closed so
  "what exactly does this allow" has an answer. Widening one is a design decision, not a refactor.
- **A bound the kernel owns stays the kernel's.** `foreachCap`, the invoke cap, the await bounds and
  the read bounds exist because the alternative is a value an author or an attacker can raise.
- **Over a cap is a rejection, not a clamp.** An author who writes `attempts: 1000` believes they will
  get 1000; silently giving them 32 is a policy that does not do what it says.
- **Fail closed, and never fail open on absent machinery.** A nil store means unreachable, not
  unguarded. A parse error is not a grant.
- **Concurrency on ONE session is a test, every time grants change.** Two collisions have already
  been found there — a sweep that cut down a concurrent run, and two runs sharing a fingerprint.
- **Run it.** Four of the last five bugs were invisible to unit tests and appeared only against live
  Docker and Kubernetes: an await that polled once, grants colliding, an approval loop that could not
  see the new step kinds, a halt that leaked a grant.

## Style

Plain and grounded, no hype. Verify, do not assert: build- and run-verify, and show the evidence;
"compiles" is not "behavior-correct." State the honest ceiling. The product's credibility rests on not
over-claiming, so read the non-goals in [SECURITY.md](SECURITY.md) as carefully as the guarantees.
