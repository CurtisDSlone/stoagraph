# StoaGraph

A deterministic gate for autonomous agents that act on real systems.

## The problem

An event fires: an alert, a webhook, a ticket. An agent picks it up. It reads context, decides what to do, and calls tools that change production. The model is choosing which tool to call, with what arguments, in what order. If the model is wrong, or manipulated, the tool call still happens.

## What StoaGraph does

StoaGraph sits between the agent and everything it can touch. The model proposes. The gate decides.

What the agent may call, with which arguments, in what order, is written down before the run, in a recipe. The gate checks every call against that recipe. Same call, same recipe, same answer, every time. There is no model inside the gate.

The model can influence which allowed action happens. It cannot add an action that was never allowed.

## How it works

You write the policy once. The gate enforces it every time.

**Define the recipe.** A recipe is a small graph of steps: read context, propose a value, branch on it, invoke a tool, wait for a human, exit. It is checked when you save it and hashed. That hash is the policy's identity. Every decision the gate makes carries it.

**Gate tools by parameter.** A tool is not allowed or denied as a whole. Each argument the agent fills is checked against a rule. `namespace` must be one of `dev`, `staging`. `host` must come from the alert, not from the model. A tool with no rule for an argument is denied, not forwarded.

**Define the rules.** Rules are closed: a value is in a declared set, or equals a value a human signed, or came from a source the recipe trusts. There is no free text on the way to an authoritative sink. Rules are ordinary code. Same value, same rule, same answer.

**Bind the right context.** At session start the recipe names which context sources the agent may read. Everything read is labeled by where it came from: untrusted, caller, authoritative. A model's claim about the world is data. It is never a permission.

**Tools appear only when the recipe reaches them.** Tools for later steps are not advertised. When a step authorizes a call, the gate mints a one-shot grant bound to those exact arguments, that session, that run. The call is checked again against the target tool's own recipe. The grant is spent on use. Nothing standing is left behind.

**Every path is computed before the run.** When a session binds, the gate resolves every route to its recipe and computes how many distinct outcomes the whole recipe can produce, across every branch and loop, as a bits bound. If any path is unbounded, strict mode refuses to bind. A session also carries a hard cap on forwarded calls. The result is a number, known in advance: the most this agent can cause.

**Proven, not promised.** Every decision, allowed or denied, is written to a hash-chained log with its recipe hash. Releases are signed. `stag-verify` replays the chain offline and reports whether it is intact. You do not have to trust the gate's word for what happened.

## How a run works

1. An event arrives. The orchestrator picks the recipe that governs it.
2. A session is bound: this agent, this recipe, this budget of actions. The agent gets a token.
3. The agent connects through the token. It sees only the tools the recipe allows at this step. Tools for later steps are not visible until the recipe reaches them.
4. Every tool call is checked to the argument. Allowed calls forward. Denied calls are refused and recorded. Risky calls wait for a human to sign a release.
5. Every decision, allowed or denied, is written to a hash-chained log. Context the agent read is labeled by where it came from, never trusted for what it says.

Authorized is not the same as should happen now. The recipe encodes order, not just permission.

## Why it is different

**A closed list is not determinism.** Many guardrails make the model pick from a fixed set of answers. The set is fixed. The picking is still a model. Same input can give a different pick. StoaGraph does not try to make the model deterministic. It puts a deterministic check after the model, and the check is what decides.

**A permission check is not a plan.** An authorization engine answers one question: is this call allowed. It has no memory of what already happened. Allowed does not mean now, and does not mean twice. The recipe is a graph, so what is allowed depends on where the run is. The same call can be legal at step three and refused at step one.

**The model never defines the space.** If the code that calls the model also invents the list of options on each call, a bug or a compromise in that code widens the space and nothing notices. Here the space is a recipe, written before the run, hashed, and enforced by a process that does not hold the model or its keys.

**Context is labeled, not trusted.** The agent can read a lot. What it reads is tagged by source and recorded. A confident claim from the model or from a document changes nothing about what the gate permits.

**You can check the audit yourself.** The log is a hash chain. The releases are signatures. Verification runs offline against the recipe hash. A gate you cannot audit is a promise. This one is a proof.

## What is in the box

| Binary | Role |
|---|---|
| `stag-serve` | Control plane. Recipes, routes, the approval queue, the signing key. |
| `stag-proxy` | The gate. Sits on the MCP wire between agent and tools. |
| `harness-serve` | The orchestrator. Runs the model, holds the model API keys, binds sessions. It can never approve. |
| `stag-tools` | Declared local commands served as tools. No shell. |

The gate and the orchestrator are separate processes. A test fails the build if the gate imports orchestrator code. The orchestrator holds the keys; the gate holds the policy. Neither can do the other's job.

Apache-2.0. No held-back edition.

## This branch: deployment readiness

`deploy` makes StoaGraph run as independent, replicated services on Kubernetes without changing how it runs on one host.

Done:

- **Postgres backend.** `-store` takes a SQLite path (default, unchanged) or a `postgres://` DSN. Same SQL, one small dialect layer. Verified on PostgreSQL 17.
- **Sessions in the store.** A bound session survives a restart and can be served by any replica. The action budget is one row, drawn down atomically, so replicas share one count.
- **Approval key from the environment.** `STAG_APPROVAL_KEY` so every replica signs with the same key. Self-generation stays the single-host default.
- **Graceful shutdown.** First SIGTERM stops accepting, finishes in-flight work, then exits. `STAG_SHUTDOWN_GRACE`, default 20s.
- **Liveness and readiness split.** `/health` is 200 while the process runs. `/ready` is 503 until the store answers, the downstreams answer, and the recipe directory is readable. The orchestrator is not ready until the gate is.
- **WAL and busy timeout** on SQLite, so two processes sharing one file do not fail on the first collision.
- **Panic containment** in the event loop. One bad run cannot take the process down.

Not yet:

- The hash-chained audit logs are files with one writer each. `stag-proxy` and `harness-serve` stay at one replica until the chain writer is store-backed.
- Helm chart, recipe git-sync, External Secrets wiring, schema migrations.

Running locally is the same as before. Same flags, same `data/` directory, same `stoagraph up`. Every new capability is behind an option that defaults to today's behavior.

## Run it

```bash
stoagraph up
```

Or build from source:

```bash
cd stoa-kernel && go build ./... && go test ./...
```

Postgres integration tests, against a throwaway local server:

```bash
tools/pg-store-test.sh
```
