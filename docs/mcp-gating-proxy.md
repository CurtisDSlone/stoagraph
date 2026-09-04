# The stag MCP gating proxy

`stag-proxy` sits between an AI agent and the MCP tool servers it calls. To the agent it **is** an MCP
server (it presents the tools); to your real MCP servers it is an MCP **client** (it forwards calls).
Between them is a deterministic gate: every `tools/call` is evaluated against a recipe (a policy), and
**only a cleared call is forwarded** to the real server. A denied or escalated call returns a tool
error and never reaches the downstream.

No model runs in the enforcement path — the decision is a deterministic walk of the recipe graph. The
gate holds no model and no API keys.

## The guarantee

- **Complete mediation** — every governed tool call is gated; there is no path to the downstream that
  bypasses the gate.
- **Forward-iff-cleared** — a call is forwarded only when the recipe verdict is `allow`. `deny`,
  `escalate`, and any fault are never forwarded.
- **Fail closed** — an unrouted tool, a missing/malformed argument, an unreachable downstream, or a
  recipe that will not parse all result in denial, never a silent allow.
- **Tamper-evident audit** — every cleared crossing is appended to a hash-chained, optionally-signed
  log.

## Two ways to run it

### stdio — a single agent (e.g. Claude Desktop)

The agent spawns `stag-proxy` and speaks MCP over its stdio. Tool→recipe bindings come from the config
store (managed in the console).

```
stag-proxy -downstream <your-mcp-server> -store <config.db>
```

Point your MCP client at that command — e.g. `claude_desktop_config.json`:

```json
{ "mcpServers": { "stag": { "command": "stag-proxy", "args": ["-downstream", "my-server"] } } }
```

### daemon — many sessions, session→recipe (streamable HTTP)

A standing server. A trusted controller binds a session to a recipe and hands the agent an opaque
endpoint; the agent cannot choose its own recipe.

```
stag-proxy -http :8091          # fronts every enabled downstream; each route names which server serves it
```

- `POST /sessions {routes:[{tool,server,recipe,gateArg}]}` → `{token, path}` — the control plane (trusted).
- The agent connects to `/mcp/<token>` (streamable HTTP); every call is gated by that session's recipe,
  and the session's `tools/list` shows only the tools that recipe governs.
- `DELETE /sessions/{token}` revokes a binding — also `dispatch`, and checked on every request, so it
  reaches an agent that is already connected.
- An unknown or revoked token → `400` carrying a JSON-RPC error (`-32001`), fail closed.

The 30-minute idle timeout closes the **transport**, not the binding: a token→recipe binding does not
expire, and reconnecting on an old token resumes the same policy and the same drawn-down crossing
budget. See [`sessions.md`](sessions.md) — the distinction is load-bearing, and conflating the two is
what let an agent outlive its own revocation.

## What a refusal looks like

A gated-but-denied call returns an MCP tool error (`isError: true`) with a human message and structured
metadata in the protocol-reserved `_meta`:

```json
{ "isError": true,
  "content": [{ "type": "text", "text": "stag gate: deny — \"delete_namespace\" not forwarded" }],
  "_meta": { "stag": { "tool": "delete_namespace", "verdict": "deny" } } }
```

On an approval-gated `escalate`, `_meta.stag.approvalId` is set, so a controller can drive a
human-approval flow (approve → signed release → the retried call is forwarded).

## Both channels are gated

- **ACT — tools.** `stag-proxy` gates `tools/call`: **allow / deny / escalate**, forward-iff-cleared.
- **READ — resources.** Each bound context provider is served as an MCP resource template
  (`stag://context/<name>{?q}`). A `resources/read` runs the provider, stamps every item **untrusted at
  origin** (unbypassably), records the crossing to the read audit log, and returns it. **Reads are
  label+record — never denied**: no recipe is consulted, because a read cannot itself exercise authority.

  The untrusted stamp is **positional, not taint-tracking** — it keeps context out of the instruction
  slot. It is *not* relied on to survive the model; the ACT gate re-derives trust at the sink. See
  [SECURITY.md](../SECURITY.md).

## Control plane

Authenticated by default. Role tokens are generated (`0600`) into `data/control.tokens` on the
gate's first start; env vars (`STAG_*_TOKEN`) override for containers.

- `POST /sessions` (bind a session — it *chooses the recipe*) requires the **`dispatch`** role.
- `/mcp/<token>` takes **no** bearer: the opaque session token *is* the untrusted agent's credential.
  Handing the agent a control-plane bearer would be exactly backwards.
- Approving an escalation requires **`approve`**, which the orchestrator is never given.

## Scope (v1)

- **Scalar gated arguments.** A recipe gates named arguments (e.g. `namespace`, `replicas`), compared
  as strings; non-scalar arguments are stringified. Which arguments a tool's policy judges is set by its
  route — see [routes.md](routes.md).
- **Multi-server fleet, namespaced tool surface.** The gate fronts several MCP servers at once. A route
  names its `server` (a route is tool → server → recipe → gateArg) and is keyed by **(server, tool)**, so
  two servers may both expose `search_code` and both be routed, each to its own recipe. The gate
  advertises them apart, as `<server>__<tool>` — `github__search_code`, `local-tools__search_code` — and
  forwards a cleared call downstream under the server's own name, so the tool server never sees the
  prefix. Tools are prefixed **always**, even with one server connected: prefixing only on collision
  would rename a tool the agent already knew the moment you registered a second server. The gate never
  infers the server from a tool name, so adding a server cannot silently re-point a route you already
  wrote. Server names are therefore restricted to `[a-zA-Z0-9_-]` with no `__` (the advertised name is
  handed to a model, and the provider tool-use APIs reject anything else).
- **Transports: stdio, `http` (streamable) and `sse` (legacy).** SSE is the older MCP remote transport
  and much of the deployed ecosystem still speaks only that, so it is supported. Auth is identical
  across both remote transports — it is a property of the HTTP hop, not of the framing over it.
- **Downstream resources are served as READ channel.** A server whose value is its *resources* (a repo,
  a wiki, a doc set) is not invisible to a tools-only gate: the gate re-serves them, namespaced as
  `stag://mcp/<server>?uri=<original>`, stamped **untrusted at origin** and **recorded**. A read is
  label+record and is never denied — reads inform the model, they do not authorize it. A server with no
  resources is unaffected (`resources/list` failing is not an error worth refusing a connection over).
- **`http`, `static`, and `mcp_resource` context providers.** `http` proxies a downstream endpoint
  (the query is a parameter, never executed). `mcp_resource` binds a *connected* downstream MCP
  server's own resources as a named context provider (config `{server, uris?}`; empty `uris` reads
  every resource the server discovered) — resolved at the daemon from the live session, stamped
  untrusted and recorded like all context. `static` is a content-addressed local bundle: the operator
  points it at a file or directory, the gate reads + hashes it at registration and serves it
  **verbatim with no query**
  — no retrieval, no outbound anything, which removes the READ-side egress channel entirely and suits
  runbooks (whole-document beats similarity search at that scale). The outbound query on any provider is
  length-bounded before it reaches the provider, and every read records per-item content hashes, so the
  audit attests the exact bytes the model saw. The `rag` and `mcp_resource` kinds are reserved and fail
  closed (an unbuildable provider is dropped from the session, never fabricated); keeping *retrieval* in a
  downstream provider is deliberate — it is what lets the gate stay model-free.

## Verified interop

`stag-proxy` is a Go (`github.com/modelcontextprotocol/go-sdk`) MCP server. It has been driven
end-to-end by the **official MCP Inspector** (a TypeScript-SDK client, an independent implementation)
over stdio: `tools/list`, a cleared `tools/call` (forwarded to the real server), and a denied
`tools/call` (blocked before the downstream, the refusal surfaced to the client) — cross-implementation
compatibility, not just self-tests.

## What the agent is offered, and what it can reach

Advertisement and reachability are separate, and the gap between them is deliberate.

**Advertised**: every route the gate can resolve — the server is connected, it exposes the tool, and
the recipe covers the tool's whole schema. A coverage gap means the tool is *not offered at all*,
because offering one whose dangerous half nothing watches is worse than offering none.

**Not advertised, still routed**: a `sequenced` route. The tool exists for a recipe's `invoke` to
authorize and is unreachable without a one-shot grant minted for that exact call. An agent that
guesses the name is denied — and recorded, because reaching for a tool it was never offered is more
suspicious than calling an unrouted one.

**Also advertised**: each bound context provider, as `context__<name>`. These are the READ channel
wearing a tool's clothes: they carry no route, are exempt from the unrouted check by *membership of
the providers this session bound* — never by the shape of the name — and are never denied.

## A sequence over the wire

An agent calls one tool. If its recipe authorized a sequence, the gate does not forward that call at
all: the tool was the trigger. Each authorized call is instead put back through the gate against its
own route and recipe, executed in order, and the agent receives a transcript of what was made and
where it stopped.

Every step reserves its own crossing, so a sequence of N costs N against the session budget — an
`await` polling six times costs six. A refusal halts the sequence; earlier steps stay done, and the
result says which step it stopped on. Nothing is rolled back, because nothing can promise that over
someone else's tools.
