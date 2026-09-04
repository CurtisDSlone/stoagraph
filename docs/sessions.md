# Sessions — the unit of granted authority

**A session is a grant, not a connection.** `stoa-approve session` mints one: *this token may call
these tools, under these recipes, up to N crossings*. An agent connects **against** it — possibly
several times, possibly after a gap — and the grant outlives any one of those connections.

The word is overloaded, and the overload has already caused one real bug, so start here:

| | **binding** (what stag means) | **MCP transport session** |
| --- | --- | --- |
| created by | `POST /sessions` — the trusted dispatcher | the client's `initialize` |
| named by | the opaque token in `/mcp/<token>` | the `Mcp-Session-Id` header |
| holds the recipes | **yes** — compiled once, at bind | no |
| holds the crossing budget | **yes** — one counter, shared | no |
| lifetime | until revoked, or the daemon restarts | 30 minutes idle |
| revocable | **yes** (`stoa-approve revoke`) | n/a — the client just reconnects |
| appears in the audit as | `session=<digest>` | not recorded |

The relationship is **one binding : many transports**. Three `initialize`s against one token are
three transport sessions drawing on one grant, one policy, and one budget.

> **"Idle sessions close after 30 minutes" is about the transport, not the grant.** The binding does
> not expire. An agent that reconnects on an old token resumes the same policy and the same
> drawn-down budget.

## Why the budget lives on the binding

An untrusted agent can re-`initialize` whenever it likes. If the crossing counter lived on the
transport, reconnecting would reset `N` to zero and `-crossing-budget` would bound nothing. So one
`*CrossingBudget` is created per **bound token** and shared by every gating server built for it.

The same reasoning fixes the meaning of the guarantee in [`SECURITY.md`](../SECURITY.md): *"the
per-session leak is a bounded, signed number"* is a statement about the **binding**. Read as
"per connection" it would be false.

## Why the tool surface is fixed at bind

A binding advertises exactly the tools named in its `POST /sessions` route list — resolved once,
compiled once. Consequences worth knowing before you debug the wrong thing:

- **Adding a route does not widen an open session.** The registry gains a tool; the binding does
  not. A new tool needs a **new bind that names it**.
- **Editing a recipe does not reach an open session.** It holds a compiled copy. `stag-serve`'s
  `/api/decide` re-resolves per call and *will* show the new policy — so the preview and the
  enforcement path can legitimately disagree. Trust the session.
- **Deleting a recipe or route does not disarm one either.** The route table can read empty while a
  bound agent still calls the tool. The registry and the enforcement path diverge.

The last one is the trap: an operator looking at an empty route table would reasonably conclude
nothing can be called. **Only revocation withdraws authority from a running agent.**

The upside of the same property: a session's decisions are explainable by exactly one policy, and
the recipe hash in every audit leaf pins which.

## Revoking

```bash
stoa-approve revoke <token>      # accepts a bare token or the whole /mcp/<token> URL
```

Requires `dispatch` — the same role that binds. Whoever may choose a session's policy may withdraw
it, and revocation grants no authority the binder lacked. It is deliberately **not** reachable with
the session's own token: an agent that could revoke or rebind itself would be choosing its own
policy, which is the thing the trusted binder exists to prevent.

Revocation is checked **per request**, not at connect. This matters more than it sounds: the MCP SDK
builds a session's server once per transport and reuses it, so a check that ran only at connect would
never run again — and an agent already connected would keep its authority for the life of its
connection. Revoking would lock the door with the agent still inside. `Gate.Live` is the predicate
that closes it.

An unknown or revoked token answers with a JSON-RPC error (`-32001`, "rebind to continue"), not the
SDK's bare `no server available` string, so a client can report the cause instead of an opaque
transport failure.

> A call refused because the **session is gone** is rejected at the transport, ahead of the gate, so
> it does not reach `decisions.jsonl`. Calls refused by **policy** are always recorded.

## `tools/list` never changes under a session

The gate advertises `tools.listChanged` as **false**, on purpose. The MCP SDK infers `true` the
moment a tool is added, but that is a promise to push `notifications/tools/list_changed` — and a
binding's surface is fixed, so the notification could never fire. A client that believed the promise
would cache its tool list for the life of the session and never re-list.

That failure is quiet and looks like something else: the operator adds a route, the agent never sees
the tool, and the backend appears stuck. The truthful answer is that the new surface belongs to a
**new binding**. Advertising a capability you do not implement makes correct clients behave
incorrectly, so the gate declines to claim it.

## Changing policy for a running agent

There is no refresh. A binding's router is resolved once and never re-read, so the sequence is:

```bash
stoa-approve revoke <old-token>
stoa-approve session --route <tool>:<server>:<recipe>:<arg> [--route ...]
# repoint the agent at the new /mcp/<token> URL
```

The asymmetry is the part to remember: **loosening a policy takes effect on the next bind;
tightening one never reaches an existing session.** After narrowing a policy in response to something
live, revoke the sessions holding the old one — do not assume the edit reached them.

## Grants: a session's authority, narrowed to one call

A session is a standing grant over a tool surface. Inside it, a recipe that authorizes a *sequence*
mints something narrower — a **grant** for one call:

| | session | grant |
| --- | --- | --- |
| granted by | the dispatcher, at bind | a recipe's `invoke`, at execution |
| covers | a tool surface | one call, with those exact arguments |
| lasts | until revoked or the binding ends | until spent, or the sequence ends |
| replay | the token keeps working | denied — it was consumed |

A grant carries the **session** and the **run** that minted it, and both are part of its identity.
One agent cannot spend another's, and two concurrent sequences asking for the same call hold two
authorizations rather than competing for one — an argumentless tool's fingerprint is just its name,
so without the run they would collide.

When a sequence ends — completed, halted, or abandoned — its grants are swept. A one-shot grant that
outlived its sequence would be a standing authorization, which is the thing it exists not to be.

**A grant is not an approval.** They are the same primitive with different minters: an approval is
minted by a person and an ed25519 signature; a grant is minted deterministically by a policy. They
live in separate stores for that reason, and a machine grant can never be read as though someone
approved it.
