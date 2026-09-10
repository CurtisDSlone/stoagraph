# Bring your own tool

A minimal MCP tool server + a recipe that gates it. Copy this folder, replace the example tool with
yours, and put StoaGraph in front of it. ~5 minutes.

## The shape

- **`main.go`** — one MCP tool, `notify(channel, text)`. This is where your tool goes.
- **`recipe.yaml`** — gates the `channel` argument: the agent may post to `support`, `general`,
  `incidents` — and provably nothing else.

## 1. Run your tool server

```bash
go run . -http :9100        # streamable HTTP (a containerised gate reaches it over the network)
# or
go run .                    # stdio (a host-run gate spawns it)
```

## 2. Gate it: drop the recipe in as a plain file

A recipe is just YAML. `stag-serve` reads whatever is in the directory it was started with
(`-recipes-dir`, `$STOA_HOME/recipes` under `tools/stoa`) — no API call needed to author one:

```bash
cp recipe.yaml "$(stoa home)/recipes/"     # stag-serve picks it up; nothing to POST
```

(Running under Docker instead of `tools/stoa`? Same file, no `stoa home` shortcut — mount it into
the gate's recipes volume, or `POST /api/recipes --data-binary @recipe.yaml`, which writes into
that same directory through the store.)

## 3. Register your tool server and route it to that recipe

Routes and MCP-server registrations aren't plain files — they're relational (a tool can be routed
differently as you register more servers), so these two go through the API:

```bash
ADMIN=$(stoa token admin)      # reads $STOA_HOME/data/control.tokens; see docs/development.md
curl -s -H "Authorization: Bearer $ADMIN" -X POST localhost:8080/api/mcp-servers \
  -d '{"name":"my-tools","transport":"http","target":"http://localhost:9100/mcp"}'
curl -s -H "Authorization: Bearer $ADMIN" -X POST localhost:8080/api/routes \
  -d '{"tool":"notify","server":"my-tools","recipe":"notify_policy","gateArg":"channel"}'
```

(Under Docker, target the compose service name instead — e.g. `http://custom-tool:9100/mcp`.)

## 4. See it enforced

```bash
curl -s -H "Authorization: Bearer $ADMIN" -X POST localhost:8080/api/decide \
  -d '{"tool":"notify","args":{"channel":"support","text":"hi"}}'        # ALLOW
curl -s -H "Authorization: Bearer $ADMIN" -X POST localhost:8080/api/decide \
  -d '{"tool":"notify","args":{"channel":"exec-private","text":"..."}}'  # DENY
```

The agent can now call your tool through the gate, on the values your policy allows, and nowhere else.

## Scripts, and directories of scripts

A script isn't a tool until it's behind an MCP server the gate proxies — that is the containment: the
agent never runs anything, it proposes a *tool call*, the gate checks the recipe, and only then does the
server run the script. To expose your own scripts:

1. In `main.go`, add one MCP tool per script (or one tool whose argument *selects* among a fixed set of
   scripts — gate that argument with `set_membership`). Each risky value the script takes becomes a
   named, gate-able argument.
2. Run the server. For a directory of scripts you maintain, mount it into the server's container and have
   the tool invoke `./scripts/<name>` — the scripts live beside the server, not in the agent.
3. Its stdout returns to the agent **labelled untrusted** — treat and gate it like any external input.

Do not hand the model a `run_script(path)` or `run_command(cmd)` tool to "run whatever's in the folder":
that is the un-gateable case from *The one rule* below. Enumerate the scripts as tools (or as an allowed
set) so the *policy*, not the model, decides what may run.

## Tools that need a credential file (kubeconfig, service account, cloud creds)

Some servers authenticate to their target with a mounted file rather than an HTTP key — e.g. Azure
[`mcp-kubernetes`](https://mcpservers.org/servers/Azure/mcp-kubernetes) reads your **kubeconfig**. Run
those as their **own** service with the credential bind-mounted read-only, and register them as
`transport: http`, `auth: none`:

```yaml
# compose.override.yml (or your own compose file)
services:
  k8s-tools:
    image: ghcr.io/azure/mcp-kubernetes
    command: ["--transport", "streamable-http", "--port", "9200"]
    volumes:
      - ${HOME}/.kube/config:/home/mcp/.kube/config:ro   # the credential stays in the tool's container
```

Register `http://k8s-tools:9200/mcp` via `POST /api/mcp-servers` (`"authScheme":"none"`), then gate its
tools with recipes. The credential never touches the agent or the gate's control plane — only the tool
server holds it, and every call it makes is still gated.

## Downstream auth, at a glance

When a server needs an HTTP credential, the gate holds it and injects it downstream — the agent never
sees it. Set `authScheme` on the `POST /api/mcp-servers` body:

| `authScheme` | For | You provide |
|---|---|---|
| **`bearer`** | most servers; pre-issued OAuth tokens / PATs | `secretEnv` (preferred) or `secret` |
| **`header`** | custom-header APIs (`X-API-Key`) | `authHeader` (header name) + `secretEnv`/`secret` |
| **`query`** | keys passed in the URL (e.g. Alpha Vantage `?apikey=`) | `authHeader` (param name) + `secretEnv`/`secret` |
| **`oauth`** | providers with a login flow | nothing — open `GET /api/oauth/start?server=<name>` in a browser (admin token required) and the gate runs discovery + PKCE, then holds the auto-refreshing token; see [`../oauth-profiles/`](../oauth-profiles/) for providers needing a profile first |

**Adding a provider never requires code.** A spec-compliant MCP server needs no configuration at all: the
gate discovers its authorization server, registers itself dynamically, and signs in with PKCE. For the
rest — a provider with no metadata, no dynamic registration, or a dialect of its own (Google's
`access_type=offline`, Auth0's `audience`) — you paste a **provider profile**: JSON, not Go. See
[`../oauth-profiles/`](../oauth-profiles/).

## The one rule

Make each tool a **specific capability with a gate-able argument**. `notify(channel, text)` can be
gated — *which channels?* A generic `run_command(cmd)` cannot: a recipe can't meaningfully constrain an
arbitrary shell string, and it hands the model unconstrained reach. **The granularity of the tool is the
granularity of the control.** If a capability is worth gating, give it its own tool with the risky value
as a named argument.

See [`../../docs/recipe-authoring.md`](../../docs/recipe-authoring.md) for the rule types
(`set_membership`, `numeric_range`, `signed_equality`).
