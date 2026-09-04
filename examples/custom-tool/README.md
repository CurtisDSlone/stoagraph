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

## 2. Register it with the gate

```bash
ADMIN=$(grep STAG_CONSOLE_TOKEN ../../.env | cut -d= -f2)     # your gate key
curl -s -H "Authorization: Bearer $ADMIN" -X POST localhost:8080/api/mcp-servers \
  -d '{"name":"my-tools","transport":"http","target":"http://custom-tool:9100/mcp"}'
```

(Under Docker, use the compose service name — e.g. `http://custom-tool:9100/mcp`. On the host,
`http://localhost:9100/mcp`.)

## 3. Gate it

```bash
# save the policy
curl -s -H "Authorization: Bearer $ADMIN" -X POST localhost:8080/api/recipes --data-binary @recipe.yaml
# route the tool to it — gate the `channel` argument
curl -s -H "Authorization: Bearer $ADMIN" -X POST localhost:8080/api/routes \
  -d '{"tool":"notify","server":"my-tools","recipe":"notify_policy","gateArg":"channel"}'
```

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

Register `http://k8s-tools:9200/mcp` in **Adapters**, then gate its tools with recipes. The credential
never touches the agent or the gate's control plane — only the tool server holds it, and every call it
makes is still gated.

## Downstream auth, at a glance

When a server needs an HTTP credential, the gate holds it and injects it downstream — the agent never
sees it. In **Adapters**, pick the scheme:

| Scheme | For | You provide |
|---|---|---|
| **bearer / token** | most servers; pre-issued OAuth tokens / PATs | the token (env var preferred) |
| **header key** | custom-header APIs (`X-API-Key`) | header name + key |
| **query-param key** | keys passed in the URL (e.g. Alpha Vantage `?apikey=`) | param name + key |
| **OAuth sign-in** | providers with a login flow | nothing — click **Sign in**; the gate runs discovery + PKCE and holds the auto-refreshing token |

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
