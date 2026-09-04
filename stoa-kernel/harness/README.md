# event_harness — the orchestrator (the commercial half of StoaGraph)

The agent-side of the deployment topology (see `../Planning/22-deployment-topology.md`). The **`stag`** gate is
the passive gate/proxy; this is the **orchestrator** that lives on the far side of the MCP wire. Together they
are the **StoaGraph** product (`stag` open-source + `event_harness` commercial). This half:

- receives an event, picks the governing **recipe** (by choosing which `stag` session/endpoint to connect to),
- runs the **model** as the (untrusted) proposer,
- speaks **MCP to the `stag` gate** as a client — every proposed tool call is gated, every context read is
  proxied + labeled untrusted,
- **holds the model API keys** (the `stag` gate never does).

It is *not* an agent framework, and it is *not* the gate. It drives the loop; the `stag` gate decides what is
allowed.

## What's here (moved from the old monolithic runtime, U9–U21)

| Package | Role |
| --- | --- |
| `model` | the proposer boundary — `Proposer`/`Request`/`Proposal`, `LocalStub`, `Decide` |
| `model/claude` | Claude adapter (Anthropic Messages API; the SDK lives here now, not in stag) |
| `model/openai` | OpenAI-compatible adapter (OpenRouter / ollama / vLLM / OpenAI) |
| `kb` | RAG retrieval (markdown chunk + embed + cosine) |
| `bind` | context binding — trust-position assembly (trusted→System, untrusted→Input) |

It depends on the stag **kernel** (`github.com/scanset/StAG`) for shared trust types, via a `replace`
directive in `go.mod` pointing at `../harness/workspaces/stag`.

## `cmd/harness-serve` — the orchestrator's API (built)

Connect models (keys stored here), **simulate an event**, forward it through `stag-proxy`, and watch the
**gated transcript** stream (the model proposes; the stag gate disposes) over SSE. API-only, no bundled UI.
Multi-model tool-use — Claude and OpenAI-compatible (OpenRouter).

```bash
go build -o /tmp/stag-proxy ../harness/workspaces/stag/cmd/stag-proxy
go build -o /tmp/harness-serve ./cmd/harness-serve
# run from the REPO ROOT so the spawned stag-proxy finds deploy/mcp/*
cd .. && /tmp/harness-serve -addr :8090 -models ./event_harness/models.json   # http://localhost:8090
```

Packages: `store` (JSON model config), `agent` (the ToolModel loop: `claude.go` + `openai.go`).

## `cmd/harness` — the minimal agent loop (CLI, built)

Connects to `stag-proxy` (the stag gating MCP server) as an MCP client, pulls the **gated** tools, and runs a
Claude tool-use loop — every tool call the model proposes is routed **through stag-proxy** (gated) before it can
reach the real downstream. The harness holds the model key (env var); the stag gate never does.

```bash
# build stag-proxy (the gate) + this harness, from the stoa-kernel module root
go build -o /tmp/stag-proxy ./cmd/stag-proxy
go build -o /tmp/harness ./cmd/harness
# run one governed agent turn-loop against a registered downstream MCP server
ANTHROPIC_API_KEY=<key> /tmp/harness -proxy "/tmp/stag-proxy -downstream my-tools" -input "<the task text>"
```

## What's NOT here yet (the next builds)

- **Multi-model tool-use** — the loop is Claude-only today; add OpenAI/OpenRouter tool-use.
- **Model-provider config + keys UI** — stag's `model_provider` store, the Models tab, and the
  connectivity/propose-then-gate surfaces were removed from stag; reintroduce them here as the
  orchestrator's own config surface.
- **Event ingress** — a trigger (webhook / queue subscriber) that maps an event type to a recipe and dispatches
  (pairs with stag-proxy's session→recipe binding, Planning/24 v2).

## Build

```bash
go build ./...
go test ./...
```
