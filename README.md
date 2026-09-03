# StoaGraph

**Verifiable control for AI agents.** An agent proposes a tool call; a deterministic gate disposes —
allow, deny, or escalate — with no model in the decision path.

> **StoaGraph does not stop prompt injection. It stops prompt injection from turning into action.**

A hijacked, prompt-injected, or simply wrong model can propose anything; it cannot make the gate release
a value your policy rejects. The model has a flashlight; the gate has the map.

Open source, Apache-2.0. No held-back edition. New here? Start with the [doctrine](docs/doctrine.md).

## Quickstart

```bash
curl -sSL https://raw.githubusercontent.com/CurtisDSlone/stoagraph/v0.3.1/install.sh | sh
stoagraph up        # mint secrets, pull the signed images, start, print a one-click login link
```

Open the console at **http://localhost:3000**. The login link from `stoagraph up` carries your keys in
the URL fragment, so there is nothing to paste; reprint it any time with `stoagraph console`.

A fresh gate is **empty** — it permits nothing until you author a policy. That is the correct starting
point for a security control: it never arrives already allowing something you did not write. The console
walks you from the empty state through wiring your first tool.

The fastest path is [`examples/custom-tool/`](examples/custom-tool/): a copy-paste MCP server and a short
recipe, about five minutes. You write one function and gate one argument, and the agent can then call
your tool on the values you allow and *provably* nowhere else.

<sub>Piping a script into your shell, from a product that says "don't trust — verify"? Fair. `install.sh`
lives in this repo at the tag it installs, verifies the binary's SHA-256 against cosign-signed checksums
before running anything, and prints `cosign verify` for the images. Prefer to read first: `curl -sSLO
…/install.sh && less install.sh && sh install.sh`. Have Go?
`go install github.com/CurtisDSlone/stoagraph/stoa-kernel/cmd/stoagraph@latest`.</sub>

## Make it yours

- **Connect a model.** Copy `config/models.example.json` to `config/models.json` and add a key. **The
  gate never sees it** — only the orchestrator does.
- **Add a tool.** Register an MCP server (yours, or one of the examples), write a recipe that says which
  arguments may take which values, and route the tool to it. All four steps are in the console from the
  empty state.
- **Author policy.** [`docs/recipe-authoring.md`](docs/recipe-authoring.md) is the policy language;
  [`docs/routes.md`](docs/routes.md) covers binding a tool to a policy.

## How it works

Two pieces, and the split is the product:

| | | |
|---|---|---|
| **`stag`** | the **gate** | Deterministic kernel, MCP proxy, policy, audit, approvals. **No model, no API keys.** |
| **`harness`** | the **orchestrator** | Dispatcher, agent loop, model connections. **Holds the keys.** |

That separation is *enforced*, not intended: [`architecture_test.go`](stoa-kernel/architecture_test.go)
fails the build if any gate package — or either gate binary — imports orchestrator code. The gate can be
trusted with your infrastructure precisely because it is *provably incapable* of reaching your keys.

The agent's only wire to the world is the gate. Every proposed tool call crosses it and is allowed,
denied, or escalated — forward-iff-cleared, so a denied call never reaches the tool. Context the agent
reads is stamped untrusted at origin and audited. When policy says an action needs a person, the gate
holds the call and a human mints an ed25519 signed release bound to that exact action; the orchestrator
can *poll* for the decision but **cannot approve**, because that is a separate secret it is never given.

For the threat model, the trust invariant, and the guarantees — read the non-goals as carefully as the
guarantees — see [SECURITY.md](SECURITY.md).

## Docs

- [docs/doctrine.md](docs/doctrine.md) — what StoaGraph does and the tenets it is built on. Start here.
- [docs/context-binding.md](docs/context-binding.md) — how an agent reads untrusted context without letting it seize control.
- [SECURITY.md](SECURITY.md) — the threat model and guarantees.
- [docs/recipe-authoring.md](docs/recipe-authoring.md) — the policy language.
- [docs/routes.md](docs/routes.md) — binding a tool to a policy: why an unrouted tool is denied, and which arguments a route must gate.
- [docs/mcp-gating-proxy.md](docs/mcp-gating-proxy.md) — how the gate speaks MCP.
- [docs/sessions.md](docs/sessions.md) — what a session is: a grant, not a connection. The crossing budget, revoking, and why a policy edit does not reach an agent that is already bound.
- [docs/docker.md](docs/docker.md) — the containers, and why the secrets are split across them.
- [docs/development.md](docs/development.md) — layout, ports, and running from source.
- [examples/custom-tool/](examples/custom-tool/) — bring your own tool in about five minutes.

## Development

```bash
tools/find.sh escalation approval   # find the code that does a thing (keyword index, not grep)
tools/check.sh                      # gofmt · vet · test · ARCHITECTURE · typecheck · index · hygiene
tools/sbom.sh                       # SBOM of the shipped images + a copyleft gate
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and [docs/development.md](docs/development.md).
