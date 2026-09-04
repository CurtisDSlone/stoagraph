# Development

Everything runs from the repo root. There is one Go module (`stoa-kernel`) and one frontend
(`frontend`); each binary boots with **zero flags** because every default path is relative to this root.

## The tools

| | |
|---|---|
| `tools/build.sh` | Build all binaries into `stoa-kernel/bin/`. |
| `tools/up.sh` | Bring up the gate, the orchestrator, and the console. Prints your control-plane tokens. |
| `tools/down.sh` | Stop everything. Leaves `data/` intact. |
| `tools/check.sh` | **The gate for a change:** gofmt · vet · test · architecture · typecheck · hygiene. |
| `tools/hygiene.sh` | Repo invariants that fail silently if nobody looks. |
| **`tools/find.sh <words>`** | **Find the code that does a thing.** Searches the keyword markers, not identifiers. Start here. |
| `tools/index.sh` | Rebuild `INDEX.md` + `.index/code.json` from the `// file-kw:` / `// kw:` markers. |
| `tools/sbom.sh` | SBOM of the shipped images (CycloneDX) + a copyleft gate. |
| `tools/gen-env.sh` | Mint the four control-plane role secrets into `.env` (Docker). |

```bash
tools/build.sh && tools/up.sh      # http://localhost:3000
tools/check.sh                     # before you commit
tools/down.sh
```


## Testing OAuth against a real identity provider

Mocks prove we call what we think we call; they cannot prove we interoperate. Every OAuth bug in this
codebase was found by a real provider disagreeing with an assumption. Two suites run against a real
in-memory OIDC server — they **skip** when it is not running, so `go test ./...` stays green without it.

```bash
npm i -g @rustmcp/oauth2-test-server && oauth2-test-server     # http://localhost:8090
go test ./stag/oauth/ ./stag/serve/ -run 'RealIdP|Rotation|Concurrent' -v
```

Its `/authorize` auto-approves a hardcoded test user, so the whole authorization-code leg runs headlessly
— no browser, no human.

| Test | Covers |
|---|---|
| `stag/oauth` · `TestAgainstRealIdP` | discovery → dynamic client registration → PKCE → auth-code redirect → token exchange → refresh **rotation** → the proxy's connect-time resolver |
| `stag/oauth` · `TestConcurrentRefreshDoesNotLockOut` | two gate processes refreshing at once must not both spend the same single-use refresh token |
| `stag/serve` · `TestOAuthSignInAgainstRealIdP` | the real HTTP endpoints: `/api/oauth/start` → the provider's redirect → `/api/oauth/callback` → `/api/oauth/status`. This is the console's **Sign in** button, minus the popup. |

**Refresh-token rotation is the trap.** Providers issue a new refresh token on each refresh and revoke the
old one. The gate must persist each rotated token, and — because `stag-proxy` (at connect) and
`stag-serve` (at discovery) share `data/oauth/<server>.json` — must serialize refreshes across processes.
It takes an exclusive file lock and **re-reads inside it**, so a loser adopts the winner's rotated token
instead of spending a dead one. Without that, one refresh wins, the other gets `invalid_grant`, and a
revoked token can land on disk — locking the operator out of a server they authorized.

Set `STOAGRAPH_IDP_URL` to point the tests at a different provider.

## Layout, and the one rule

```
stoa-kernel/
  stag/      the GATE          — kernel, policy, proxy, auth, audit, approvals
  harness/   the ORCHESTRATOR  — dispatch, agent loop, models (the API KEYS live here)
  cmd/       the binaries; each ships as its own container
```

**The dependency runs one way: `harness/` → `stag/`, never the reverse.**

This is the product's central claim ("the gate holds no model and no keys"), and merging the two into a
single Go module removed the module boundary that used to make it structurally true. So it is now an
enforced test. `stoa-kernel/architecture_test.go` fails if any `stag/...` package — or either gate
*binary* — so much as imports `harness/...`.

If that test goes red, it is not a style violation. The claim is false and the build must not ship.

## Ports and roles

| Service | Port | What it is |
|---|---|---|
| `stag-serve` | 8080 | The gate's control plane: policy, approvals, audit. No model, no keys. |
| `stag-proxy` | 8091 | The gate's MCP proxy. Sessions are bound to a recipe here. |
| `harness-serve` | 8090 (host) / 8092 under Docker | The orchestrator's API. **Holds the model keys.** |
| console | 3000 | One UI, talking to both backends. |

`harness-serve`'s default is `-addr :8090`, so that is the port on the host. Under Docker, `compose.yml`
remaps it to host **8092** → container **8090** — because `:8090` is also what the OAuth test server
(below) wants, and running both on the host at once collides. Both numbers are correct; which one you
see depends on whether you are on the host or in the container.

Three secrets (`stoagraph up` mints them, `.env`): **console** (author policy + approve),
**operator** (models + dispatch), **dispatch** (machine-only — the orchestrator binds sessions, and
**cannot approve**). Your login link carries console + operator; you never handle dispatch. The one rule
that makes the whole thing safe: the orchestrator is never given an approve-capable secret. Do not
"fix" a 401 by handing it a stronger token — that 401 is the human-in-the-loop working.

## Paths

| | |
|---|---|
| `data/` | **All runtime state** — `config.db`, **`recipes/`** (the gate reads *and writes* it), `control.tokens`, `approval.key`, audit logs. **Gitignored**; the binaries create it. `rm -rf data` for a clean slate. |
| `config/` | `event_map.json`, and `models.json` (your keys — gitignored; copy `models.example.json`). |

### Model request timeouts

A model behind a gateway — a queue, a proxy, an inference server under load — can legitimately
take minutes to answer, and the client's timeout is what decides whether "slow" means "failed".
It is set per model, because one deployment may reach a fast endpoint and a slow one at once:

```json
{ "name": "gateway", "kind": "openai", "baseUrl": "https://…", "model": "…",
  "apiKeyEnv": "OPENROUTER_API_KEY", "timeoutSeconds": 300 }
```

Resolution order, first match wins:

| source | scope |
| --- | --- |
| `STOA_MODEL_TIMEOUT_SECONDS_<NAME>` | one model (the name uppercased, non-alphanumerics → `_`) |
| `STOA_MODEL_TIMEOUT_SECONDS` | every model |
| `timeoutSeconds` in `models.json` | that model |
| default | 90s |

The env layer exists so you can raise a limit for one run without editing config. The ceiling is
**15 minutes**; there is no "unlimited", because a hung request would pin a dispatch with no
other way to end. An out-of-range or unparseable value falls back to the default rather than to
no limit — a typo must not silently remove a bound.

The same budget covers the **dispatch router** (the model call that routes an event to a recipe):
a gated endpoint is no faster for being asked a short question.
| `examples/` | `custom-tool` (bring your own MCP tool), `local-tools` (declared local commands, no shell), `oauth-profiles` (downstream auth profiles). **Each example carries its own recipe(s) and a README** showing how to register and route it. |

A fresh instance boots **empty** — 0 recipes, 0 routes, 0 policies. The recipe store is runtime state,
not shipped content, so nothing is trusted until you author or load it. `stag-serve -recipe <file>` will
seed one policy + route on first run if you want a one-liner demo.

## Finding your way around

```bash
tools/find.sh escalation approval release
  stoa-kernel/stag/store/approval.go:13     [gate]
  stoa-kernel/harness/agent/approval.go     [orchestrator]
```

The source carries keyword markers that say what a file is **for** — the thing a grep cannot infer:

```go
// file-kw: context provider read channel untrusted gather label-at-origin fail-open
// kw: gather run providers stamp untrusted fail-open per-provider
```

`tools/find.sh` searches those, so you get a path, a line, and **which side of the gate/orchestrator
boundary** you are on — instead of sixty hits on the word `approve`. `INDEX.md` is the same map in
prose; both are generated by `tools/index.sh`.

**If you add a file, add a `// file-kw:` line and re-run `tools/index.sh`.** `tools/check.sh` fails on a
stale index: a map nobody maintains is a map that lies, and that is worse than no map.

## Why `tools/hygiene.sh` exists

Both bugs it catches actually happened in this repo, and **neither announced itself**:

1. A `.gitignore` line meant for a compiled binary (`/stoa-kernel/harness`) also matched the
   **orchestrator's source directory** and silently ignored 19 `.go` files. `go build` kept working
   locally; only a fresh `git clone` would have been broken — i.e. we'd have learned from the first
   person who tried to use it.
2. A `models.json` full of live API keys stayed **tracked** because `.gitignore` does nothing to a file
   that is *already committed*. It was pushed.

So: never add an ignore pattern that is a bare name colliding with a source directory (build to `bin/`),
and remember that ignoring a tracked file requires `git rm --cached`. `tools/hygiene.sh` checks both,
plus committed binaries. Run it in CI.

## Testing notes

- `go test ./...` from `stoa-kernel/` covers kernel, policy linter, proxy, auth, and the architecture rule.
- Auth tests assert the load-bearing negative: `TestDispatchCannotApprove`. If it ever passes a
  `dispatch` token to an approve route, human-in-the-loop is gone.
