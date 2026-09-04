# Docker

```bash
stoagraph up      # mints the secrets, pulls the signed images, starts, prints your control-plane tokens
```

`compose.yml` is **pull-only** — it references published images and nothing on your disk, so it works
for someone who never cloned the repo. In a clone, `compose.override.yml` is merged automatically and
adds the `build:` blocks, so `docker compose build` still builds from source.

Doing it by hand:

```bash
tools/gen-env.sh && docker compose up -d
```

## Why there is no `docker run` one-liner

The control plane uses **per-role secrets**, and `approve` — the token that releases a held action —
must never reach the orchestrator's environment. Something has to mint three distinct secrets and give
each service only what it is entitled to, *before anything starts*. That is the step a single
`docker run` cannot do, and it is precisely the thing we made impossible to shortcut. `stoagraph up`
does it and gets out of the way.

Three containers by default (a fourth, `local-tools`, is opt-in), one Dockerfile:

| Service | Port | Image |
|---|---|---|
| `stag-serve` | 8080 | the **gate's** control plane — policy, approvals, audit |
| `stag-proxy` | 8091 | the **gate's** MCP proxy — sessions bound to a recipe |
| `harness-serve` | 8092 | the **orchestrator** — holds the model API keys (host `8092` → container `8090`) |
| `local-tools` | 9300 | local tool server — declared commands, no shell. **Opt-in:** profile `tools` (see below) |

The Go services all come from **one** `Dockerfile` (`--build-arg CMD=<binary>`), on
`distroless/static` as `nonroot`: no shell, no package manager, ~25–43 MB. Nothing to pivot to if a
binary is ever popped — which is also why the healthcheck is a 3 MB static probe (`cmd/healthcheck`)
rather than dropping `curl` into the image.

## Why not one container

Because the secrets would all end up on one filesystem, and that **structurally defeats the
human-in-the-loop guarantee.**

## The three secrets

There are three, and the split is the entire point. What must be true: the orchestrator — which runs
untrusted model output — can never approve its own escalations. That is only enforceable if the token
it holds is a **different secret** from the one that approves. (The gate's HTTP role check alone does
not save you: a compromised orchestrator would not send its token to `/approve` and accept the 401 —
it would send whatever approve-capable secret it was holding. So it holds none.)

| Secret | What it does | Held by |
|---|---|---|
| **console** | author policy **and** approve held actions | you (via `stoagraph tokens`) + `stag-serve` |
| **operator** | connect models, dispatch events | you (via `stoagraph tokens`) + `harness-serve` |
| **dispatch** | bind sessions, poll approvals — **cannot approve** | `harness-serve` + `stag-proxy` (machine only) |

`stoagraph tokens` prints **console** + **operator**. **dispatch** is machine-only and never
leaves a container. So no container mounts a tokens file, and — the line that matters — the orchestrator
is injected `operator` + `dispatch` and **never** the console/approve secret. Verify it:

```bash
docker inspect stoagraph-harness-serve-1 --format '{{range .Config.Env}}{{println .}}{{end}}' \
  | grep -c "$(grep STAG_CONSOLE_TOKEN .env | cut -d= -f2)"    # => 0
```

(Want an operator-vs-approver split — a junior who can operate but not approve? Give `admin` and
`approve` different values in `.env`. The default keeps them the same because both are just "you".)

## Model API keys

**Preferred:** keep keys out of every file. Set `"apiKeyEnv": "ANTHROPIC_API_KEY"` in
`config/models.json` and put the key in `.env`; compose passes it to the orchestrator only. A mounted
secrets file is precisely the thing this design avoids.

If you do keep a key inside `config/models.json`, note the bind mount preserves host ownership: a
`0600` file is unreadable by the container's default user. `compose.yml` therefore runs
`harness-serve` as `${HOST_UID}` (written by `tools/gen-env.sh`).

Either way, **the gate never sees any of it.** `config/` is mounted into the orchestrator alone.

## A fresh instance is empty

No recipes, no routes, nothing pre-trusted. `stag-proxy` comes up **live but not ready** and says so:

```
GET  /health    {"ok":true,"ready":false}
POST /sessions  503 {"error":"gate not ready: no downstream MCP server connected yet"}
```

That is fail-closed, not a fault. A gate with nothing to mediate must not pretend it is mediating. It
polls for a downstream and starts serving the moment one is registered — no restart needed.

## Registering your own downstream

A containerized gate cannot *spawn* a `stdio` MCP server — and we would rather keep the gate distroless
and minimal than bake an interpreter into it. So under Docker, register an **`http`** downstream; the
gate is an MCP client over streamable HTTP natively:

```bash
ADMIN=$(grep STAG_ADMIN_TOKEN .env | cut -d= -f2)
curl -s -H "Authorization: Bearer $ADMIN" -X POST localhost:8080/api/mcp-servers \
  -d '{"name":"my-tools","transport":"http","target":"http://my-tools:9000/mcp"}'
```

`examples/custom-tool` is a minimal reference for what such a server looks like (it serves stdio *and*
streamable HTTP from the same binary). `examples/local-tools` shows the shipped `stag-tools` server run
the same way.

## Operational notes

- `data/` is a named volume (config DB, the recipe store, audit logs). `docker compose down -v` wipes
  it back to a fresh instance.
- Every service answers `GET /health` unauthenticated, so one healthcheck shape works for all of them.
- Rotate the control plane: delete `.env`, re-run `tools/gen-env.sh`, `docker compose up -d`.
