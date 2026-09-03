# Local tools — real capability, no shell

`stag-tools` serves a **declared** set of local commands to an agent as MCP tools. It is how you give a
model genuine local capability — search the code, read a file, run the checks — without ever giving it a
shell.

```bash
stag-tools -config tools.yaml               # stdio: a local agent, or a host-run gate, spawns it
stag-tools -config tools.yaml -http :9300   # http:  its own container; the gate proxies it
```

## Two layers, and they are not the same

| | Constrains | Enforced by |
|---|---|---|
| **Declaration** (`tools.yaml`) | the **shape** — which commands exist, which arguments they take | `stag-tools` |
| **Recipe** (the gate) | the **values** — which values those arguments may hold | `stag` |

The command is authored by **you**. The model only fills declared `{placeholder}` arguments, and argv is
handed to the OS **directly** — never through a shell. So a `pattern` of `root; touch /tmp/PWNED` is
searched for, literally: it is one argument to `grep`, not two commands. There is no escaping to get
right, because **nothing is ever parsed**.

Then the gate bounds the values:

```yaml
rules:
  path.allowed:
    kind: set_membership
    set: ["README.md", "go.mod", "docs/routes.md"]
```
```bash
curl -H "Authorization: Bearer $STAG_CONSOLE_TOKEN" -X POST localhost:8080/api/routes \
  -d '{"tool":"read_file","server":"local-tools","recipe":"local_read_policy","gateArg":"path"}'
```

`read_file("README.md")` → **ALLOW**. `read_file("/etc/passwd")` → **DENY**, before the tool ever runs.

## What will not load, and why

```yaml
- name: run_command
  command: [bash, -c, "{cmd}"]     # stag-tools REFUSES to start
```

```
tool "run_command": `bash -c` with a placeholder in the script argument is a shell for the model —
the value would be parsed as a program.
```

This is a **structural** refusal, not a filter. A shell with a placeholder in its script argument hands
the model a shell through the back door, and no recipe can meaningfully constrain an arbitrary shell
string — `set_membership` over the set of all possible shell commands is not a policy.

**The granularity of the tool is the granularity of the control.** If a capability is worth having, give
it its own tool with the risky value as a named argument, then gate that argument.

Also refused: a placeholder in `argv[0]` (the model would be choosing the *program*), a placeholder that
isn't declared under `args`, and a declared arg the command never uses.

## The environment

A local tool sees `PATH`, `HOME`, and **only** what you name in `env_allow`. Nothing else.

That matters more than it looks. This server can be spawned as a **child of the gate**, and the gate's
process environment holds the control-plane secrets — `STAG_DISPATCH_TOKEN` binds sessions to *any*
recipe. A tool that could read it could grant itself any tool in the system. So the gate scrubs its own
secrets before spawning any stdio server, and `stag-tools` builds its tools' environment from an
allowlist besides. Two independent layers, because this one is worth getting wrong twice.

## Where the tools actually run

- **stdio** — the tool runs as a child of whatever spawned the server. Simple, and how local MCP normally
  works, but the tool shares that process's filesystem and network.
- **http** — run `stag-tools` as its **own** container with only the workspace mounted. Better isolation:
  a tool cannot reach what the container cannot reach. Prefer this under Docker.

## Files

- `tools.yaml` — the declared toolset. Start here.
- `recipes/read_file_policy.yaml` — gates `read_file`'s `path` to a named set.
- `scripts/check.sh` — a `script:` tool; declared args arrive as NAMED FLAGS (`--path <value>`), each value its own argv
  element, so a value with spaces or semicolons is still exactly one argument.
