# Contributing

Thanks for looking. This is a security control, so the bar is a bit different from a normal library:
we care less about how fast a change lands and more about whether the guarantees still hold afterwards.

## The 60-second version

```bash
tools/find.sh escalation approval   # find the code that does the thing
git switch -c fix/approval-replay   # branch
# ...change...
tools/check.sh                      # the gate: fmt, vet, test, ARCHITECTURE, typecheck, index, hygiene
git commit -s -m "fix: ..."         # -s is required (DCO)
# open a PR
```

## Find the code first

The codebase is annotated with keyword markers that say what a file is **for** — the thing a grep
cannot infer:

```go
// file-kw: context provider read channel untrusted gather label-at-origin fail-open
// kw: gather run providers stamp untrusted fail-open per-provider
```

So instead of grepping for `approve` and getting sixty hits:

```bash
tools/find.sh escalation approval release
  stoa-kernel/stag/store/approval.go:13     [gate]
  stoa-kernel/harness/agent/approval.go     [orchestrator]
```

It tells you the **path, the line, and which side of the boundary you are on**. `INDEX.md` is the same
map in prose. Both are generated: `tools/index.sh`. If you add a file, add a `// file-kw:` line and
re-run it — CI fails on a stale index, because a map nobody maintains is a map that lies.

## The one rule that is not negotiable

**The gate must not depend on the orchestrator.**

```
harness/  (the ORCHESTRATOR — holds the model API keys)
   │
   ▼  imports
stag/    (the GATE — holds no model, no keys)
```

Never the other way. This is the product's central claim: the gate can be trusted with your
infrastructure precisely because it is *provably incapable* of reaching your keys. It is enforced by
[`stoa-kernel/architecture_test.go`](stoa-kernel/architecture_test.go), which fails the build if any
`stag/...` package — or either gate binary — so much as imports `harness/...`.

**If that test goes red, it is not a style violation. The claim is false and the change cannot ship.**

A related trap, from real experience: do not "fix" a 401 by handing a component a stronger token. The
orchestrator holds `dispatch` and `operator` and **must never hold `approve`** — an orchestrator that
can approve its own escalations makes the human-in-the-loop gate decorative, and every test still
passes. That 401 is the design working. See [SECURITY.md](SECURITY.md).

## Branches and commits

| | |
|---|---|
| `feat/<slug>` | a new capability |
| `fix/<slug>` | a bug |
| `docs/<slug>` | docs only |
| `chore/<slug>` | tooling, deps, CI |
| `security/<slug>` | see below before you push |

Commits use [Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`, `docs:`,
`refactor:`, `test:`, `chore:`. Keep the subject imperative and under ~72 chars.

**Every commit must be signed off (DCO):**

```bash
git commit -s -m "fix: consume the release token on replay"
```

That appends `Signed-off-by: Your Name <you@example.com>`, which certifies you wrote the patch or
otherwise have the right to submit it under Apache-2.0 (see [DCO](https://developercertificate.org/)).
CI enforces it. `git config format.signoff true` to make it automatic.

## Before you open a PR

```bash
tools/check.sh
```

That runs exactly what CI runs — fmt, vet, tests, the **architecture rule**, the index, and repo
hygiene. Nothing is expected of you that a single command cannot tell you.

If you touched dependencies or a Dockerfile:

```bash
docker compose build && tools/sbom.sh   # regenerates the SBOM; FAILS on copyleft in our dep graph
```

We are Apache-2.0 and are meant to be embeddable by people whose legal teams will not accept a
GPL/LGPL obligation. The gate is not decoration: it has already caught 33MB of LGPL code being shipped
for a feature we do not use.

## Tests we will ask you for

- **A bug fix needs a test that fails without it.** Not negotiable for anything in `stag/`.
- **A change to policy evaluation, auth, or the audit log needs a test that states the *negative*** —
  what must NOT happen. The existing ones are the model: `TestDispatchCannotApprove`,
  `TestGateDependsOnNothingInTheOrchestrator`, `TestNilAuthFailsClosed`. A test that only proves the
  happy path is how a security guarantee quietly stops being true.
- Fail closed. Ambiguity (unknown tool, missing arg, unreachable downstream, unset token) must resolve
  to *deny*, never to *allow*.

## Reporting a vulnerability

**Do not open a public issue.** See [SECURITY.md](SECURITY.md) for private disclosure.

If you are unsure whether something is a vulnerability or a bug: treat it as a vulnerability and report
it privately. We would much rather triage a false alarm than read about a real one on the internet.

## Docs count

A change that alters behaviour but not the docs is incomplete. `SECURITY.md` in particular must never
overstate what the gate does — an inaccurate security doc is worse than no security doc, because it is
believed. If your change narrows or widens a guarantee, say so there.
