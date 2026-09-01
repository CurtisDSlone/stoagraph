#!/usr/bin/env bash
# tools/check.sh — the full verification gate. One command; exactly what CI runs.
#
#   gofmt · go vet · go test · ARCHITECTURE · frontend typecheck · code index · repo hygiene
#
# Every check is judged by its EXIT CODE, and its output is shown only when it fails.
#
# That is not a style preference — it is a bug fix. This script used to decide "did it pass?" by
# grepping the command's output, so on a cold module cache `go: downloading modernc.org/...` (progress
# chatter on stderr) was read as a vet diagnostic and CI failed a clean tree. A check that cries wolf is
# a check people learn to ignore, which is worse than no check at all. Exit codes are the contract; the
# output is just for humans.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

fail=0
step() { printf '\n== %s ==\n' "$1"; }
ok()   { printf '  ✓ %s\n' "$1"; }
no()   { printf '  ✗ %s\n' "$1"; fail=1; }
show() { sed 's/^/      /' <<<"$1"; }

# Warm the module cache first, so a slow network cannot be mistaken for a broken tree and so the
# per-check output below is signal, not progress bars.
(cd stoa-kernel && go mod download) >/dev/null 2>&1 || true

step "gofmt"
unformatted=$(gofmt -l stoa-kernel 2>/dev/null)
if [ -n "$unformatted" ]; then no "unformatted:"; show "$unformatted"; else ok "formatted"; fi

step "go vet"
if out=$( (cd stoa-kernel && go vet ./...) 2>&1 ); then ok "vet clean"; else no "vet found problems:"; show "$out"; fi

step "go test"
if out=$( (cd stoa-kernel && go test ./...) 2>&1 ); then
  ok "tests pass"
else
  no "tests failed:"; show "$(grep -vE '^(ok|---)' <<<"$out" | head -40)"
fi

step "ARCHITECTURE — the gate must not depend on the orchestrator"
# The product's central claim ("the gate holds no model and no keys") is TRUE only while this passes.
# If it goes red the claim is false, and no amount of "but it works" makes the build safe to ship.
if out=$( (cd stoa-kernel && go test -run TestGate .) 2>&1 ); then
  ok "stag/ imports zero harness/ code (and neither gate binary links it)"
else
  no "ARCHITECTURE BREACH — the gate reaches orchestrator code:"; show "$out"
fi

step "frontend typecheck"
if [ -d frontend/node_modules ]; then
  if out=$( (cd frontend && npx tsc --noEmit) 2>&1 ); then ok "typecheck clean"; else no "typecheck failed:"; show "$out"; fi
else
  printf '  – skipped (run: cd frontend && npm ci)\n'
fi

step "code index"
# An index nobody maintains is a map that lies, and a lying map is worse than no map. Fails if a file
# was added without a `// file-kw:` marker, or if the index was not rebuilt after a change.
if out=$(bash tools/index.sh --check 2>&1); then ok "index current"; else no "index stale/incomplete:"; show "$out"; fi

step "repo hygiene"
if out=$(bash tools/hygiene.sh 2>&1); then ok "hygiene OK"; else no "hygiene FAILED:"; show "$out"; fi

step "gate images are DISTROLESS (no shell)"
# "Nothing to pivot to if a binary is ever popped" is a security claim, so verify it — do not assert it.
#
# This check exists because the claim was FALSE and nobody noticed: the Dockerfile's alpine tool-server
# stage was last, and every caller (compose, ci, release) built without --target, so Docker built the
# LAST stage. The gate shipped with a shell, git and ripgrep in it while the README, SECURITY.md and the
# Dockerfile's own comments all said distroless. A claim with no test is a claim with a shelf life.
#
# Skipped (not failed) when the images are not built locally — CI builds them and runs the same assert.
if ! command -v docker >/dev/null 2>&1; then
  printf '  – skipped (docker not available)\n'
else
  missing=""; shelled=""
  for svc in stag-serve stag-proxy harness-serve; do
    img="ghcr.io/CurtisDSlone/stoagraph/$svc:latest"
    if ! docker image inspect "$img" >/dev/null 2>&1; then missing="$missing $svc"; continue; fi
    # a distroless image has no /bin/sh, so this must FAIL to run
    if docker run --rm --entrypoint /bin/sh "$img" -c 'exit 0' >/dev/null 2>&1; then shelled="$shelled $svc"; fi
  done
  if [ -n "$shelled" ]; then
    no "NOT distroless — a shell runs in:$shelled (build with --target runtime)"
  elif [ -n "$missing" ]; then
    printf '  – skipped (not built:%s — run: docker compose build)\n' "$missing"
  else
    ok "no shell in any gate image"
  fi
fi

echo
[ "$fail" -eq 0 ] && { echo "ALL CHECKS PASSED"; exit 0; }
echo "CHECKS FAILED"; exit 1
