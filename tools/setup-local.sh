#!/usr/bin/env bash
# tools/setup-local.sh — build StoaGraph from this checkout and install it as LOCAL BINARIES.
#
#   ./tools/setup-local.sh            # build, install to ~/.stoagraph, link the CLIs onto PATH
#   ./tools/setup-local.sh --start    # …and start the gate
#
# This is the no-Docker path. The repo's install.sh downloads a released binary and needs Docker; this
# builds what is in front of you and runs it as ordinary processes. Use this when you are developing on
# the gate, or when Docker is not the deployment you want.
#
# WHAT IT TOUCHES
#   ~/.stoagraph/          the instance: bin, data, recipes, config, logs, run  (chmod 700)
#   ~/.local/bin/stoa      symlink -> this checkout's tools/stoa
#   ~/.local/bin/stoa-approve   symlink -> tools/stoa-approve
#   your shell rc          ONE line adding ~/.local/bin to PATH, and only if it is not already there
#
# It does NOT write secrets, models, or policy. `stag-serve` mints its own tokens on first start, and a
# fresh gate permits nothing until you author a recipe — which is the correct starting point for a
# security control.
set -euo pipefail
cd "$(dirname "$0")/.." || exit 1
CHECKOUT="$(pwd)"

STOA_HOME="${STOA_HOME:-$HOME/.stoagraph}"
LINKDIR="${STOA_LINKDIR:-$HOME/.local/bin}"
START=0; NOPATH=0
for a in "$@"; do
  case "$a" in
    --start)   START=1 ;;
    --no-path) NOPATH=1 ;;   # do not touch any shell rc (CI, or you manage PATH yourself)
    *) die "unknown flag: $a  (--start, --no-path)" ;;
  esac
done

BOLD=$'\e[1m'; DIM=$'\e[2m'; GREEN=$'\e[32m'; YELLOW=$'\e[33m'; RESET=$'\e[0m'
say()  { printf '  %s\n' "$*"; }
ok()   { printf '  %s✓%s %s\n' "$GREEN" "$RESET" "$*"; }
warn() { printf '  %s!%s %s\n' "$YELLOW" "$RESET" "$*"; }
die()  { printf '\n  error: %s\n\n' "$*" >&2; exit 1; }

printf '\n%sStoaGraph — local install (no Docker)%s\n\n' "$BOLD" "$RESET"

# ---- prerequisites -------------------------------------------------------------------------------
command -v go >/dev/null 2>&1 || die "go is required to build from source — https://go.dev/dl/"
say "go        $(go version | awk '{print $3}')"
command -v python3 >/dev/null 2>&1 || die "python3 is required (stoa-approve is a python script)"
say "python3   $(python3 --version | awk '{print $2}')"

# ---- build ---------------------------------------------------------------------------------------
printf '\n%s== build ==%s\n' "$BOLD" "$RESET"
./tools/build.sh >/dev/null 2>&1 || die "build failed — run ./tools/build.sh to see why"
ok "built $(ls stoa-kernel/bin | wc -l | tr -d ' ') binaries"

# ---- install into the instance -------------------------------------------------------------------
printf '\n%s== instance: %s ==%s\n' "$BOLD" "$STOA_HOME" "$RESET"
mkdir -p "$STOA_HOME"/{bin,data,logs,run,config,recipes}
chmod 700 "$STOA_HOME"

# Refuse to overwrite a binary a running process holds open: a half-installed gate is a gate whose
# parts can disagree about the on-disk record format.
running_now=""
for b in stag-serve stag-proxy harness-serve; do
  pf="$STOA_HOME/run/$b.pid"
  if [ -f "$pf" ] && kill -0 "$(cat "$pf")" 2>/dev/null; then running_now="$running_now $b"; fi
done
if [ -n "$running_now" ]; then
  warn "already running:$running_now"
  say "${DIM}a running process holds its binary open, so this would half-install${RESET}"
  say ""
  say "  ${BOLD}stoa down${RESET}  &&  ${BOLD}$0${RESET}  &&  ${BOLD}stoa up${RESET}"
  say ""
  die "stop the gate first"
fi
for b in stag-serve stag-proxy harness-serve stag-tools stag-verify stag-probe harness; do
  [ -x "stoa-kernel/bin/$b" ] && cp "stoa-kernel/bin/$b" "$STOA_HOME/bin/"
done
ok "binaries -> $STOA_HOME/bin"

# The CLIs are SYMLINKED, not copied, so `git pull` updates them and there is never a stale second copy
# of the tool that starts your gate.
mkdir -p "$LINKDIR"
ln -sf "$CHECKOUT/tools/stoa"         "$LINKDIR/stoa"
ln -sf "$CHECKOUT/tools/stoa-approve" "$LINKDIR/stoa-approve"
ok "stoa, stoa-approve -> $LINKDIR  ${DIM}(symlinks into $CHECKOUT)${RESET}"

[ -f "$STOA_HOME/config/models.json" ] || {
  [ -f config/models.example.json ] && cp config/models.example.json "$STOA_HOME/config/models.example.json"
  say "${DIM}no models.json — only needed for StoaGraph's OWN agent loop (--with-harness)${RESET}"
}

# ---- PATH ----------------------------------------------------------------------------------------
printf '\n%s== PATH ==%s\n' "$BOLD" "$RESET"
if [ "$NOPATH" = 1 ]; then
  say "${DIM}--no-path: leaving your shell rc alone. Add $LINKDIR to PATH yourself.${RESET}"
else
case ":$PATH:" in
  *":$LINKDIR:"*) ok "$LINKDIR already on PATH" ;;
  *)
    # Pick the rc the user's shell actually reads. Appending to the wrong file is worse than not
    # appending: it looks like it worked and silently does nothing.
    rc=""
    case "$(basename "${SHELL:-/bin/bash}")" in
      zsh)  rc="$HOME/.zshrc" ;;
      bash) [ -f "$HOME/.bashrc" ] && rc="$HOME/.bashrc" || rc="$HOME/.bash_profile" ;;
      *)    rc="$HOME/.profile" ;;
    esac
    line="export PATH=\"$LINKDIR:\$PATH\"   # stoagraph"
    # Match the LITERAL path and the ~/$HOME spellings of it: an rc that already adds the directory as
    # "$HOME/.local/bin" must not get a second, redundant export appended.
    short="${LINKDIR#"$HOME"/}"
    if [ -f "$rc" ] && { grep -qF "$LINKDIR" "$rc" || grep -qF "\$HOME/$short" "$rc" || grep -qF "~/$short" "$rc"; }; then
      ok "$(basename "$rc") already adds $LINKDIR"
    else
      printf '\n%s\n' "$line" >> "$rc"
      ok "added $LINKDIR to $(basename "$rc")"
      warn "open a new shell, or:  source $rc"
    fi
    ;;
esac
fi

# ---- start ---------------------------------------------------------------------------------------
if [ "$START" = 1 ]; then
  printf '\n%s== start ==%s\n' "$BOLD" "$RESET"
  "$CHECKOUT/tools/stoa" up
fi

# ---- what does this instance actually have? -------------------------------------------------------
# Report DETECTED state, not a generic checklist. The next step differs completely depending on whether
# there is policy, and a script that says "now write a recipe" to someone who already has three is
# noise — while one that stays silent about an empty gate leaves them wondering why nothing works.
printf '\n%s== this instance ==%s\n' "$BOLD" "$RESET"
n_recipes=$(ls "$STOA_HOME/recipes" 2>/dev/null | wc -l | tr -d ' ')
have_models=no; [ -f "$STOA_HOME/config/models.json" ] && have_models=yes
if [ "$n_recipes" = 0 ]; then
  say "recipes   ${BOLD}0${RESET} — the gate permits nothing until you author policy"
else
  say "recipes   $n_recipes"
fi
say "models    $have_models  ${DIM}(only needed for --with-harness, StoaGraph's own agent loop)${RESET}"

printf '\n%s== start it ==%s\n' "$BOLD" "$RESET"
cat <<EOF
  ${BOLD}stoa up${RESET}          the gate: stag-serve :8080, stag-proxy :8091
  ${BOLD}stoa status${RESET}      what is running, pending approvals, recipe count
  ${BOLD}stoa down${RESET}        stop

${BOLD}== give an agent access ==${RESET}
A session must be bound to a recipe BEFORE an agent can connect — the binder chooses the policy,
because an agent that picked its own would pick the empty one.

  ${BOLD}stoa mcp${RESET} <tool>:<server>:<recipe>:<gateArg>
      prints  http://localhost:8091/mcp/<token>   ${DIM}— hand that URL to your agent${RESET}
      Claude Code:  claude mcp add --transport http stoagraph <that URL>

  ${BOLD}stoa-approve revoke${RESET} <token>     take the authority back; the only way to disarm a
                                     running agent (editing the recipe does NOT reach it)

${BOLD}== keeping the approve secret away from the agent ==${RESET}
The role secrets live in $STOA_HOME/data/control.tokens (0600). You can hold them in the SHELL
instead, and deliberately withhold the one that matters:

  ${BOLD}eval "\$(stoa env)"${RESET}              admin, dispatch, operator — NOT approve
  ${BOLD}eval "\$(stoa env --approve)"${RESET}    adds approve — ONLY in the terminal where you decide

  ${DIM}Honest scope: an agent running as you can read the 0600 file anyway — same uid is not a
  boundary. What this buys is that an agent which reads FILES (grepping, tailing, following a path
  a poisoned document suggested) does not stumble onto a secret that is not on disk, and that the
  shell the agent runs in never holds \`approve\` at all.${RESET}

${BOLD}== approvals, from the terminal ==${RESET}
When policy escalates, the gate HOLDS the call and waits for a person. You do not need the console:

  ${BOLD}stoa-approve list${RESET}               what is held right now
  ${BOLD}stoa-approve show${RESET} <id>          the exact call that was proposed
  ${BOLD}stoa-approve approve${RESET} <id>       mint the signed release  ${DIM}(-m "reason", -y to skip the prompt)${RESET}
  ${BOLD}stoa-approve deny${RESET} <id> -m why   refuse it; the denial sticks
  ${BOLD}stoa-approve watch --decide${RESET}     sit on the queue and decide as they arrive

  ${DIM}\`list\` prints a short id; \`show\`/\`approve\` want the full one.${RESET}
  An AGENT must never run \`approve\`: it reads the \`approve\` role secret, which the orchestrator is
  never given. Approval is a different secret, held by a different party — you.

${BOLD}== audit ==${RESET}
  ${BOLD}stag-verify${RESET} $STOA_HOME/data/decisions.jsonl
      every decision — allow, deny AND escalate — hash-chained, with the session and policy version
      that produced each one.

  ${DIM}next:${RESET}  examples/custom-tool/       one function, one gated argument, ~5 min
         docs/recipe-authoring.md     the policy language
         docs/sessions.md             what a session is, and how to revoke one

Rebuilt the source?  ${BOLD}stoa down && $0 && stoa up${RESET}
EOF
