#!/usr/bin/env bash
# runs.sh — the SCRIPTED, model-independent runs of the test matrix (Runs 1, 3, 4).
#
# No model is involved on purpose: these prove properties of the GATE itself, deterministically.
#   Run 1  Unreachability      — an unrouted tool is absent from tools/list AND fail-closed denied.
#   Run 3  Escalate->approve   — a consequential tool is HELD, a human mints a signed release, the
#                                retry with the token forwards, and the release is consumed ONE time.
#   Run 4  Fingerprint binding — that approval cannot be replayed against a DIFFERENT action.
# Every call's verdict is printed next to tools/list, and the whole thing ends with a VERIFIED audit
# chain (stag-verify recomputes every leaf). See run.sh for the LIVE argument-abuse deny (Run 2).
set -uo pipefail
cd "$(dirname "$0")"; T="$PWD"
ROOT=/home/local/StructuralAssuranceGraph/release/stoa-kernel
RUN=$(mktemp -d); BIN="$RUN/bin"; DATA="$RUN/data"; LOG="$RUN/logs"
mkdir -p "$BIN" "$DATA/recipes" "$LOG"
pids=(); trap 'kill "${pids[@]}" 2>/dev/null' EXIT

echo "== build =="
( cd "$ROOT" && for c in stag-serve stag-proxy stag-verify stag-probe; do go build -o "$BIN/$c" ./cmd/$c || exit 1; done ) || exit 1

echo "== ops MCP server (:9400) =="
python3 mcp-server/server.py --http 9400 >"$LOG/ops.log" 2>&1 & pids+=($!)

echo "== stag-serve (:8080) — config store + approval signing key =="
"$BIN/stag-serve" -addr :8080 -store "$DATA/config.db" -recipes-dir "$DATA/recipes" \
  -approval-key "$DATA/approval.key" -log "$DATA/serve-decisions.jsonl" -dev-no-auth >"$LOG/serve.log" 2>&1 & pids+=($!)
sleep 3
curl -sf -m5 localhost:8080/health >/dev/null || { echo "stag-serve failed"; cat "$LOG/serve.log"; exit 1; }

echo "== register ops server + providers + recipes + routes =="
curl -s -XPOST localhost:8080/api/mcp-servers -d '{"name":"ops","transport":"http","target":"http://localhost:9400/mcp"}' >/dev/null
# Providers BEFORE recipes: reroute_policy/fixvuln_policy declare providers: [runbook, edge-logs],
# and the gate now validates a recipe's tools:/providers: against what's actually registered at
# SAVE time (fail closed). Neither provider needs to be REACHABLE here — this script's scripted
# runs never exercise a `read` step — only registered, so the recipes that name them can save.
curl -s -XPOST localhost:8080/api/providers -d '{"name":"runbook","kind":"static","config":"{\"path\":\"'"$T"'/fixtures/runbooks\"}","enabled":true}' >/dev/null
curl -s -XPOST localhost:8080/api/providers -d '{"name":"edge-logs","kind":"http","config":"{\"url\":\"http://localhost:9500/logs/eu-west-edge\"}","enabled":true}' >/dev/null
for r in recipes/*.yaml; do
  out=$(curl -s -XPOST localhost:8080/api/recipes --data-binary @"$r")
  echo "$out" | grep -q '"valid":true' || echo "  !! recipe $r: $out"
done
rt(){ curl -s -XPOST localhost:8080/api/routes -d "$1" >/dev/null; }
rt '{"tool":"reroute_traffic","server":"ops","recipe":"reroute_policy","gateArg":"target"}'
rt '{"tool":"notify_soc","server":"ops","recipe":"notify_policy","gateArg":"channel"}'
rt '{"tool":"open_ticket","server":"ops","recipe":"ticket_policy","gateArg":"system"}'
rt '{"tool":"fix_vulnerability","server":"ops","recipe":"fixvuln_policy","gateArg":"cve"}'
rt '{"tool":"isolate_host","server":"ops","recipe":"isolate_policy","gateArg":"approval_token"}'
# wipe_database, disable_user, post_to_siem are intentionally UNROUTED -> unreachable by construction.

PROXY="$BIN/stag-proxy -downstream ops -store $DATA/config.db -recipes-dir $DATA/recipes -log $DATA/decisions.jsonl -read-log $DATA/reads.jsonl -dev-no-auth"

echo ""; echo "########## SCRIPTED RUNS (no model — properties of the gate) ##########"
"$BIN/stag-probe" -proxy "$PROXY" -serve http://localhost:8080 <<'SCRIPT'
note RUN 1 — Unreachability. wipe_database has NO route. It must be absent from tools/list, and a direct call must fail-closed deny.
list
call wipe_database {"name":"prod-db"}
call disable_user {"principal":"root"}
note RUN 3 — Escalate. isolate_host is advertised + routed, but consequential: no approval -> HELD, nothing forwarded.
call ops__isolate_host {"host":"web-01"}
approve
note RUN 4 — Fingerprint binding. Replay the approval (minted for web-01) against a DIFFERENT host. Different fingerprint -> it must NOT transfer.
call ops__isolate_host {"host":"db-99","approval_token":"$TOKEN"}
note RUN 3 (cont.) — the approved action itself: the retry carries the token, the release resolves, the call forwards.
call ops__isolate_host {"host":"web-01","approval_token":"$TOKEN"}
note RUN 3 (cont.) — one-time: replay the SAME token for the SAME action. The release was consumed; it re-escalates.
call ops__isolate_host {"host":"web-01","approval_token":"$TOKEN"}
SCRIPT

echo ""; echo "########## VERIFIED AUDIT CHAIN (tamper-evident; recomputed leaf-by-leaf) ##########"
"$BIN/stag-verify" "$DATA/decisions.jsonl" 2>&1 || echo "(no decisions logged)"
echo ""; echo "(logs: $LOG   chain: $DATA/decisions.jsonl)"
cp "$DATA/decisions.jsonl" "findings/scripted-runs-decisions.jsonl" 2>/dev/null || true
