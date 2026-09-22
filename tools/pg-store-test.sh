#!/usr/bin/env bash
# Run the store's Postgres integration tests against a THROWAWAY local server.
#
# Boots PostgreSQL from PG_BIN (default /usr/pgsql-17/bin) into a temp dir, listening on a unix
# socket only (no TCP port, no collision with anything else on the box), runs the store tests with
# STAG_TEST_PG_DSN set, and tears it all down. Nothing persists.
#
#   tools/pg-store-test.sh            # run the postgres tests
#   PG_BIN=/usr/lib/postgresql/16/bin tools/pg-store-test.sh
set -euo pipefail

PG_BIN="${PG_BIN:-/usr/pgsql-17/bin}"
for b in initdb pg_ctl psql; do
  [ -x "$PG_BIN/$b" ] || { echo "pg-store-test: $PG_BIN/$b not found (set PG_BIN)"; exit 2; }
done

T="$(mktemp -d)"
trap '"$PG_BIN/pg_ctl" -D "$T/pg" -m immediate stop >/dev/null 2>&1 || true; rm -rf "$T"' EXIT

"$PG_BIN/initdb" -D "$T/pg" -U stag --auth=trust >"$T/initdb.log" 2>&1
"$PG_BIN/pg_ctl" -D "$T/pg" -l "$T/pg.log" -w \
  -o "-k $T -c listen_addresses='' -c fsync=off -c synchronous_commit=off" start >/dev/null
"$PG_BIN/psql" -h "$T" -U stag -d postgres -qc 'CREATE DATABASE stag' >/dev/null

export STAG_TEST_PG_DSN="postgres://stag@/stag?host=$T&sslmode=disable"
cd "$(dirname "$0")/../stoa-kernel"
go test -count=1 -run 'Postgres' -v ./stag/store/ "$@"
