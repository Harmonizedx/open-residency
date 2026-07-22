#!/usr/bin/env bash
#
# Full-stack SSO end-to-end test orchestrator.
#
# Stands up a throwaway PostgreSQL cluster with the local server binaries (no Docker),
# pushes the Prisma schema, builds the app, and runs scripts/sso-nest-e2e.cjs against it
# -- which boots the ACTUAL NestJS application and drives a real "Sign in with the State"
# flow through the real InteractionController. Tears everything down on exit.
#
# Skips cleanly (exit 0) when the PostgreSQL server binaries are not installed, so it can
# sit in CI without becoming a machine-specific failure. Requires: initdb, pg_ctl, psql
# on PATH (Homebrew `postgresql@14`, or the postgres apt packages).
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v initdb >/dev/null 2>&1 || ! command -v pg_ctl >/dev/null 2>&1; then
  echo "  - SKIPPED: PostgreSQL server binaries (initdb/pg_ctl) not found on PATH."
  echo "    Install them (e.g. 'brew install postgresql@14') to run this test."
  exit 0
fi

PGDATA="$(mktemp -d "${TMPDIR:-/tmp}/ors-pgdata.XXXXXX")"
# The Unix socket path has a hard ~103-byte limit, so keep the socket dir short and in /tmp.
PGSOCK="$(mktemp -d /tmp/orspg.XXXXXX)"
PGPORT="$(( 50000 + RANDOM % 10000 ))"
DBNAME="openres_e2e"
STARTED=0

cleanup() {
  if [ "$STARTED" = "1" ]; then
    pg_ctl -D "$PGDATA" -m immediate -w stop >/dev/null 2>&1 || true
  fi
  rm -rf "$PGDATA" "$PGSOCK"
}
trap cleanup EXIT

echo "== full-stack SSO e2e: starting ephemeral PostgreSQL on :$PGPORT =="
initdb -D "$PGDATA" -U postgres --auth=trust >/dev/null 2>&1
pg_ctl -D "$PGDATA" \
  -o "-p $PGPORT -k $PGSOCK -c listen_addresses=127.0.0.1" \
  -l "$PGDATA/server.log" -w start >/dev/null
STARTED=1
psql -h 127.0.0.1 -p "$PGPORT" -U postgres -c "CREATE DATABASE $DBNAME;" >/dev/null

export DATABASE_URL="postgresql://postgres@127.0.0.1:$PGPORT/$DBNAME"

echo "== pushing Prisma schema and generating client =="
npx prisma db push --skip-generate >/dev/null 2>&1
npx prisma generate >/dev/null 2>&1

echo "== building the application =="
npm run build >/dev/null 2>&1

echo "== driving the real app =="
node scripts/sso-nest-e2e.cjs