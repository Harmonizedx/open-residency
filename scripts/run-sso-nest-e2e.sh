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

echo "== applying migrations and generating client =="
# `migrate deploy`, not `db push`, because that is what the deployment runs: both the Helm
# chart and the raw k8s manifests apply migrations from prisma/migrations in an init
# container. `db push` derives the schema straight from schema.prisma, so this harness used
# to pass against a schema no deployment could actually reach -- which is how a missing
# migrations directory stayed invisible while every test was green.
npx prisma migrate deploy >/dev/null 2>&1
npx prisma generate >/dev/null 2>&1

echo "== building the application =="
npm run build >/dev/null 2>&1

echo "== driving the real app =="
node scripts/sso-nest-e2e.cjs
# Second app boot against the same cluster: an OIDC provider acting as the foundational
# register (#116). Separate because it needs a different country config, and so a different
# boot; standing up another PostgreSQL for it would double the slowest job in CI for nothing.
echo "== driving the real app: an OIDC provider as the register =="
node scripts/identity-oidc-nest-e2e.cjs
