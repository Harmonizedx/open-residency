#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Persistence contract test: every Prisma store, against a real PostgreSQL.
#
# The suite this repository runs by default is hermetic -- in-memory stores, no database. That
# is fast and it is why most of it can run anywhere, but it means a whole class of defect is
# structurally invisible to it: anything that only exists between the record and the column.
#
# Two such defects shipped and were caught by hand rather than by a test. A `residenceAddress`
# column was missing for several commits while everything typechecked, because Prisma's `data`
# object is spread into the call and excess-property checking does not apply through a spread.
# Adding it exposed a second: a JSON column set to database NULL needs Prisma.DbNull, not a bare
# null. The in-memory smokes passed throughout both.
#
# So this exists to make the persistence layer answerable to a test rather than to whoever
# happens to be paying attention. It stands up a throwaway cluster, applies the committed
# migrations -- the same `migrate deploy` a deployment runs, not `db push` -- and round-trips
# every store.
#
# Skips cleanly (exit 0) when the PostgreSQL server binaries are absent, so it can sit in CI
# without becoming a machine-specific failure. Requires initdb, pg_ctl, psql on PATH.
set -euo pipefail

cd "$(dirname "$0")/.."

# CI supplies a database as a service container. Locally there is none, so one is started
# here. Same test either way -- what differs is only who owns the cluster.
if [ -n "${DATABASE_URL:-}" ]; then
  echo "== store e2e: using the DATABASE_URL already in the environment =="
  npx prisma migrate deploy >/dev/null 2>&1
  npx prisma generate >/dev/null 2>&1
  npx tsc -p tsconfig.core.json
  node dist-core/scripts/store-e2e.js
  exit $?
fi

if ! command -v initdb >/dev/null 2>&1 || ! command -v pg_ctl >/dev/null 2>&1; then
  echo "  - SKIPPED: PostgreSQL server binaries (initdb/pg_ctl) not found on PATH."
  echo "    Install them (e.g. 'brew install postgresql@14') to run this test."
  exit 0
fi

PGDATA="$(mktemp -d "${TMPDIR:-/tmp}/ors-store-pgdata.XXXXXX")"
# The Unix socket path has a hard ~103-byte limit, so keep the socket dir short and in /tmp.
PGSOCK="$(mktemp -d /tmp/orsstore.XXXXXX)"
PGPORT="$(( 50000 + RANDOM % 10000 ))"
DBNAME="openres_store_e2e"
STARTED=0

cleanup() {
  if [ "$STARTED" = "1" ]; then
    pg_ctl -D "$PGDATA" -m immediate -w stop >/dev/null 2>&1 || true
  fi
  rm -rf "$PGDATA" "$PGSOCK"
}
trap cleanup EXIT

echo "== store e2e: starting ephemeral PostgreSQL on :$PGPORT =="
initdb -D "$PGDATA" -U postgres --auth=trust >/dev/null 2>&1
pg_ctl -D "$PGDATA" \
  -o "-p $PGPORT -k $PGSOCK -c listen_addresses=127.0.0.1" \
  -l "$PGDATA/server.log" -w start >/dev/null
STARTED=1
psql -h 127.0.0.1 -p "$PGPORT" -U postgres -c "CREATE DATABASE $DBNAME;" >/dev/null

export DATABASE_URL="postgresql://postgres@127.0.0.1:$PGPORT/$DBNAME"

# `migrate deploy`, not `db push`: a deployment applies the committed migrations, and a harness
# that derived the schema from schema.prisma would pass against a shape no deployment reaches.
echo "== applying migrations =="
npx prisma migrate deploy >/dev/null 2>&1
npx prisma generate >/dev/null 2>&1

echo "== round-tripping every store =="
npx tsc -p tsconfig.core.json
node dist-core/scripts/store-e2e.js
