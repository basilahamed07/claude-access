#!/usr/bin/env bash
# Start throwaway Postgres (5433) and Redis (6380) for local tests. Idempotent.
set -euo pipefail
PGDATA=${PGDATA:-/tmp/pgdata}
PGBIN=$(ls -d /usr/lib/postgresql/*/bin | sort -V | tail -1)
if ! "$PGBIN/pg_isready" -h localhost -p 5433 >/dev/null 2>&1; then
  if [ ! -d "$PGDATA/base" ]; then
    mkdir -p "$PGDATA"; chown postgres:postgres "$PGDATA"
    su postgres -c "$PGBIN/initdb -D $PGDATA -A trust -E UTF8 >/dev/null"
  fi
  su postgres -c "$PGBIN/pg_ctl -D $PGDATA -o '-p 5433 -k /tmp' -l /tmp/pg.log start" >/dev/null
fi
redis-cli -p 6380 ping >/dev/null 2>&1 || redis-server --port 6380 --daemonize yes --save "" >/dev/null
echo "postgres: postgresql://postgres@localhost:5433/postgres   redis: redis://localhost:6380/0"
