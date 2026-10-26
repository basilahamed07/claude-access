#!/usr/bin/env bash
# Fuzz the running API from openapi.json with Schemathesis; fails on any 5xx or contract violation.
# Needs Postgres + Redis (AGENTSHIELD_TEST_DSN / AGENTSHIELD_TEST_REDIS, as for the tests). Runs as a signed-in demo admin.
set -euo pipefail
cd "$(dirname "$0")/.."
PY=${PY:-.venv/bin/python}
DSN=${AGENTSHIELD_TEST_DSN:-postgresql://postgres@localhost:5433/postgres}
REDIS=${AGENTSHIELD_TEST_REDIS:-redis://localhost:6380/0}
PORT=${PORT:-8765}
DB="as_fuzz_$$"
base=${DSN%/*}
$PY - "$DSN" "$DB" <<'PYEOF'
import asyncio, sys, asyncpg
async def main(dsn, db):
    c = await asyncpg.connect(dsn)
    await c.execute(f'create database "{db}"'); await c.close()
asyncio.run(main(*sys.argv[1:]))
PYEOF
export AGENTSHIELD_OWNER_DATABASE_URL="$base/$DB"
$PY -m agentshield.cli db upgrade >/dev/null
$PY - "$AGENTSHIELD_OWNER_DATABASE_URL" <<'PYEOF'
import asyncio, sys, asyncpg
async def main(dsn):
    c = await asyncpg.connect(dsn)
    for login, group in [("as_app_login", "agentshield_app"), ("as_worker_login", "agentshield_worker")]:
        if not await c.fetchval("select 1 from pg_roles where rolname=$1", login):
            await c.execute(f"create role {login} login password 'pw' in role {group}")
    await c.close()
asyncio.run(main(sys.argv[1]))
PYEOF
host=${base#*://}; host=${host#*@}
export AGENTSHIELD_DATABASE_URL="postgresql+asyncpg://as_app_login:pw@${host}/$DB"
export AGENTSHIELD_REDIS_URL="$REDIS" AGENTSHIELD_ENV=test AGENTSHIELD_COOKIE_SECURE=false
export AGENTSHIELD_MASTER_KEY=$($PY -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
export AGENTSHIELD_KEY_PEPPER=$(head -c 32 /dev/urandom | base64) AGENTSHIELD_JWT_SECRET=$(head -c 32 /dev/urandom | base64)
export AGENTSHIELD_SESSION_SECRET=$(head -c 32 /dev/urandom | base64) AGENTSHIELD_SPOOL_DIR=$(mktemp -d)
$PY -m agentshield.cli seed-demo --password fuzz-password-123 >/dev/null
$PY -m uvicorn agentshield.gateway.app:create_app --factory --port "$PORT" --log-level warning &
SERVER=$!
cleanup() { kill "$SERVER" 2>/dev/null || true; $PY - "$DSN" "$DB" <<'PYEOF'
import asyncio, sys, asyncpg
async def main(dsn, db):
    c = await asyncpg.connect(dsn)
    await c.execute(f'drop database if exists "{db}" with (force)'); await c.close()
asyncio.run(main(*sys.argv[1:]))
PYEOF
}
trap cleanup EXIT
for _ in $(seq 1 50); do curl -sf "http://127.0.0.1:$PORT/healthz" >/dev/null && break; sleep 0.2; done
JAR=$(mktemp)
CSRF=$(curl -sf -c "$JAR" -H 'content-type: application/json' -d '{"email":"demo@example.com","password":"fuzz-password-123"}' \
  "http://127.0.0.1:$PORT/v1/auth/login" | $PY -c "import sys,json; print(json.load(sys.stdin)['csrf_token'])")
COOKIE=$(awk '$6=="as_session"{print $6"="$7}' "$JAR")
SCHEMATHESIS=${SCHEMATHESIS:-.venv/bin/schemathesis}
"$SCHEMATHESIS" run openapi.json --url "http://127.0.0.1:$PORT" \
  -H "Cookie: $COOKIE" -H "X-CSRF-Token: $CSRF" \
  --checks not_a_server_error,response_schema_conformance,status_code_conformance \
  --max-examples "${MAX_EXAMPLES:-30}" --workers 2 --exclude-path /v1/auth/logout
