#!/usr/bin/env bash
# Run a complete local AgentShield backend on a throwaway database: migrate, seed the demo tenant, start the
# audit worker and the API. Used by the dashboard's end-to-end tests and handy for trying things by hand.
#   demo login: demo@example.com / demo-password-123      API: http://127.0.0.1:${PORT:-8000}
set -euo pipefail
cd "$(dirname "$0")/.."
PY=${PY:-.venv/bin/python}
./scripts/dev-services.sh >/dev/null 2>&1 || true
DSN=${AGENTSHIELD_TEST_DSN:-postgresql://postgres@localhost:5433/postgres}
REDIS=${AGENTSHIELD_TEST_REDIS:-redis://localhost:6380/0}
PORT=${PORT:-8000}
DB=${STACK_DB:-agentshield_stack}
base=${DSN%/*}
$PY - "$DSN" "$DB" <<'PYEOF'
import asyncio, sys, asyncpg
async def main(dsn, db):
    c = await asyncpg.connect(dsn)
    await c.execute(f'drop database if exists "{db}" with (force)')
    await c.execute(f'create database "{db}"'); await c.close()
asyncio.run(main(*sys.argv[1:]))
PYEOF
export AGENTSHIELD_OWNER_DATABASE_URL="$base/$DB"
$PY -m agentshield.cli db upgrade >/dev/null
AGENTSHIELD_APP_PASSWORD=pw AGENTSHIELD_WORKER_PASSWORD=pw $PY -m agentshield.cli db create-logins >/dev/null
host=${base#*://}; host=${host#*@}
export AGENTSHIELD_DATABASE_URL="postgresql+asyncpg://agentshield_app_login:pw@${host}/$DB"
export AGENTSHIELD_WORKER_DATABASE_URL="postgresql+asyncpg://agentshield_worker_login:pw@${host}/$DB"
export AGENTSHIELD_REDIS_URL="$REDIS" AGENTSHIELD_ENV=${AGENTSHIELD_ENV:-dev} AGENTSHIELD_COOKIE_SECURE=false
export AGENTSHIELD_MASTER_KEY=${AGENTSHIELD_MASTER_KEY:-$($PY -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")}
export AGENTSHIELD_KEY_PEPPER=${AGENTSHIELD_KEY_PEPPER:-$(head -c 32 /dev/urandom | base64)}
export AGENTSHIELD_JWT_SECRET=${AGENTSHIELD_JWT_SECRET:-$(head -c 32 /dev/urandom | base64)}
export AGENTSHIELD_SESSION_SECRET=${AGENTSHIELD_SESSION_SECRET:-$(head -c 32 /dev/urandom | base64)}
export AGENTSHIELD_SPOOL_DIR=${AGENTSHIELD_SPOOL_DIR:-$(mktemp -d)}
$PY -c "import redis; redis.Redis.from_url('$REDIS').flushdb()"
$PY -m agentshield.cli seed-demo --password demo-password-123 >/dev/null
$PY -m agentshield.cli worker &
WORKER=$!
trap 'kill $WORKER 2>/dev/null || true' EXIT
exec $PY -m uvicorn agentshield.gateway.app:create_app --factory --host 127.0.0.1 --port "$PORT" --log-level warning
