"""Shared fixtures. Integration tests need AGENTSHIELD_TEST_DSN (a superuser DSN) and
AGENTSHIELD_TEST_REDIS; run ``scripts/test.sh`` to start throwaway services and set them."""

from __future__ import annotations

import os
import secrets
from collections.abc import AsyncIterator
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import asyncpg
import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncEngine

from agentshield.db.engine import create_engine
from agentshield.db.migrate import migrate

ADMIN_DSN = os.environ.get("AGENTSHIELD_TEST_DSN")
REDIS_URL = os.environ.get("AGENTSHIELD_TEST_REDIS")


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if ADMIN_DSN and REDIS_URL:
        return
    skip = pytest.mark.skip(reason="set AGENTSHIELD_TEST_DSN and AGENTSHIELD_TEST_REDIS (scripts/test.sh)")
    for item in items:
        if "integration" in item.keywords or "security" in item.keywords:
            item.add_marker(skip)


def _with(dsn: str, *, user: str | None = None, password: str | None = None,
          db: str | None = None, scheme: str | None = None) -> str:
    parts = urlsplit(dsn)
    host = parts.hostname or "localhost"
    port = f":{parts.port}" if parts.port else ""
    u = user if user is not None else (parts.username or "")
    pw = f":{password}" if password else ""
    netloc = f"{u}{pw}@{host}{port}" if u else f"{host}{port}"
    path = f"/{db}" if db else parts.path
    return urlunsplit((scheme or parts.scheme, netloc, path, "", ""))


class DbUrls:
    def __init__(self, admin_dsn: str, db_name: str) -> None:
        self.db_name = db_name
        self.owner = _with(admin_dsn, db=db_name)                      # superuser (owner)
        self.app = _with(admin_dsn, user="as_app_login", password="pw", db=db_name,
                         scheme="postgresql+asyncpg")
        self.worker = _with(admin_dsn, user="as_worker_login", password="pw", db=db_name,
                            scheme="postgresql+asyncpg")
        self.retention = _with(admin_dsn, user="as_retention_login", password="pw", db=db_name,
                               scheme="postgresql+asyncpg")
        self.readonly = _with(admin_dsn, user="as_ro_login", password="pw", db=db_name,
                              scheme="postgresql+asyncpg")


@pytest_asyncio.fixture(scope="session")
async def db_urls() -> AsyncIterator[DbUrls]:
    assert ADMIN_DSN
    name = f"as_test_{secrets.token_hex(4)}"
    admin = await asyncpg.connect(ADMIN_DSN)
    try:
        await admin.execute(f'create database "{name}"')
    finally:
        await admin.close()
    await migrate(_with(ADMIN_DSN, db=name))
    conn = await asyncpg.connect(_with(ADMIN_DSN, db=name))
    try:
        for login, group in [("as_app_login", "agentshield_app"), ("as_worker_login", "agentshield_worker"),
                             ("as_retention_login", "agentshield_retention"),
                             ("as_ro_login", "agentshield_readonly")]:
            exists = await conn.fetchval("select 1 from pg_roles where rolname=$1", login)
            if not exists:
                await conn.execute(f"create role {login} login password 'pw' in role {group}")
            else:
                await conn.execute(f"grant {group} to {login}")
    finally:
        await conn.close()
    yield DbUrls(ADMIN_DSN, name)
    admin = await asyncpg.connect(ADMIN_DSN)
    try:
        await admin.execute(f'drop database if exists "{name}" with (force)')
    finally:
        await admin.close()


@pytest_asyncio.fixture(scope="session")
async def app_engine(db_urls: DbUrls) -> AsyncIterator[AsyncEngine]:
    eng = create_engine(db_urls.app, pool_size=5)
    yield eng
    await eng.dispose()


@pytest_asyncio.fixture(scope="session")
async def worker_engine(db_urls: DbUrls) -> AsyncIterator[AsyncEngine]:
    eng = create_engine(db_urls.worker, pool_size=5)
    yield eng
    await eng.dispose()


@pytest_asyncio.fixture
async def owner_conn(db_urls: DbUrls) -> AsyncIterator[asyncpg.Connection]:
    conn = await asyncpg.connect(db_urls.owner)
    try:
        yield conn
    finally:
        await conn.close()


@pytest_asyncio.fixture
async def redis_client() -> AsyncIterator[Any]:
    import redis.asyncio as aioredis

    assert REDIS_URL
    r = aioredis.from_url(REDIS_URL, decode_responses=False)
    await r.flushdb()
    yield r
    await r.flushdb()
    await r.aclose()


async def seed_tenant(conn: asyncpg.Connection, slug: str) -> dict[str, Any]:
    """Insert one row into every tenant table (as superuser); returns the ids."""
    tid = await conn.fetchval("insert into tenants (name, slug) values ($1, $2) returning id", slug, slug)
    uid = await conn.fetchval(
        "insert into users (tenant_id, email, password_hash, role) values ($1, $2, 'x', 'admin') returning id",
        tid, f"admin@{slug}.test")
    await conn.execute("insert into user_tokens (tenant_id, user_id, prefix, token_hash) values ($1,$2,$3,'\\x00')",
                       tid, uid, f"asu_{secrets.token_hex(6)}")
    up = await conn.fetchval(
        "insert into upstreams (tenant_id, name, kind, base_url) values ($1,'u','openai','https://x.test') returning id", tid)
    ag = await conn.fetchval(
        "insert into agents (tenant_id, slug, name, owner, risk_tier, upstream_id) "
        "values ($1,'agent-one','A','o','low',$2) returning id", tid, up)
    await conn.execute("insert into agent_keys (tenant_id, agent_id, prefix, key_hash) values ($1,$2,$3,'\\x00')",
                       tid, ag, f"ask_live_{secrets.token_hex(4)[:7]}")
    await conn.execute(
        "insert into policy_versions (tenant_id, agent_id, version, yaml, parsed, sha256, created_by) "
        "values ($1,$2,1,'v: 1','{}','\\x00',$3)", tid, ag, uid)
    sid = await conn.fetchval(
        "insert into sessions (tenant_id, agent_id, session_key) values ($1,$2,'k') returning id", tid, ag)
    await conn.execute(
        "insert into approvals (tenant_id, agent_id, session_id, trace_id, tool, args_hash, args_redacted, rule_id, expires_at) "
        "values ($1,$2,$3,'t-1','pay','h','{}','r', now() + interval '5 minutes')", tid, ag, sid)
    await conn.execute("insert into budget_counters (tenant_id, agent_id, day) values ($1,$2,current_date)", tid, ag)
    await conn.execute("insert into incidents (tenant_id, session_id, title, severity, created_by) "
                       "values ($1,$2,'t','high',$3)", tid, sid, uid)
    await conn.execute("insert into scan_rule_sets (tenant_id, version, yaml, sha256) values ($1,1,'r: 1','\\x00')", tid)
    await conn.execute("insert into mcp_servers (tenant_id, name, ref, pinned_version, owner) values ($1,'m','r','1','o')", tid)
    await conn.execute("insert into ai_tools_seen (tenant_id, domain, classification, first_seen, last_seen) "
                       "values ($1,'x.test','unknown', now(), now())", tid)
    await conn.execute(
        "insert into audit_events (tenant_id, seq, ts, id, trace_id, module, type, severity, summary, "
        "payload_sha256, prev_hash, hash) values ($1,1,now(),'evt_1','t-1','gateway','request.received','info','s',"
        "'\\x00','\\x00','\\x00')", tid)
    await conn.execute("insert into audit_payloads (tenant_id, seq, ts, payload) values ($1,1,now(),'{}')", tid)
    await conn.execute("insert into audit_chain_heads (tenant_id, last_seq, last_hash) values ($1,1,'\\x00')", tid)
    return {"tenant_id": tid, "user_id": uid, "agent_id": ag, "session_id": sid,
            "slug": slug, "email": f"admin@{slug}.test"}


@pytest_asyncio.fixture
async def two_tenants(owner_conn: asyncpg.Connection) -> tuple[dict[str, Any], dict[str, Any]]:
    suffix = secrets.token_hex(3)
    a = await seed_tenant(owner_conn, f"alpha-{suffix}")
    b = await seed_tenant(owner_conn, f"bravo-{suffix}")
    return a, b
