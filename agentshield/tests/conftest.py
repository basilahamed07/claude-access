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


# ── API harness ─────────────────────────────────────────────────────────────────────────────────
import httpx  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi.routing import APIRoute  # noqa: E402

from agentshield.gateway.app import create_app  # noqa: E402
from agentshield.settings import Settings  # noqa: E402
from agentshield.tenants import urls as _urls  # noqa: E402
from agentshield.tenants.crypto import generate_master_key  # noqa: E402

PUBLIC_IP = "93.184.216.34"


def api_routes(app: FastAPI) -> list[APIRoute]:
    out: list[APIRoute] = []
    for r in app.routes:
        original = getattr(r, "original_router", None)
        if original is not None:
            out.extend(x for x in original.routes if isinstance(x, APIRoute))
        elif isinstance(r, APIRoute):
            out.append(r)
    return out


def make_settings(db_urls: DbUrls, **over: Any) -> Settings:
    base: dict[str, Any] = dict(
        env="test", database_url=db_urls.app, owner_database_url=db_urls.owner,
        redis_url=REDIS_URL or "", master_key=generate_master_key(), key_pepper="p" * 40,
        jwt_secret="j" * 40, session_secret="s" * 40, cookie_secure=False, signup="open",
    )
    base.update(over)
    return Settings(**base)


@pytest_asyncio.fixture(scope="session")
async def app(db_urls: DbUrls) -> AsyncIterator[FastAPI]:
    application = create_app(make_settings(db_urls))
    async with application.router.lifespan_context(application):
        yield application


class Account:
    def __init__(self, client: httpx.AsyncClient, tenant_id: str, email: str, csrf: str, slug: str) -> None:
        self.client, self.tenant_id, self.email, self.csrf, self.slug = client, tenant_id, email, csrf, slug

    @property
    def h(self) -> dict[str, str]:
        return {"X-CSRF-Token": self.csrf}

    async def post(self, url: str, json: Any = None, **kw: Any) -> httpx.Response:
        return await self.client.post(url, json=json, headers={**self.h, **kw.pop("headers", {})}, **kw)

    async def patch(self, url: str, json: Any = None, **kw: Any) -> httpx.Response:
        return await self.client.patch(url, json=json, headers={**self.h, **kw.pop("headers", {})}, **kw)

    async def delete(self, url: str, **kw: Any) -> httpx.Response:
        return await self.client.delete(url, headers={**self.h, **kw.pop("headers", {})}, **kw)

    async def get(self, url: str, **kw: Any) -> httpx.Response:
        return await self.client.get(url, **kw)

    async def make_agent(self, slug: str = "email-reader-01", **over: Any) -> dict[str, Any]:
        body = {"slug": slug, "name": "Email reader", "owner": "ops@example.com", "risk_tier": "medium", **over}
        r = await self.post("/v1/admin/agents", body)
        assert r.status_code == 201, r.text
        return r.json()

    async def make_key(self, slug: str = "email-reader-01") -> dict[str, Any]:
        r = await self.post(f"/v1/admin/agents/{slug}/keys")
        assert r.status_code == 201, r.text
        return r.json()

    async def make_upstream(self, name: str = "main", **over: Any) -> dict[str, Any]:
        body = {"name": name, "kind": "openai", "base_url": "https://api.openai.com/v1", "api_key": "sk-test-123",
                **over}
        r = await self.post("/v1/admin/upstreams", body)
        assert r.status_code == 201, r.text
        return r.json()


class Api:
    def __init__(self, app: FastAPI, redis_client: Any) -> None:
        self.app = app
        self.redis = redis_client
        self._clients: list[httpx.AsyncClient] = []

    def client(self, **kw: Any) -> httpx.AsyncClient:
        c = httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app), base_url="http://test", **kw)
        self._clients.append(c)
        return c

    async def signup(self, name: str | None = None, password: str = "correct-horse-battery") -> Account:
        tag = secrets.token_hex(3)
        name = name or f"Acme {tag}"
        email = f"admin-{tag}@example.com"
        c = self.client()
        r = await c.post("/v1/signup", json={"tenant_name": name, "email": email, "password": password})
        assert r.status_code == 201, r.text
        slug = r.json()["slug"]
        r = await c.post("/v1/auth/login", json={"email": email, "password": password})
        assert r.status_code == 200, r.text
        return Account(c, r.json()["tenant_id"], email, r.json()["csrf_token"], slug)

    async def add_user(self, admin: Account, role: str, password: str = "correct-horse-battery") -> Account:
        email = f"{role}-{secrets.token_hex(3)}@example.com"
        r = await admin.post("/v1/admin/users", {"email": email, "password": password, "role": role})
        assert r.status_code == 201, r.text
        c = self.client()
        r = await c.post("/v1/auth/login", json={"email": email, "password": password})
        assert r.status_code == 200, r.text
        return Account(c, r.json()["tenant_id"], email, r.json()["csrf_token"], admin.slug)

    async def aclose(self) -> None:
        for c in self._clients:
            await c.aclose()


@pytest_asyncio.fixture
async def api(app: FastAPI, redis_client: Any, monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[Api]:
    monkeypatch.setattr(_urls, "_default_resolver", lambda host, port: [PUBLIC_IP])
    helper = Api(app, redis_client)
    yield helper
    await helper.aclose()


# ── stub provider ───────────────────────────────────────────────────────────────────────────────
from agentshield.testing.stub_upstream import StubUpstream  # noqa: E402


@pytest_asyncio.fixture
async def stub(app: FastAPI) -> AsyncIterator[StubUpstream]:
    """Route the gateway's upstream traffic to an in-process scripted provider."""
    s = StubUpstream()
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=s.app), base_url="http://stub")
    state = app.state.s
    original = state.upstream.http
    state.upstream.http = client
    yield s
    state.upstream.http = original
    await client.aclose()


class ProxyWorld:
    def __init__(self, acct: Account, openai_key: str, anthropic_key: str, api: Api) -> None:
        self.acct, self.openai_key, self.anthropic_key, self.api = acct, openai_key, anthropic_key, api

    def oa(self, key: str | None = None, **headers: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {key or self.openai_key}", **headers}

    def an(self, key: str | None = None, **headers: str) -> dict[str, str]:
        return {"x-api-key": key or self.anthropic_key, "anthropic-version": "2023-06-01", **headers}


@pytest_asyncio.fixture
async def world(api: Api, stub: StubUpstream) -> ProxyWorld:
    acct = await api.signup()
    await acct.make_upstream("oa", kind="openai", base_url="https://api.openai.com/v1", api_key="sk-provider-openai",
                             model_map={"fast": {"model": "gpt-4.1-mini"},
                                        "gpt-4.1": {"model": "gpt-4.1", "input_micro_usd_per_mtok": 2_000_000,
                                                    "output_micro_usd_per_mtok": 8_000_000}})
    price = {"input_micro_usd_per_mtok": 3_000_000, "output_micro_usd_per_mtok": 15_000_000}
    up_an = await acct.make_upstream("an", kind="anthropic", base_url="https://api.anthropic.com",
                                     api_key="sk-ant-provider",
                                     model_map={"claude-x": {"model": "claude-x", **price}, "m": {"model": "m", **price}})
    up_oa = (await acct.get("/v1/admin/upstreams")).json()
    oa_id = next(u["id"] for u in up_oa if u["name"] == "oa")
    await acct.make_agent("oa-agent", upstream_id=oa_id)
    await acct.make_agent("an-agent", upstream_id=up_an["id"])
    k1, k2 = await acct.make_key("oa-agent"), await acct.make_key("an-agent")
    return ProxyWorld(acct, k1["key"], k2["key"], api)


# ── helpers used by several suites ───────────────────────────────────────────────────────────────
import json as _json  # noqa: E402
from pathlib import Path as _Path  # noqa: E402

from agentshield.audit.worker import AuditWorker  # noqa: E402

POLICY_SAMPLE = (_Path(__file__).resolve().parent / "fixtures" / "policies" / "email_reader.yaml").read_text()


async def drain(worker: AuditWorker) -> int:
    total = 0
    while n := await worker.process_once():
        total += n
    return total


async def set_policy(acct: Account, slug: str, yaml_text: str | None = None, *, mode: str = "enforce") -> None:
    """Create + activate a policy version for `slug` and set its mode."""
    text = (yaml_text or POLICY_SAMPLE).replace("agent: email-reader-01\n", "")
    r = await acct.post(f"/v1/admin/agents/{slug}/policy/versions", {"yaml": text})
    assert r.status_code == 201, r.text
    etag = (await acct.get(f"/v1/admin/agents/{slug}")).headers["etag"]
    r = await acct.post(f"/v1/admin/agents/{slug}/policy/versions/{r.json()['version']}/activate", headers={"If-Match": etag})
    assert r.status_code == 200, r.text
    etag = (await acct.get(f"/v1/admin/agents/{slug}")).headers["etag"]
    r = await acct.patch(f"/v1/admin/agents/{slug}", {"mode": mode}, headers={"If-Match": etag})
    assert r.status_code == 200, r.text


async def events_of(acct: Account, worker: AuditWorker, **params: str) -> list[dict[str, Any]]:
    await drain(worker)
    qs = "&".join(f"{k}={v}" for k, v in params.items())
    r = await acct.get(f"/v1/admin/events?limit=200&include_payload=true&{qs}")
    assert r.status_code == 200, r.text
    return list(reversed(r.json()["items"]))


_ = _json


@pytest_asyncio.fixture
async def webhook(app: FastAPI) -> AsyncIterator[dict[str, Any]]:
    """Capture webhook deliveries instead of sending them. `sink["fail"]=N` makes the first N deliveries fail."""
    sink: dict[str, Any] = {"requests": [], "fail": 0, "status": 200}

    def handler(request: httpx.Request) -> httpx.Response:
        if sink["fail"] > 0:
            sink["fail"] -= 1
            return httpx.Response(500)
        sink["requests"].append((str(request.url), _json.loads(request.content)))
        return httpx.Response(sink["status"])

    state = app.state.s
    original = state.approvals.http
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    state.approvals.http = client
    yield sink
    await state.approvals.drain_notifications()
    state.approvals.http = original
    await client.aclose()
