"""OWASP API Security Top 10 (2023) checks that are not covered by a feature's own tests (api spec §A.6)."""

import inspect

import httpx
import pytest
from pydantic import ValidationError
from tests.conftest import api_routes

from agentshield.contracts import admin as admin_contracts
from agentshield.gateway.app import create_app
from agentshield.settings import Settings

pytestmark = [pytest.mark.integration, pytest.mark.security]

SECRET_FIELDS = {"key_hash", "key_ciphertext", "password_hash", "token_hash", "hash_pepper", "master_key", "jwt_secret"}


# ── API8: security misconfiguration ──────────────────────────────────────────────────────────────
@pytest.mark.parametrize("path", ["/healthz", "/v1/admin/agents", "/v1/messages", "/no-such-route"])
async def test_security_headers_are_on_every_response_even_errors(api, path):
    r = await api.client().get(path)
    assert r.headers["x-content-type-options"] == "nosniff" and r.headers["x-frame-options"] == "DENY"
    assert r.headers["referrer-policy"] == "no-referrer"
    assert r.headers["content-security-policy"] == "default-src 'none'; frame-ancestors 'none'"
    assert "geolocation=()" in r.headers["permissions-policy"]


async def test_admin_and_auth_responses_are_never_cached(api):
    acct = await api.signup()
    assert (await acct.get("/v1/admin/agents")).headers["cache-control"] == "no-store"
    assert (await api.client().post("/v1/auth/login", json={"email": "x@example.com", "password": "nope-nope-nope"})).headers["cache-control"] == "no-store"


async def test_hsts_is_sent_when_cookies_are_secure_and_in_prod(app, api):
    assert "strict-transport-security" not in (await api.client().get("/healthz")).headers      # test settings: cookie_secure=False
    secure = create_app(Settings(env="dev", cookie_secure=True))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=secure), base_url="http://t") as c:
        assert "max-age=" in (await c.get("/healthz")).headers["strict-transport-security"]


async def test_docs_and_openapi_are_off_in_prod_and_on_in_dev():
    for env, status in (("prod", 404), ("dev", 200)):
        application = create_app(Settings(env=env))
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=application), base_url="http://t") as c:
            assert (await c.get("/openapi.json")).status_code == status, env
            assert (await c.get("/docs")).status_code == status, env


async def test_docs_page_is_not_blocked_by_the_strict_csp():
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app(Settings(env="dev"))), base_url="http://t") as c:
        assert "content-security-policy" not in (await c.get("/docs")).headers


def test_wildcard_cors_is_refused_at_startup():
    for bad in ("*", "https://a.example.com, *"):
        with pytest.raises(ValidationError, match="wildcard"):
            Settings(cors_origins=bad)
    assert Settings(cors_origins="https://a.example.com,https://b.example.com").cors_origins


async def test_cors_only_reflects_the_configured_dashboard_origin(api):
    c = api.client()
    ok = await c.options("/v1/admin/agents", headers={"Origin": "http://localhost:5173", "Access-Control-Request-Method": "GET"})
    assert ok.headers["access-control-allow-origin"] == "http://localhost:5173" and ok.headers["access-control-allow-credentials"] == "true"
    evil = await c.options("/v1/admin/agents", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"})
    assert "access-control-allow-origin" not in evil.headers
    simple = await c.get("/healthz", headers={"Origin": "https://evil.example"})
    assert "access-control-allow-origin" not in simple.headers


def test_debug_is_off_and_no_route_returns_a_stack_trace(app):
    assert app.debug is False


async def test_unhandled_errors_do_not_leak_internals(api, app, monkeypatch):
    async def boom(*a, **kw):
        raise RuntimeError("secret internal detail /srv/app/x.py")

    monkeypatch.setattr(app.state.s.approvals, "list", boom)
    acct = await api.signup()
    quiet = httpx.AsyncClient(transport=httpx.ASGITransport(app=app, raise_app_exceptions=False), base_url="http://test",
                              cookies=acct.client.cookies)
    r = await quiet.get("/v1/admin/approvals")
    await quiet.aclose()
    assert r.status_code == 500 and "secret internal detail" not in r.text and "Traceback" not in r.text
    assert r.json()["status"] == 500 and r.headers["content-type"].startswith("application/problem+json")


# ── API3: object property level ──────────────────────────────────────────────────────────────────
def test_read_models_never_expose_secrets():
    reads = [c for _, c in inspect.getmembers(admin_contracts, inspect.isclass)
             if issubclass(c, admin_contracts.Out) and c is not admin_contracts.Out]
    assert len(reads) > 15
    leaked = [(c.__name__, f) for c in reads for f in c.model_fields if f in SECRET_FIELDS]
    assert leaked == []


def test_openapi_responses_never_mention_secret_fields_or_write_only_api_keys():
    spec = create_app(Settings(env="dev")).openapi()["components"]["schemas"]
    for name, schema in spec.items():
        props = set(schema.get("properties", {}))
        assert not props & SECRET_FIELDS, name
        if name.endswith(("Read", "Issued")) or name in {"TenantSettings"}:
            assert "api_key" not in props and "password" not in props, name


async def test_upstream_read_hides_the_provider_key_and_shows_only_that_one_is_set(api):
    acct = await api.signup()
    up = await acct.make_upstream("hidden", api_key="sk-super-secret-value")
    body = (await acct.get(f"/v1/admin/upstreams/{up['id']}")).text
    assert "sk-super-secret-value" not in body and "key_ciphertext" not in body


# ── API4: resource consumption ───────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("path", ["/v1/admin/events", "/v1/admin/sessions", "/v1/admin/alerts", "/v1/admin/incidents",
                                  "/v1/admin/agents", "/v1/admin/approvals", "/v1/admin/users"])
async def test_page_size_is_capped_at_200(api, path):
    acct = await api.signup()
    assert (await acct.get(f"{path}?limit=200")).status_code == 200
    assert (await acct.get(f"{path}?limit=201")).status_code == 422
    assert (await acct.get(f"{path}?limit=0")).status_code == 422


async def test_app_database_role_has_a_statement_timeout(app):
    from sqlalchemy import text
    async with app.state.s.engine.connect() as conn:
        assert (await conn.execute(text("show statement_timeout"))).scalar_one() == "5s"
        assert (await conn.execute(text("show idle_in_transaction_session_timeout"))).scalar_one() == "10s"


async def test_a_slow_query_is_cancelled_not_left_running(app):
    from sqlalchemy import text
    from sqlalchemy.exc import DBAPIError
    async with app.state.s.engine.connect() as conn:
        await conn.execute(text("set statement_timeout = '200ms'"))
        with pytest.raises(DBAPIError, match="statement timeout"):
            await conn.execute(text("select pg_sleep(2)"))


# ── API9: inventory ──────────────────────────────────────────────────────────────────────────────
def test_no_route_is_undocumented_except_the_internal_ones(app):
    spec = app.openapi()["paths"]
    undocumented = {r.path for r in api_routes(app) if r.path not in spec}
    assert undocumented == {"/metrics"}


# ── API2/API5: data-plane credentials vs control plane, once more on the new routes ──────────────
async def test_agent_key_cannot_reach_any_new_control_plane_route(api):
    acct = await api.signup()
    await acct.make_agent("probe")
    key = (await acct.make_key("probe"))["key"]
    c = api.client()
    for path in ("/v1/admin/sessions", "/v1/admin/incidents", "/v1/admin/alerts", "/v1/admin/stats/overview", "/v1/admin/events"):
        assert (await c.get(path, headers={"Authorization": f"Bearer {key}"})).status_code == 401, path


# ── found by Schemathesis: explicit null and integer overflow used to be 500s ───────────────────────
async def test_null_for_a_required_field_in_a_patch_is_a_422_not_a_500(api):
    acct = await api.signup()
    up = await acct.make_upstream("fuzz")
    agent = await acct.make_agent("fuzz-agent")
    etag = (await acct.get(f"/v1/admin/agents/{agent['slug']}")).headers["etag"]
    for field in ("name", "base_url", "model_map"):
        r = await acct.patch(f"/v1/admin/upstreams/{up['id']}", {field: None})
        assert r.status_code == 422, field
    for field in ("name", "owner", "risk_tier", "mode", "status"):
        r = await acct.patch(f"/v1/admin/agents/{agent['slug']}", {field: None}, headers={"If-Match": etag})
        assert r.status_code == 422, field
    me = (await acct.get("/v1/admin/users")).json()["items"][0]["id"]
    assert (await acct.patch(f"/v1/admin/users/{me}", {"role": None})).status_code == 422
    assert (await acct.patch(f"/v1/admin/upstreams/{up['id']}", {"judge_model": None})).status_code == 200      # nullable: allowed


async def test_huge_integers_are_rejected_before_they_reach_the_database(api):
    acct = await api.signup()
    await acct.make_agent("big")
    assert (await acct.post("/v1/admin/agents/big/policy/simulate", {"version": 3_863_834_606})).status_code == 422
    assert (await acct.get("/v1/admin/agents/big/policy/versions/3863834606")).status_code == 422
    assert (await acct.post("/v1/admin/agents/big/policy/versions/3863834606/activate", {}, headers={"If-Match": "*"})).status_code == 422
    assert (await acct.post("/v1/admin/agents/big/policy/versions", {"yaml": "version: 1\n", "version": 3_863_834_606})).status_code == 422
