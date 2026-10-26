import re

import pytest

pytestmark = pytest.mark.integration


# ── signup / login ──────────────────────────────────────────────────────────────────────────────
async def test_signup_login_me(api):
    acct = await api.signup()
    r = await acct.get("/v1/auth/me")
    assert r.status_code == 200
    body = r.json()
    assert body["role"] == "admin" and body["email"] == acct.email and body["csrf_token"] == acct.csrf


async def test_signup_closed(app, api, monkeypatch):
    monkeypatch.setattr(app.state.s.settings, "signup", "closed")
    r = await api.client().post("/v1/signup", json={"tenant_name": "Nope", "email": "n@example.com",
                                                    "password": "correct-horse-battery"})
    assert r.status_code == 403 and r.json()["code"] == "forbidden"
    assert r.headers["content-type"].startswith("application/problem+json")


async def test_signup_duplicate_email_conflicts(api):
    acct = await api.signup()
    r = await api.client().post("/v1/signup", json={"tenant_name": "Other Co", "email": acct.email,
                                                    "password": "correct-horse-battery"})
    assert r.status_code == 409


async def test_weak_password_rejected(api):
    r = await api.client().post("/v1/signup", json={"tenant_name": "Weak", "email": "w@example.com", "password": "short"})
    assert r.status_code == 422 and r.json()["code"] == "validation_failed"


async def test_unknown_email_and_wrong_password_are_identical(api):
    acct = await api.signup()
    c = api.client()
    wrong = await c.post("/v1/auth/login", json={"email": acct.email, "password": "not-the-password-1"})
    unknown = await c.post("/v1/auth/login", json={"email": "nobody@example.com", "password": "not-the-password-1"})
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json()["detail"] == unknown.json()["detail"]
    assert set(wrong.json()) - {"request_id"} == set(unknown.json()) - {"request_id"}


async def test_five_bad_logins_lock_account_for_everyone_including_correct_password(api):
    acct = await api.signup()
    c = api.client()
    for _ in range(4):
        r = await c.post("/v1/auth/login", json={"email": acct.email, "password": "wrong-password-xx"})
        assert r.status_code == 401
    r = await c.post("/v1/auth/login", json={"email": acct.email, "password": "wrong-password-xx"})
    assert r.status_code == 429 and "Retry-After" in r.headers
    r = await c.post("/v1/auth/login", json={"email": acct.email, "password": "correct-horse-battery"})
    assert r.status_code == 429


async def test_unknown_email_is_rate_limited_too(api):
    c = api.client()
    codes = [(await c.post("/v1/auth/login", json={"email": "ghost@example.com", "password": "wrong-password-xx"})).status_code
             for _ in range(6)]
    assert codes[:4] == [401] * 4 and codes[4] == 429


async def test_session_cookie_flags_when_secure(db_urls, redis_client):
    from httpx import ASGITransport, AsyncClient
    from tests.conftest import make_settings

    from agentshield.gateway.app import create_app
    app = create_app(make_settings(db_urls, cookie_secure=True))
    async with app.router.lifespan_context(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="https://test") as c:
            await c.post("/v1/signup", json={"tenant_name": "Flags Inc", "email": "flags@example.com",
                                             "password": "correct-horse-battery"})
            r = await c.post("/v1/auth/login", json={"email": "flags@example.com", "password": "correct-horse-battery"})
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "secure" in cookie and "samesite=lax" in cookie


async def test_unsafe_method_without_csrf_is_forbidden(api):
    acct = await api.signup()
    r = await acct.client.post("/v1/admin/agents", json={"slug": "no-csrf", "name": "x", "owner": "o"})
    assert r.status_code == 403
    r = await acct.client.post("/v1/admin/agents", json={"slug": "no-csrf", "name": "x", "owner": "o"},
                               headers={"X-CSRF-Token": "wrong"})
    assert r.status_code == 403


async def test_unauthenticated_admin_request_is_401(api):
    r = await api.client().get("/v1/admin/agents")
    assert r.status_code == 401 and r.json()["code"] == "unauthenticated"


# ── agents & keys ───────────────────────────────────────────────────────────────────────────────
async def test_agent_crud_and_etag(api):
    acct = await api.signup()
    agent = await acct.make_agent()
    assert agent["slug"] == "email-reader-01" and agent["mode"] == "monitor" and agent["key_count"] == 0
    r = await acct.get("/v1/admin/agents/email-reader-01")
    etag = r.headers["etag"]
    r = await acct.patch("/v1/admin/agents/email-reader-01", {"mode": "enforce"})
    assert r.status_code == 428
    r = await acct.patch("/v1/admin/agents/email-reader-01", {"mode": "enforce"}, headers={"If-Match": 'W/"stale"'})
    assert r.status_code == 412
    r = await acct.patch("/v1/admin/agents/email-reader-01", {"mode": "enforce"}, headers={"If-Match": etag})
    assert r.status_code == 200 and r.json()["mode"] == "enforce"
    r = await acct.patch("/v1/admin/agents/email-reader-01", {"mode": "monitor"}, headers={"If-Match": etag})
    assert r.status_code == 412   # the old ETag no longer matches


async def test_agent_slug_validation_and_duplicates(api):
    acct = await api.signup()
    for bad in ["Email", "-x", "a", "has space", "x" * 70]:
        r = await acct.post("/v1/admin/agents", {"slug": bad, "name": "n", "owner": "o"})
        assert r.status_code == 422, bad
    await acct.make_agent("dup-agent")
    r = await acct.post("/v1/admin/agents", {"slug": "dup-agent", "name": "n", "owner": "o"})
    assert r.status_code == 409


async def test_agent_create_rejects_server_owned_fields(api):
    acct = await api.signup()
    r = await acct.post("/v1/admin/agents", {"slug": "mass-assign", "name": "n", "owner": "o",
                                             "tenant_id": "00000000-0000-0000-0000-000000000000",
                                             "status": "suspended", "active_policy_version": 9})
    assert r.status_code == 422


async def test_list_agents_pagination(api):
    acct = await api.signup()
    for i in range(5):
        await acct.make_agent(f"agent-{i}")
    r = await acct.get("/v1/admin/agents?limit=2")
    page1 = r.json()
    assert len(page1["items"]) == 2 and page1["next_cursor"]
    seen = [a["slug"] for a in page1["items"]]
    cursor = page1["next_cursor"]
    while cursor:
        page = (await acct.get(f"/v1/admin/agents?limit=2&cursor={cursor}")).json()
        seen += [a["slug"] for a in page["items"]]
        cursor = page["next_cursor"]
    assert sorted(seen) == [f"agent-{i}" for i in range(5)]
    assert (await acct.get("/v1/admin/agents?limit=500")).status_code == 422
    assert (await acct.get("/v1/admin/agents?cursor=!!!")).status_code == 422


async def test_issue_key_returns_plaintext_once_then_only_prefix(api):
    acct = await api.signup()
    await acct.make_agent()
    key = await acct.make_key()
    assert re.fullmatch(r"ask_live_[A-Za-z0-9_-]{32}", key["key"]) and key["prefix"] == key["key"][:16]
    listed = (await acct.get("/v1/admin/agents/email-reader-01/keys")).json()
    assert listed[0]["prefix"] == key["prefix"] and "key" not in listed[0] and "key_hash" not in listed[0]
    assert key["key"] not in (await acct.get("/v1/admin/agents/email-reader-01")).text


async def test_rotate_sets_old_key_expiry_to_overlap_and_returns_new_plaintext_once(api):
    acct = await api.signup()
    await acct.make_agent()
    old = await acct.make_key()
    r = await acct.post(f"/v1/admin/agents/email-reader-01/keys/{old['id']}/rotate", {"overlap_seconds": 3600})
    assert r.status_code == 201
    new = r.json()
    assert new["key"] != old["key"]
    keys = {k["id"]: k for k in (await acct.get("/v1/admin/agents/email-reader-01/keys")).json()}
    assert keys[old["id"]]["expires_at"] is not None and keys[new["id"]]["expires_at"] is None


async def test_agent_key_authenticates_revoked_and_expired_do_not(api):
    acct = await api.signup()
    await acct.make_agent()
    key = await acct.make_key()
    c = api.client()
    r = await c.post("/v1/token", headers={"Authorization": f"Bearer {key['key']}"})
    assert r.status_code == 200 and r.json()["expires_in"] == 900
    jwt_token = r.json()["access_token"]
    # a JWT cannot mint another JWT
    assert (await c.post("/v1/token", headers={"Authorization": f"Bearer {jwt_token}"})).status_code == 401
    # wrong key
    assert (await c.post("/v1/token", headers={"Authorization": "Bearer ask_live_" + "x" * 32})).status_code == 401
    # x-api-key header form
    assert (await c.post("/v1/token", headers={"x-api-key": key["key"]})).status_code == 200
    # revoke
    assert (await acct.post(f"/v1/admin/agents/email-reader-01/keys/{key['id']}/revoke")).status_code == 200
    assert (await c.post("/v1/token", headers={"Authorization": f"Bearer {key['key']}"})).status_code == 401


async def test_suspended_agent_key_is_refused(api):
    acct = await api.signup()
    await acct.make_agent()
    key = await acct.make_key()
    etag = (await acct.get("/v1/admin/agents/email-reader-01")).headers["etag"]
    await acct.patch("/v1/admin/agents/email-reader-01", {"status": "suspended"}, headers={"If-Match": etag})
    r = await api.client().post("/v1/token", headers={"Authorization": f"Bearer {key['key']}"})
    assert r.status_code == 403


async def test_agent_credentials_are_rejected_on_the_control_plane(api):
    acct = await api.signup()
    await acct.make_agent()
    key = await acct.make_key()
    r = await api.client().get("/v1/admin/agents", headers={"Authorization": f"Bearer {key['key']}"})
    assert r.status_code == 401


async def test_snippets(api):
    acct = await api.signup()
    await acct.make_agent()
    for lang, needle in [("python-openai", "OpenAI("), ("python-anthropic", "Anthropic("), ("curl", "curl "),
                         ("claude-code", "ANTHROPIC_BASE_URL")]:
        r = await acct.get(f"/v1/admin/agents/email-reader-01/snippet?lang={lang}")
        assert r.status_code == 200 and needle in r.json()["code"] and "ask_live_..." in r.json()["code"]
    assert (await acct.get("/v1/admin/agents/email-reader-01/snippet?lang=cobol")).status_code == 422


async def test_agent_upstream_must_belong_to_tenant(api):
    a, b = await api.signup(), await api.signup()
    up_b = await b.make_upstream()
    r = await a.post("/v1/admin/agents", {"slug": "steal", "name": "n", "owner": "o", "upstream_id": up_b["id"]})
    assert r.status_code == 422      # FK checks bypass RLS, so the API must reject foreign ids explicitly


# ── upstreams ───────────────────────────────────────────────────────────────────────────────────
async def test_upstream_read_never_contains_key_material(api):
    acct = await api.signup()
    up = await acct.make_upstream(api_key="sk-live-supersecret")
    assert up["has_key"] is True
    for r in [await acct.get(f"/v1/admin/upstreams/{up['id']}"), await acct.get("/v1/admin/upstreams")]:
        assert "supersecret" not in r.text and "key_ciphertext" not in r.text and "api_key" not in r.text


async def test_upstream_key_is_encrypted_at_rest(api, owner_conn):
    acct = await api.signup()
    up = await acct.make_upstream(api_key="sk-live-supersecret")
    blob = await owner_conn.fetchval("select key_ciphertext from upstreams where id = $1::uuid", up["id"])
    assert blob and b"supersecret" not in bytes(blob)


async def test_upstream_rejects_ssrf_urls(api):
    acct = await api.signup()
    for url in ["http://169.254.169.254/latest", "https://127.0.0.1/v1", "http://example.com/v1", "https://10.1.2.3"]:
        r = await acct.post("/v1/admin/upstreams", {"name": "bad", "kind": "openai", "base_url": url})
        assert r.status_code == 422, url


async def test_upstream_update_rotates_key_and_delete_guard(api):
    acct = await api.signup()
    up = await acct.make_upstream()
    r = await acct.patch(f"/v1/admin/upstreams/{up['id']}", {"api_key": "sk-new", "judge_model": "gpt-4.1-mini"})
    assert r.status_code == 200 and r.json()["judge_model"] == "gpt-4.1-mini"
    await acct.make_agent(upstream_id=up["id"])
    assert (await acct.delete(f"/v1/admin/upstreams/{up['id']}")).status_code == 409


async def test_logs_never_contain_provider_key(api, caplog):
    caplog.set_level("DEBUG")
    acct = await api.signup()
    await acct.make_upstream(api_key="sk-live-leakcheck-12345")
    assert "leakcheck" not in caplog.text


# ── users, roles, settings ──────────────────────────────────────────────────────────────────────
async def test_roles_viewer_cannot_write_analyst_cannot_admin(api):
    admin = await api.signup()
    viewer = await api.add_user(admin, "viewer")
    analyst = await api.add_user(admin, "analyst")
    assert (await viewer.get("/v1/admin/agents")).status_code == 200
    assert (await viewer.post("/v1/admin/agents", {"slug": "v-agent", "name": "n", "owner": "o"})).status_code == 403
    assert (await analyst.post("/v1/admin/agents", {"slug": "a-agent", "name": "n", "owner": "o"})).status_code == 403
    assert (await analyst.get("/v1/admin/users")).status_code == 403
    assert (await admin.get("/v1/admin/users")).status_code == 200


async def test_cannot_remove_last_admin(api):
    admin = await api.signup()
    me = (await admin.get("/v1/auth/me")).json()
    r = await admin.patch(f"/v1/admin/users/{me['user_id']}", {"role": "viewer"})
    assert r.status_code == 409
    r = await admin.patch(f"/v1/admin/users/{me['user_id']}", {"disabled": True})
    assert r.status_code == 409


async def test_disabled_user_session_stops_working(api):
    admin = await api.signup()
    viewer = await api.add_user(admin, "viewer")
    uid = (await viewer.get("/v1/auth/me")).json()["user_id"]
    assert (await admin.patch(f"/v1/admin/users/{uid}", {"disabled": True})).status_code == 200
    assert (await viewer.get("/v1/admin/agents")).status_code == 401


async def test_role_change_takes_effect_on_existing_session(api):
    admin = await api.signup()
    other = await api.add_user(admin, "admin")
    uid = (await other.get("/v1/auth/me")).json()["user_id"]
    assert (await admin.patch(f"/v1/admin/users/{uid}", {"role": "viewer"})).status_code == 200
    assert (await other.get("/v1/admin/users")).status_code == 403


async def test_settings_defaults_floors_and_validation(api):
    acct = await api.signup()
    r = await acct.get("/v1/admin/settings")
    assert r.status_code == 200
    cur = r.json()
    assert cur["on_malicious"] == "sanitize" and cur["retention"] == {"payload_days": 30, "envelope_days": 180, "incident_days": 1095}
    etag = r.headers["etag"]
    assert (await acct.patch("/v1/admin/settings", {"on_malicious": "flag"})).status_code == 428
    bad = await acct.patch("/v1/admin/settings", {"retention": {"envelope_days": 30}}, headers={"If-Match": etag})
    assert bad.status_code == 422                       # below the 180-day floor
    bad = await acct.patch("/v1/admin/settings", {"webhook_url": "http://169.254.169.254/x"}, headers={"If-Match": etag})
    assert bad.status_code == 422
    ok = await acct.patch("/v1/admin/settings", {"on_malicious": "quarantine", "webhook_url": "https://hooks.slack.com/x"},
                          headers={"If-Match": etag})
    assert ok.status_code == 200 and ok.json()["on_malicious"] == "quarantine"
    assert (await acct.get("/v1/admin/settings")).json()["webhook_url"] == "https://hooks.slack.com/x"


async def test_settings_judge_upstream_must_be_own(api):
    a, b = await api.signup(), await api.signup()
    up_b = await b.make_upstream()
    etag = (await a.get("/v1/admin/settings")).headers["etag"]
    r = await a.patch("/v1/admin/settings", {"judge_upstream_id": up_b["id"]}, headers={"If-Match": etag})
    assert r.status_code == 422


# ── idempotency ─────────────────────────────────────────────────────────────────────────────────
async def test_idempotency_replays_and_detects_conflicts(api):
    acct = await api.signup()
    body = {"slug": "idem-agent", "name": "n", "owner": "o"}
    h = {"Idempotency-Key": "abc-123"}
    r1 = await acct.post("/v1/admin/agents", body, headers=h)
    r2 = await acct.post("/v1/admin/agents", body, headers=h)
    assert r1.status_code == r2.status_code == 201
    assert r2.headers.get("idempotency-replayed") == "true" and r1.json() == r2.json()
    r3 = await acct.post("/v1/admin/agents", {**body, "name": "different"}, headers=h)
    assert r3.status_code == 409 and r3.json()["code"] == "idempotency_conflict"
    assert len((await acct.get("/v1/admin/agents")).json()["items"]) == 1


async def test_idempotency_keys_do_not_cross_credentials(api):
    a, b = await api.signup(), await api.signup()
    h = {"Idempotency-Key": "shared-key"}
    r1 = await a.post("/v1/admin/agents", {"slug": "same-slug", "name": "n", "owner": "o"}, headers=h)
    r2 = await b.post("/v1/admin/agents", {"slug": "same-slug", "name": "n", "owner": "o"}, headers=h)
    assert r1.status_code == r2.status_code == 201 and "idempotency-replayed" not in r2.headers


# ── misc ────────────────────────────────────────────────────────────────────────────────────────
async def test_request_id_header_and_problem_shape(api):
    r = await api.client().get("/v1/admin/agents", headers={"X-Request-Id": "req_test_1"})
    assert r.headers["x-request-id"] == "req_test_1"
    assert r.json()["request_id"] == "req_test_1" and r.json()["type"].endswith("/unauthenticated")


async def test_unknown_route_and_validation_problem(api):
    c = api.client()
    r = await c.get("/v1/nope")
    assert r.status_code == 404 and r.json()["code"] == "not_found"
    acct = await api.signup()
    r = await acct.post("/v1/admin/agents", {"slug": "BAD"})
    assert r.status_code == 422 and r.json()["errors"]


async def test_health_endpoints(api):
    c = api.client()
    assert (await c.get("/healthz")).json() == {"status": "ok"}
    ready = await c.get("/readyz")
    assert ready.status_code == 200 and ready.json()["database"] == "ok" and ready.json()["redis"] == "ok"
