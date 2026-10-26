"""M4 end to end: ingest proxy / DNS logs, inventory, classification, alerts, tokens, isolation."""

import time
from datetime import UTC, datetime

import pytest
from tests.conftest import events_of

from agentshield.audit.worker import AuditWorker

pytestmark = pytest.mark.integration

NOW = time.time()
SQUID = [f"{NOW:.3f}    120 10.0.0.{i} TCP_TUNNEL/200 5120 CONNECT {host}:443 user{i} HIER_DIRECT/1.2.3.4 -"
         for i, host in enumerate(["chat.openai.com", "claude.ai", "chat.openai.com", "intranet.acme.com"])]


@pytest.fixture
def worker(worker_engine, redis_client):
    return AuditWorker(worker_engine, redis_client)


def batch(bid, lines=SQUID, **kw):
    return {"source": "proxy", "format": "squid", "batch_id": bid, "lines": lines, **kw}


async def tools(acct, **qs):
    q = "&".join(f"{k}={v}" for k, v in qs.items())
    r = await acct.get(f"/v1/admin/ai-tools?{q}")
    assert r.status_code == 200, r.text
    return r.json()


async def test_ingest_builds_the_inventory_and_counts_people_without_storing_their_names(api, worker, owner_conn):
    acct = await api.signup()
    r = await acct.post("/v1/ingest/logs", batch("b1", team="Marketing"))
    assert r.status_code == 200 and r.json()["accepted"] == 4 and r.json()["tools_seen"] == 2 and r.json()["new_tools"] == 2
    inv = {t["domain"]: t for t in await tools(acct)}
    assert set(inv) == {"chat.openai.com", "claude.ai"} and inv["chat.openai.com"]["hits"] == 2 and inv["chat.openai.com"]["users_count"] == 2
    assert inv["chat.openai.com"]["classification"] == "unknown" and inv["chat.openai.com"]["team"] == "Marketing"
    dump = await owner_conn.fetch("select * from ai_tools_seen where tenant_id = $1", __import__("uuid").UUID(acct.tenant_id))
    assert "user0" not in str([dict(r) for r in dump])
    seen = await events_of(acct, worker, type="shadow.tool_seen")
    assert len(seen) == 2 and {e["payload"]["domain"] for e in seen} == {"chat.openai.com", "claude.ai"}


async def test_the_same_batch_is_counted_once_and_a_second_batch_adds_up(api):
    acct = await api.signup()
    assert (await acct.post("/v1/ingest/logs", batch("same"))).json()["duplicate"] is False
    again = (await acct.post("/v1/ingest/logs", batch("same"))).json()
    assert again["duplicate"] is True and again["accepted"] == 0
    assert (await acct.post("/v1/ingest/logs", batch("other"))).status_code == 200
    inv = {t["domain"]: t for t in await tools(acct)}
    assert inv["chat.openai.com"]["hits"] == 4 and inv["chat.openai.com"]["users_count"] == 2          # users are not double counted
    assert inv["chat.openai.com"]["team"] == "unassigned"


async def test_bad_lines_are_counted_and_do_not_fail_the_batch(api):
    acct = await api.signup()
    r = (await acct.post("/v1/ingest/logs", batch("bad", lines=["garbage", SQUID[0]]))).json()
    assert r["accepted"] == 1 and r["rejected"] == 1 and r["reasons"]


async def test_dns_logs_and_unknown_hosts_with_model_api_paths(api):
    acct = await api.signup()
    r = await acct.post("/v1/ingest/logs", {"source": "dns", "format": "dns", "batch_id": "d1", "lines": [f"{NOW} laptop-7 api.mistral.ai", f"{NOW} laptop-7 example.org"]})
    assert r.status_code == 200 and r.json()["tools_seen"] == 1
    r = await acct.post("/v1/ingest/logs", {"source": "proxy", "format": "records", "batch_id": "r1", "records": [
        {"ts": NOW, "user": "u1", "url": "https://llm.internal-startup.io/v1/chat/completions", "bytes_out": 10}]})
    assert r.json()["tools_seen"] == 1
    inv = {t["domain"]: t for t in await tools(acct)}
    assert inv["llm.internal-startup.io"]["reason"].startswith("heuristic")


async def test_classifying_a_tool_changes_how_later_use_is_reported(api, worker):
    admin = await api.signup()
    await admin.post("/v1/ingest/logs", batch("c1"))
    t = next(x for x in await tools(admin) if x["domain"] == "claude.ai")
    r = await admin.patch(f"/v1/admin/ai-tools/{t['id']}", {"classification": "blocked"})
    assert r.status_code == 200 and r.json()["classification"] == "blocked"
    await admin.post("/v1/ingest/logs", batch("c2"))
    blocked_events = [e for e in await events_of(admin, worker, type="shadow.tool_seen") if e["payload"]["classification"] == "blocked"]
    assert blocked_events and blocked_events[-1]["severity"] == "high"
    assert [x["domain"] for x in await tools(admin, classification="blocked")] == ["claude.ai"]
    alerts = (await admin.get("/v1/admin/alerts?kind=shadow_ai")).json()
    assert alerts["items"] and all(a["kind"] == "shadow_ai" for a in alerts["items"])
    oa = next(x for x in await tools(admin) if x["domain"] == "chat.openai.com")
    ok = (await admin.patch(f"/v1/admin/ai-tools/{oa['id']}", {"classification": "approved"})).json()
    assert "AgentShield" in ok["suggested_alternative"]


async def test_a_large_upload_to_an_unapproved_tool_is_a_dlp_event(api, worker):
    acct = await api.signup()
    rec = {"ts": NOW, "user": "u1", "url": "https://claude.ai/chat", "bytes_out": 5_000_000}
    await acct.post("/v1/ingest/logs", {"source": "proxy", "format": "records", "batch_id": "big", "records": [rec]})
    dlp = await events_of(acct, worker, type="shadow.dlp_hit")
    assert len(dlp) == 1 and dlp[0]["payload"]["max_upload_bytes"] == 5_000_000


async def test_a_silent_source_raises_one_stale_event_a_day(api, worker, redis_client, app):
    from agentshield.tenants.context import TenantContext
    acct = await api.signup()
    await acct.post("/v1/ingest/logs", batch("s1"))
    state = app.state.s
    ctx = TenantContext(tenant_id=__import__("uuid").UUID(acct.tenant_id), actor="user", actor_id=__import__("uuid").uuid4(), role="admin", auth_method="session")
    assert await state.shadow.check_stale(ctx) == []
    assert await state.shadow.check_stale(ctx, now=time.time() + 25 * 3600) == ["proxy"]
    assert await state.shadow.check_stale(ctx, now=time.time() + 26 * 3600) == ["proxy"]
    assert len(await events_of(acct, worker, type="shadow.source_stale")) == 1


async def test_validation_and_size_limits(api):
    acct = await api.signup()
    for bad in ({"source": "proxy", "format": "squid", "batch_id": "x"},                                    # no lines
                {"source": "proxy", "format": "records", "batch_id": "x", "lines": ["a"]},
                {"source": "proxy", "format": "squid", "batch_id": "bad id!", "lines": ["a"]},
                {"source": "ftp", "format": "squid", "batch_id": "x", "lines": ["a"]},
                {"source": "proxy", "format": "squid", "batch_id": "x", "lines": ["a"] * 20_001}):
        assert (await acct.post("/v1/ingest/logs", bad)).status_code == 422, bad
    big = {"source": "proxy", "format": "squid", "batch_id": "big", "lines": ["x" * 4000] * 1400}
    assert (await acct.post("/v1/ingest/logs", big)).status_code == 413
    assert (await acct.patch("/v1/admin/ai-tools/00000000-0000-0000-0000-000000000000", {"classification": "approved"})).status_code == 404


async def test_ingest_tokens_work_for_ingest_only_and_can_be_revoked(api):
    acct = await api.signup()
    t = (await acct.post("/v1/admin/tokens", {"label": "squid-shipper"})).json()
    assert t["token"].startswith("asu_") and (await acct.get("/v1/admin/tokens")).json()[0]["label"] == "squid-shipper"
    assert "token" not in (await acct.get("/v1/admin/tokens")).json()[0]
    c = api.client()
    auth = {"Authorization": f"Bearer {t['token']}"}
    assert (await c.post("/v1/ingest/logs", json=batch("t1"), headers=auth)).status_code == 200
    assert (await c.post("/v1/admin/tokens", json={"label": "chained"}, headers=auth)).status_code == 403         # a token cannot mint tokens
    for path in ("/v1/admin/agents", "/v1/admin/ai-tools", "/v1/admin/mcp-servers", "/v1/admin/users"):          # and it reaches nothing but ingest
        r = await c.get(path, headers=auth)
        assert r.status_code == 403 and "only send logs" in r.json()["detail"], path
    assert (await acct.delete(f"/v1/admin/tokens/{t['id']}")).status_code == 204
    assert (await c.post("/v1/ingest/logs", json=batch("t2"), headers=auth)).status_code == 401


async def test_roles_and_tenant_isolation(api):
    admin = await api.signup()
    await admin.post("/v1/ingest/logs", batch("i1"))
    viewer, analyst = await api.add_user(admin, "viewer"), await api.add_user(admin, "analyst")
    assert (await viewer.post("/v1/ingest/logs", batch("v1"))).status_code == 403
    assert (await analyst.post("/v1/ingest/logs", batch("a1"))).status_code == 200
    assert len(await tools(viewer)) == 2
    tid = (await tools(admin))[0]["id"]
    assert (await analyst.patch(f"/v1/admin/ai-tools/{tid}", {"classification": "approved"})).status_code == 403
    other = await api.signup()
    assert await tools(other) == []
    assert (await other.patch(f"/v1/admin/ai-tools/{tid}", {"classification": "approved"})).status_code == 404
    # the same batch id in another tenant is a different batch
    assert (await other.post("/v1/ingest/logs", batch("i1"))).json()["duplicate"] is False


_ = datetime, UTC


async def test_a_token_stops_working_when_its_owner_is_disabled(api):
    admin = await api.signup()
    analyst = await api.add_user(admin, "analyst")
    t = (await analyst.post("/v1/admin/tokens", {"label": "shipper"})).json()
    auth = {"Authorization": f"Bearer {t['token']}"}
    c = api.client()
    assert (await c.post("/v1/ingest/logs", json=batch("o1"), headers=auth)).status_code == 200
    users = (await admin.get("/v1/admin/users")).json()["items"]
    uid = next(u["id"] for u in users if u["email"] == analyst.email)
    assert (await admin.patch(f"/v1/admin/users/{uid}", {"disabled": True})).status_code == 200
    assert (await c.post("/v1/ingest/logs", json=batch("o2"), headers=auth)).status_code == 401


async def test_a_token_row_without_a_scope_is_restricted(owner_conn):
    assert "ingest" in str(await owner_conn.fetchval("select column_default from information_schema.columns where table_name = 'user_tokens' and column_name = 'scope'"))
