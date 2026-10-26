"""Retention (payload purge, partition drop with checkpoint and floor) and seed-demo idempotence."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text
from tests.conftest import events_of, make_settings

from agentshield.audit.chain import verify_chain
from agentshield.audit.retention import retention_run
from agentshield.audit.worker import AuditWorker
from agentshield.contracts.events import AuditEvent, EventType
from agentshield.contracts.ids import new_trace_id
from agentshield.db.engine import create_engine
from agentshield.demo.seed import seed_demo

pytestmark = pytest.mark.integration


@pytest.fixture
def worker(worker_engine, redis_client):
    return AuditWorker(worker_engine, redis_client)


@pytest.fixture
async def retention_engine(db_urls):
    eng = create_engine(db_urls.retention, pool_size=3)
    yield eng
    await eng.dispose()


async def make_session(world, key="s-ret"):
    c = world.api.client()
    await c.post("/v1/chat/completions", json={"model": "gpt-4.1", "messages": [{"role": "user", "content": "hello"}]},
                 headers=world.oa(**{"X-AgentShield-Session": key}))
    return (await world.acct.get("/v1/admin/sessions?agent=oa-agent")).json()["items"][0]["id"]


async def test_payloads_are_purged_after_the_window_but_envelopes_and_the_chain_survive(world, stub, worker, retention_engine, app):
    sid = await make_session(world)
    before = await events_of(world.acct, worker)
    assert before and all(e["payload_available"] for e in before)
    soon = await retention_run(retention_engine, datetime.now(UTC) + timedelta(days=10))
    assert soon.payloads_deleted == 0                                       # inside the 30-day window
    report = await retention_run(retention_engine, datetime.now(UTC) + timedelta(days=31))
    assert report.payloads_deleted >= len(before) and report.partitions_dropped == []
    after = (await world.acct.get("/v1/admin/events?limit=200&include_payload=true")).json()["items"]
    assert len(after) == len(before) and not any(e["payload_available"] for e in after) and all(e["payload"] is None for e in after)
    assert all(e["hash"] for e in after)
    assert (await verify_chain(app.state.s.engine, world.acct.tenant_id)).ok
    _ = sid


async def test_incident_sessions_keep_their_payloads_for_the_longer_period(world, stub, worker, retention_engine):
    sid = await make_session(world)
    await events_of(world.acct, worker)
    assert (await world.acct.post("/v1/admin/incidents", {"session_id": sid, "title": "keep me"})).status_code == 201
    await retention_run(retention_engine, datetime.now(UTC) + timedelta(days=31))
    kept = (await world.acct.get(f"/v1/admin/events?session={sid}&limit=200")).json()["items"]
    assert kept and all(e["payload_available"] for e in kept)
    await retention_run(retention_engine, datetime.now(UTC) + timedelta(days=1100))
    gone = (await world.acct.get(f"/v1/admin/events?session={sid}&limit=200")).json()["items"]
    assert gone and not any(e["payload_available"] for e in gone)


async def test_custom_payload_retention_is_respected(world, stub, worker, retention_engine):
    await make_session(world)
    await events_of(world.acct, worker)
    etag = (await world.acct.get("/v1/admin/settings")).headers["etag"]
    assert (await world.acct.patch("/v1/admin/settings", {"retention": {"payload_days": 90}}, headers={"If-Match": etag})).status_code == 200
    assert (await retention_run(retention_engine, datetime.now(UTC) + timedelta(days=60))).payloads_deleted == 0
    assert (await retention_run(retention_engine, datetime.now(UTC) + timedelta(days=95))).payloads_deleted > 0


async def test_old_partitions_are_checkpointed_archived_and_dropped_but_young_ones_never(
        api, stub, retention_engine, owner_conn, app, worker, redis_client):
    acct = await api.signup()                                    # a fresh chain: the old events come first, as in real life
    tid = uuid.UUID(acct.tenant_id)
    await acct.make_agent("old-agent")
    await owner_conn.execute("create table if not exists audit_events_2025_01 partition of audit_events "
                             "for values from ('2025-01-01 00:00:00+00') to ('2025-02-01 00:00:00+00')")
    await owner_conn.execute("create table if not exists audit_payloads_2025_01 partition of audit_payloads "
                             "for values from ('2025-01-01 00:00:00+00') to ('2025-02-01 00:00:00+00')")
    for t in ("audit_events_2025_01", "audit_payloads_2025_01"):          # as `ensure-partitions` would have made them
        await owner_conn.execute(f"alter table {t} owner to agentshield_owner")
    agent_id = await owner_conn.fetchval("select id from agents where tenant_id = $1", tid)
    sid = await owner_conn.fetchval("insert into sessions (tenant_id, agent_id, session_key) values ($1, $2, 'old') returning id",
                                    tid, agent_id)
    assert (await acct.post("/v1/admin/incidents", {"session_id": str(sid), "title": "old but important"})).status_code == 201
    emitter = app.state.s.emitter
    for i in range(3):
        await emitter.emit(AuditEvent(tenant_id=acct.tenant_id, trace_id=new_trace_id(), module="gateway",
                                      type=EventType.request_received, session_id=str(sid), agent_slug="old-agent",
                                      summary=f"old event {i}", ts=datetime(2025, 1, 10 + i, tzinfo=UTC)), {"n": i})
    await emitter.emit(AuditEvent(tenant_id=acct.tenant_id, trace_id=new_trace_id(), module="gateway",
                                  type=EventType.request_received, agent_slug="old-agent", summary="current event"), {})
    await events_of(acct, worker)
    assert await owner_conn.fetchval("select count(*) from audit_events_2025_01 where tenant_id = $1", tid) == 3
    assert (await verify_chain(app.state.s.engine, tid)).ok

    report = await retention_run(retention_engine, emitter=emitter)
    assert "2025-01" in report.partitions_dropped and report.checkpoints >= 1 and report.archived_events == 3
    assert await owner_conn.fetchval("select to_regclass('audit_events_2025_01')") is None
    assert await owner_conn.fetchval("select count(*) from audit_events_archive where tenant_id = $1", tid) == 3
    # the dropped range is described by a checkpoint, and the chain still verifies from the first surviving row
    checkpoints = await events_of(acct, worker, type="audit.checkpoint")
    assert checkpoints and checkpoints[-1]["payload"]["partition"] == "2025-01" and checkpoints[-1]["payload"]["events"] == 3
    after = await verify_chain(app.state.s.engine, tid)
    assert after.ok and after.first_seq > 1 and after.checked >= 2
    assert (await retention_run(retention_engine, emitter=emitter)).partitions_dropped == []     # nothing left to drop

    # the current month can never be dropped, not by the job and not by calling the function directly
    now = datetime.now(UTC)
    with pytest.raises(Exception, match="younger than 180 days"):
        async with retention_engine.connect() as conn:
            await conn.execute(text("select private.drop_audit_partition(:y, :m, :now)"), {"y": now.year, "m": now.month, "now": now})
    assert await owner_conn.fetchval("select to_regclass($1)", f"audit_events_{now:%Y_%m}") is not None
    far = await retention_run(retention_engine, now + timedelta(days=100), emitter=emitter)
    assert f"{now:%Y-%m}" not in far.partitions_dropped


async def test_retention_role_cannot_touch_envelopes(world, stub, worker, retention_engine):
    await make_session(world)
    await events_of(world.acct, worker)
    async with retention_engine.connect() as conn:
        await conn.execute(text("select set_config('app.tenant_id', :t, false)"), {"t": world.acct.tenant_id})
        for sql in ("delete from audit_events", "update audit_events set summary = 'x'"):
            with pytest.raises(Exception, match="permission denied"):
                await conn.execute(text(sql))
            await conn.rollback()
            await conn.execute(text("select set_config('app.tenant_id', :t, false)"), {"t": world.acct.tenant_id})


async def test_seed_demo_is_idempotent_and_produces_a_verifiable_story(db_urls, api, redis_client, app):
    settings = make_settings(db_urls)
    first = await seed_demo(settings, password="demo-password-123")
    assert first.created and first.password == "demo-password-123"
    again = await seed_demo(settings)
    assert not again.created and again.password is None
    c = api.client()
    r = await c.post("/v1/auth/login", json={"email": first.email, "password": "demo-password-123"})
    assert r.status_code == 200
    h = {"X-CSRF-Token": r.json()["csrf_token"]}
    sessions = (await c.get("/v1/admin/sessions")).json()["items"]
    assert len(sessions) == 3 and {s["end_user"] for s in sessions} == {"alice@acme.com", "bob@acme.com", "carol@acme.com"}
    attack = next(s for s in sessions if s["end_user"] == "alice@acme.com")
    assert attack["blocked"] == 1 and attack["risk_score"] == pytest.approx(0.6)
    kinds = {a["kind"] for a in (await c.get("/v1/admin/alerts")).json()["items"]}
    assert {"blocked_call", "malicious_content"} <= kinds
    replay = (await c.post(f"/v1/admin/sessions/{attack['id']}/replay", json={}, headers=h)).json()
    assert replay["changed"] == 0 and replay["compared"] == 2
    ex = (await c.get(f"/v1/admin/sessions/{attack['id']}/export.json")).json()
    assert ex["verification"]["verified"] is True
    assert (await verify_chain(app.state.s.engine, r.json()["tenant_id"])).ok
