import asyncio
import json
import subprocess
import sys

import pytest
from sqlalchemy import text

from agentshield.audit.chain import verify_chain
from agentshield.audit.emitter import STREAM, Emitter
from agentshield.audit.spool import Spool
from agentshield.audit.worker import AuditWorker
from agentshield.contracts.events import AuditEvent, EventType
from agentshield.db.tenant_tx import tenant_tx

pytestmark = pytest.mark.integration
OA = {"model": "gpt-4.1", "messages": [{"role": "user", "content": "Summarize my unread mail"}]}


@pytest.fixture
def worker(worker_engine, redis_client):
    return AuditWorker(worker_engine, redis_client)


async def drain(w: AuditWorker) -> int:
    total = 0
    while n := await w.process_once():
        total += n
    return total


async def test_stage1_gate_every_call_is_logged_and_viewable(world, stub, worker):
    c = world.api.client()
    r = await c.post("/v1/chat/completions", json=OA, headers=world.oa())
    trace = r.headers["x-agentshield-trace"]
    async with c.stream("POST", "/v1/messages", json={"model": "m", "max_tokens": 9, "stream": True,
                                                      "messages": OA["messages"]}, headers=world.an()) as rs:
        _ = [x async for x in rs.aiter_bytes()]
    assert await drain(worker) >= 4
    ev = await world.acct.get(f"/v1/admin/events?trace={trace}")
    types = [e["type"] for e in ev.json()["items"] if e["type"] != "budget.price_missing"]
    assert sorted(types) == ["model.response", "request.received"]
    allev = [e for e in (await world.acct.get("/v1/admin/events?limit=100")).json()["items"]
             if e["type"] != "budget.price_missing"]
    assert len(allev) == 4 and all(e["agent_slug"] in {"oa-agent", "an-agent"} for e in allev)
    report = await verify_chain(worker.engine, world.acct.tenant_id)
    assert report.ok and report.checked >= 4 and report.first_seq == 1 and report.last_seq == report.checked


async def test_events_have_summary_decision_fields_and_payload_for_analysts_only(world, stub, worker):
    await world.api.client().post("/v1/chat/completions", json=OA, headers=world.oa())
    await drain(worker)
    items = (await world.acct.get("/v1/admin/events?include_payload=true")).json()["items"]
    req = next(e for e in items if e["type"] == "request.received")
    assert req["payload"]["api"] == "openai" and req["payload"]["user_request"] == "Summarize my unread mail"
    assert req["payload_available"] and len(req["hash"]) == 64
    viewer = await world.api.add_user(world.acct, "viewer")
    assert (await viewer.get("/v1/admin/events")).status_code == 200
    assert (await viewer.get("/v1/admin/events?include_payload=true")).status_code == 403


async def test_filters_pagination_and_isolation(world, stub, worker, api):
    c = world.api.client()
    for _ in range(3):
        await c.post("/v1/chat/completions", json=OA, headers=world.oa(**{"X-AgentShield-User": "u-9"}))
    await drain(worker)
    page1 = (await world.acct.get("/v1/admin/events?limit=2&user=u-9")).json()
    assert len(page1["items"]) == 2 and page1["next_cursor"]
    page2 = (await world.acct.get(f"/v1/admin/events?limit=2&user=u-9&cursor={page1['next_cursor']}")).json()
    seqs = [e["seq"] for e in page1["items"] + page2["items"]]
    assert seqs == sorted(seqs, reverse=True) and len(set(seqs)) == len(seqs) == 4
    assert (await world.acct.get("/v1/admin/events?type=model.response")).json()["items"]
    assert (await world.acct.get("/v1/admin/events?user=nobody")).json()["items"] == []
    other = await api.signup()
    assert (await other.get("/v1/admin/events")).json()["items"] == []        # nothing from another tenant
    assert (await world.acct.get("/v1/admin/events?cursor=%%%")).status_code == 422


async def test_request_carrying_sk_key_leaves_no_secret_in_redis_or_postgres(world, stub, worker, redis_client, owner_conn):
    body = {"model": "gpt-4.1", "messages": [{"role": "user",
            "content": "my key is sk-ant-api03-abcdefghijklmnopqrstuvwx and card 4111 1111 1111 1111, mail bob@unknown.com"}]}
    await world.api.client().post("/v1/chat/completions", json=body, headers=world.oa())
    raw = json.dumps([{k.decode(): v.decode() for k, v in f.items()} for _, f in await redis_client.xrange(STREAM)])
    for secret in ("sk-ant-api03", "4111 1111", "bob@"):
        assert secret not in raw, secret
    await drain(worker)
    dump = json.dumps([dict(r) for r in await owner_conn.fetch(
        "select e.summary, e.reason, p.payload::text from audit_events e join audit_payloads p "
        "on p.tenant_id=e.tenant_id and p.seq=e.seq and p.ts=e.ts where e.tenant_id=$1::uuid", world.acct.tenant_id)])
    for secret in ("sk-ant-api03", "4111 1111", "bob@"):
        assert secret not in dump, secret
    assert "@unknown.com" in dump


async def test_two_workers_writing_the_same_tenant_do_not_fork_the_chain(world, stub, worker_engine, redis_client):
    c = world.api.client()
    await asyncio.gather(*[c.post("/v1/chat/completions", json=OA, headers=world.oa(**{"X-AgentShield-Session": f"s{i}"}))
                           for i in range(25)])
    w1 = AuditWorker(worker_engine, redis_client, consumer="w1", batch=7)
    w2 = AuditWorker(worker_engine, redis_client, consumer="w2", batch=5)

    async def loop(w):
        while await w.process_once():
            pass

    await asyncio.gather(loop(w1), loop(w2), loop(w1), loop(w2))
    report = await verify_chain(worker_engine, world.acct.tenant_id)
    assert report.ok and report.checked == 50 and report.last_seq == 50
    async with tenant_tx(worker_engine, world.acct.tenant_id) as conn:
        n = (await conn.execute(text("select count(distinct seq) from audit_events"))).scalar_one()
    assert n == 50


async def test_redelivered_messages_are_not_written_twice(world, stub, worker, redis_client):
    await world.api.client().post("/v1/chat/completions", json=OA, headers=world.oa())
    # read but never ack (simulates a crash after commit), then re-claim
    await worker.ensure_group()
    msgs = await redis_client.xreadgroup(worker.group, "dead-consumer", {STREAM: ">"}, count=10)
    assert msgs
    first = await worker._write_tenant(world.acct.tenant_id, [
        (m[0], json.loads(m[1][b"event"]), m[1][b"payload"].decode()) for m in msgs[0][1]])
    again = await worker._write_tenant(world.acct.tenant_id, [
        (m[0], json.loads(m[1][b"event"]), m[1][b"payload"].decode()) for m in msgs[0][1]])
    assert first == 2 and again == 0
    assert (await verify_chain(worker.engine, world.acct.tenant_id)).ok


async def test_unacked_messages_are_reclaimed_by_another_worker(world, stub, worker, redis_client, monkeypatch):
    await world.api.client().post("/v1/chat/completions", json=OA, headers=world.oa())
    await worker.ensure_group()
    await redis_client.xreadgroup(worker.group, "crashed", {STREAM: ">"}, count=10)
    monkeypatch.setattr("agentshield.audit.worker.CLAIM_IDLE_MS", 0)
    assert await drain(worker) == 2


async def test_tampering_is_detected_at_the_exact_row(world, stub, worker, owner_conn):
    c = world.api.client()
    for _ in range(3):
        await c.post("/v1/chat/completions", json=OA, headers=world.oa())
    await drain(worker)
    assert (await verify_chain(worker.engine, world.acct.tenant_id)).ok
    # an insider with superuser rights disables the guard trigger and edits a row
    await owner_conn.execute("alter table audit_events_default disable trigger all")
    await owner_conn.execute("set session_replication_role = replica")
    part = await owner_conn.fetchval("select tableoid::regclass::text from audit_events where tenant_id=$1::uuid and seq=3",
                                     world.acct.tenant_id)
    await owner_conn.execute(f"update {part} set summary = 'edited' where tenant_id=$1::uuid and seq=3", world.acct.tenant_id)
    await owner_conn.execute("set session_replication_role = default")
    report = await verify_chain(worker.engine, world.acct.tenant_id)
    assert not report.ok and report.first_bad_seq == 3 and "altered" in report.reason


async def test_deleting_the_tail_is_detected_via_chain_head(world, stub, worker, owner_conn):
    c = world.api.client()
    for _ in range(2):
        await c.post("/v1/chat/completions", json=OA, headers=world.oa())
    await drain(worker)
    await owner_conn.execute("set session_replication_role = replica")
    part = await owner_conn.fetchval("select tableoid::regclass::text from audit_events where tenant_id=$1::uuid and seq=4",
                                     world.acct.tenant_id)
    await owner_conn.execute(f"delete from {part} where tenant_id=$1::uuid and seq=4", world.acct.tenant_id)
    await owner_conn.execute("set session_replication_role = default")
    report = await verify_chain(worker.engine, world.acct.tenant_id)
    assert not report.ok and "head" in report.reason


async def test_purging_payload_bodies_does_not_break_the_chain(world, stub, worker, owner_conn):
    await world.api.client().post("/v1/chat/completions", json=OA, headers=world.oa())
    await drain(worker)
    await owner_conn.execute("delete from audit_payloads where tenant_id = $1::uuid", world.acct.tenant_id)
    assert (await verify_chain(worker.engine, world.acct.tenant_id)).ok
    items = (await world.acct.get("/v1/admin/events?include_payload=true")).json()["items"]
    assert items and all(e["payload_available"] is False and e["payload"] is None for e in items)


async def test_redis_down_spools_and_recovers_with_audit_gap(world, stub, worker, app, redis_client, tmp_path):
    state = app.state.s
    original = state.emitter

    class Down:
        async def xadd(self, *a, **kw):
            raise ConnectionError("down")

    state.emitter = Emitter(Down(), Spool(tmp_path))
    try:
        r = await world.api.client().post("/v1/chat/completions", json=OA, headers=world.oa())
        assert r.status_code == 200                                    # requests never fail because of logging
        assert len(state.emitter.spool) == 2
        state.emitter.redis = redis_client                              # redis is back
        await world.api.client().post("/v1/chat/completions", json=OA, headers=world.oa())
    finally:
        state.emitter = original
    await drain(worker)
    types = [e["type"] for e in reversed((await world.acct.get("/v1/admin/events?limit=50")).json()["items"])]
    assert types.count("audit.gap") == 1 and types.count("request.received") == 2
    assert (await verify_chain(worker.engine, world.acct.tenant_id)).ok


async def test_malformed_stream_messages_are_dropped_not_fatal(world, stub, worker, redis_client):
    await redis_client.xadd(STREAM, {"garbage": "yes"})
    await world.api.client().post("/v1/chat/completions", json=OA, headers=world.oa())
    assert await drain(worker) == 2


async def test_verify_chain_cli(world, stub, worker, db_urls, owner_conn, tmp_path):
    await world.api.client().post("/v1/chat/completions", json=OA, headers=world.oa())
    await drain(worker)
    slug = await owner_conn.fetchval("select slug from tenants where id=$1::uuid", world.acct.tenant_id)
    env = {"AGENTSHIELD_OWNER_DATABASE_URL": db_urls.owner.replace("postgresql://", "postgresql+asyncpg://"),
           "PATH": "/usr/bin:/bin", "HOME": str(tmp_path)}
    def run(tenant: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run([sys.executable, "-m", "agentshield.cli", "verify-chain", "--tenant", tenant],  # noqa: S603
                              capture_output=True, text=True, env=env, timeout=60)

    out = await asyncio.to_thread(run, slug)
    assert out.returncode == 0 and "OK: 2 events verified" in out.stdout
    assert (await asyncio.to_thread(run, "nope")).returncode == 2


def test_event_model_roundtrip():
    e = AuditEvent(tenant_id="00000000-0000-0000-0000-000000000001", trace_id="t-1", module="gateway",
                   type=EventType.request_received, summary="x")
    assert json.loads(json.dumps(e.envelope()))["schema"] == "agentshield.event/1"
