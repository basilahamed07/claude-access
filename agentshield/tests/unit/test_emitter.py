import json

import fakeredis.aioredis
import pytest

from agentshield.audit.emitter import STREAM, Emitter
from agentshield.audit.spool import Spool
from agentshield.contracts.events import AuditEvent, EventType

TENANT = "00000000-0000-0000-0000-000000000001"


def ev(**kw):
    return AuditEvent(tenant_id=TENANT, trace_id="t-1", module="gateway", type=EventType.request_received,
                      summary="hello", **kw)


@pytest.fixture
async def redis():
    r = fakeredis.aioredis.FakeRedis()
    yield r
    await r.aclose()


async def entries(redis):
    return [{k.decode(): v.decode() for k, v in f.items()} for _, f in await redis.xrange(STREAM)]


async def test_emit_redacts_before_publishing(redis, tmp_path):
    em = Emitter(redis, Spool(tmp_path))
    e = ev(reason="used sk-ant-api03-abcdefghijklmnopqrstuvwx")
    e.summary = "mail to bob@unknown.com with Bearer abcdefghijklmnopqrstuvwxyz"
    await em.emit(e, {"headers": {"authorization": "Bearer zzzzzzzzzzzzzzzzzzzz"}, "tool": "send_email",
                      "args": {"to": "bob@unknown.com", "token": "abc"}})
    raw = json.dumps(await entries(redis))
    for secret in ("sk-ant-api03", "abcdefghijklmnopqrstuvwxyz", "zzzzzzzzzzzzzzzz", "bob@", '"abc"'):
        assert secret not in raw, secret
    assert "@unknown.com" in raw and "send_email" in raw


async def test_payload_digest_covers_full_redacted_payload_and_cap_sets_flag(redis, tmp_path):
    em = Emitter(redis, Spool(tmp_path), max_payload=1000)
    big = {"data": "x" * 5000}
    e = ev()
    await em.emit(e, big)
    (entry,) = await entries(redis)
    envelope, payload = json.loads(entry["event"]), json.loads(entry["payload"])
    assert envelope["payload_truncated"] is True and payload["_truncated"] is True and payload["_bytes"] > 5000
    assert len(entry["payload"]) < 2000
    import hashlib

    from agentshield.audit.chain import canonical_json
    assert envelope["payload_sha256"] == hashlib.sha256(canonical_json(big)).hexdigest()


async def test_small_payload_not_truncated(redis, tmp_path):
    await Emitter(redis, Spool(tmp_path)).emit(ev(), {"a": 1})
    (entry,) = await entries(redis)
    assert json.loads(entry["event"])["payload_truncated"] is False


class FlakyRedis:
    def __init__(self, real, fail_times):
        self.real, self.fail = real, fail_times

    async def xadd(self, *a, **kw):
        if self.fail > 0:
            self.fail -= 1
            raise ConnectionError("redis down")
        return await self.real.xadd(*a, **kw)


async def test_redis_down_spools_then_flushes_and_emits_audit_gap(redis, tmp_path):
    flaky = FlakyRedis(redis, fail_times=2)
    spool = Spool(tmp_path)
    em = Emitter(flaky, spool)
    await em.emit(ev(), {"n": 1})
    await em.emit(ev(), {"n": 2})                       # both fail -> spooled, no exception raised
    assert len(spool) == 2 and await entries(redis) == []
    await em.emit(ev(), {"n": 3})                       # redis is back: spool flushed first, then gap marker, then this
    types = [json.loads(e["event"])["type"] for e in await entries(redis)]
    assert types == ["request.received", "request.received", "audit.gap", "request.received"]
    assert len(spool) == 0
    gap = json.loads((await entries(redis))[2]["payload"])
    assert gap["delayed"] == 2 and gap["dropped"] == 0


async def test_spool_is_bounded_and_counts_dropped(redis, tmp_path):
    spool = Spool(tmp_path, max_items=3)
    em = Emitter(FlakyRedis(redis, fail_times=100), spool)
    for i in range(5):
        await em.emit(ev(), {"n": i})
    assert len(spool) == 3 and spool.dropped == 2


async def test_spool_survives_restart(redis, tmp_path):
    em = Emitter(FlakyRedis(redis, fail_times=100), Spool(tmp_path))
    await em.emit(ev(), {"n": 1})
    assert len(Spool(tmp_path)) == 1                    # a new process sees the spooled event


async def test_emit_never_raises(tmp_path):
    class Boom:
        async def xadd(self, *a, **kw):
            raise RuntimeError("boom")

    await Emitter(Boom(), Spool(tmp_path)).emit(ev(), {"x": object()})
