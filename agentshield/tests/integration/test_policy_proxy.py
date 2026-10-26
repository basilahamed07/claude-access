"""M1 enforcement in the model proxy: the stage-2 gate and its failure modes."""

import json

import pytest
from tests.conftest import events_of, set_policy

from agentshield.audit.worker import AuditWorker
from agentshield.policy.budgets import BudgetTracker, BudgetUnavailable
from agentshield.policy.session_state import raise_risk
from agentshield.proxy.sse import SseParser
from agentshield.testing.stub_upstream import StubToolCall, Turn

pytestmark = pytest.mark.integration

OA = {"model": "gpt-4.1", "messages": [{"role": "user", "content": "Summarize my unread mail"}]}
AN = {"model": "claude-x", "max_tokens": 64, "messages": [{"role": "user", "content": "Summarize my unread mail"}]}
SEND_EXTERNAL = Turn(text="Forwarding.", tool_calls=[StubToolCall("send_email", {"to": "x@unknown.com", "body": "Secret invoice data"})])
READ = Turn(tool_calls=[StubToolCall("read_email", {"folder": "INBOX"})])


@pytest.fixture
def worker(worker_engine, redis_client):
    return AuditWorker(worker_engine, redis_client)


@pytest.fixture
async def guarded(world):
    await set_policy(world.acct, "oa-agent")
    await set_policy(world.acct, "an-agent")
    return world


async def sse_text(client, url, body, headers):
    async with client.stream("POST", url, json={**body, "stream": True}, headers=headers) as r:
        data = b"".join([c async for c in r.aiter_bytes()])
    return r, data


# ── the stage 2 gate ────────────────────────────────────────────────────────────────────────────
async def test_stage2_gate_forbidden_tool_blocked(guarded, stub, worker):
    stub.queue.append(SEND_EXTERNAL)
    r = await guarded.api.client().post("/v1/chat/completions", json=OA, headers=guarded.oa())
    choice = r.json()["choices"][0]
    assert "tool_calls" not in choice["message"] and choice["finish_reason"] == "stop"
    assert "Action blocked by AgentShield: External email is not permitted for this agent (rule deny-external-send, trace t-" \
        in choice["message"]["content"]
    assert "x@unknown.com" not in r.text and "Secret invoice data" not in r.text
    events = await events_of(guarded.acct, worker, trace=r.headers["x-agentshield-trace"])
    dec = next(e for e in events if e["type"] == "policy.decision")
    assert (dec["decision"], dec["rule_id"], dec["severity"]) == ("block", "deny-external-send", "high")
    assert dec["reason"] == "External email is not permitted for this agent"
    assert dec["payload"]["matched"] == ["deny-external-send"] and dec["payload"]["effect_tag"] == "external"
    kinds = [e["type"] for e in events]
    assert "tool.requested" in kinds and "tool.rewritten" in kinds
    requested = next(e for e in events if e["type"] == "tool.requested")
    assert "@unknown.com" in json.dumps(requested["payload"]) and "x@" not in json.dumps(requested["payload"])   # redacted


async def test_read_email_is_allowed_and_untouched(guarded, stub):
    stub.queue.append(READ)
    r = await guarded.api.client().post("/v1/chat/completions", json=OA, headers=guarded.oa())
    msg = r.json()["choices"][0]["message"]
    assert msg["tool_calls"][0]["function"]["name"] == "read_email" and r.json()["choices"][0]["finish_reason"] == "tool_calls"


@pytest.mark.parametrize("chunk", [0, 1])
async def test_blocked_in_both_formats_when_streaming(guarded, stub, chunk):
    stub.chunk_size = chunk
    stub.queue.append(SEND_EXTERNAL)
    r, data = await sse_text(guarded.api.client(), "/v1/chat/completions", OA, guarded.oa())
    assert b"x@unknown.com" not in data and b"Secret" not in data and b"Action blocked by AgentShield" in data
    stub.queue.append(SEND_EXTERNAL)
    r, data = await sse_text(guarded.api.client(), "/v1/messages", AN, guarded.an())
    events = [e.json() for e in SseParser().feed(data) if e.json()]
    assert b"x@unknown.com" not in data and next(e for e in events if e["type"] == "message_delta")["delta"]["stop_reason"] == "end_turn"


async def test_internal_send_is_allowed_by_the_same_policy(guarded, stub):
    stub.queue.append(Turn(tool_calls=[StubToolCall("send_email", {"to": "bob@acme.com", "body": "hi"})]))
    r = await guarded.api.client().post("/v1/chat/completions", json=OA, headers=guarded.oa())
    assert r.json()["choices"][0]["message"]["tool_calls"][0]["function"]["name"] == "send_email"


async def test_unknown_tool_is_default_deny_and_agent_without_policy_denies_everything(guarded, world, stub, worker):
    stub.queue.append(Turn(tool_calls=[StubToolCall("launch_missiles", {})]))
    r = await world.api.client().post("/v1/chat/completions", json=OA, headers=guarded.oa())
    assert "rule default-deny" in r.json()["choices"][0]["message"]["content"]
    acct = world.acct
    await acct.make_agent("no-policy", upstream_id=(await acct.get("/v1/admin/agents/oa-agent")).json()["upstream_id"])
    key = (await acct.make_key("no-policy"))["key"]
    etag = (await acct.get("/v1/admin/agents/no-policy")).headers["etag"]
    await acct.patch("/v1/admin/agents/no-policy", {"mode": "enforce"}, headers={"If-Match": etag})
    stub.queue.append(READ)
    r = await world.api.client().post("/v1/chat/completions", json=OA, headers=world.oa(key=key))
    assert "rule default-deny" in r.json()["choices"][0]["message"]["content"]


async def test_monitor_mode_records_what_would_have_been_blocked_but_blocks_nothing(guarded, stub, worker):
    acct = guarded.acct
    etag = (await acct.get("/v1/admin/agents/oa-agent")).headers["etag"]
    await acct.patch("/v1/admin/agents/oa-agent", {"mode": "monitor"}, headers={"If-Match": etag})
    stub.queue.append(SEND_EXTERNAL)
    r = await guarded.api.client().post("/v1/chat/completions", json=OA, headers=guarded.oa())
    assert r.json()["choices"][0]["message"]["tool_calls"][0]["function"]["name"] == "send_email"     # passed through
    dec = next(e for e in await events_of(acct, worker, type="policy.decision"))
    assert dec["decision"] == "allow" and dec["payload"]["would_have"] == "block" and dec["payload"]["mode"] == "monitor"
    assert dec["rule_id"] == "deny-external-send" and dec["reason"].startswith("[monitor mode: would have been block]")
    assert dec["severity"] == "high"                                       # still flagged for review


async def test_malformed_tool_arguments_are_blocked_not_crashed(guarded, stub):
    stub.queue.append(Turn(tool_calls=[StubToolCall("send_email", {}, raw_arguments='{"to": "bob@acme.com", ')]))
    r = await guarded.api.client().post("/v1/chat/completions", json=OA, headers=guarded.oa())
    assert r.status_code == 200 and "tool_calls" not in r.json()["choices"][0]["message"]
    assert "not valid JSON" in r.json()["choices"][0]["message"]["content"] or "deny-external-send" in r.text


async def test_session_risk_tightens_permissions_mid_session(guarded, stub, redis_client, owner_conn):
    c = guarded.api.client()
    stub.queue.append(READ)
    r = await c.post("/v1/chat/completions", json=OA, headers=guarded.oa(**{"X-AgentShield-Session": "s-risk"}))
    assert "tool_calls" in r.json()["choices"][0]["message"]
    sid = await owner_conn.fetchval("select id from sessions where session_key = 's-risk' and tenant_id = $1::uuid",
                                    guarded.acct.tenant_id)
    await raise_risk(redis_client, guarded.acct.tenant_id, sid, 0.9)             # what the injection firewall will do
    stub.queue.append(READ)
    r = await c.post("/v1/chat/completions", json=OA, headers=guarded.oa(**{"X-AgentShield-Session": "s-risk"}))
    assert "rule tighten-on-risk" in r.json()["choices"][0]["message"]["content"]
    stub.queue.append(READ)                                                      # another session is unaffected
    r = await c.post("/v1/chat/completions", json=OA, headers=guarded.oa(**{"X-AgentShield-Session": "s-other"}))
    assert "tool_calls" in r.json()["choices"][0]["message"]


async def test_end_user_header_is_recorded_on_events(guarded, stub, worker):
    stub.queue.append(SEND_EXTERNAL)
    await guarded.api.client().post("/v1/chat/completions", json=OA, headers=guarded.oa(**{"X-AgentShield-User": "u-77"}))
    events = await events_of(guarded.acct, worker, user="u-77")
    assert {"request.received", "policy.decision", "tool.requested"} <= {e["type"] for e in events}


# ── budgets ─────────────────────────────────────────────────────────────────────────────────────
LIMITED = "version: 1\nbudgets: { max_calls_per_day: 2 }\nrules:\n  - {id: r, effect: allow, tool: read_email}\n"


async def test_daily_call_budget_returns_429_in_provider_shape_and_logs_event(world, stub, worker):
    await set_policy(world.acct, "oa-agent", LIMITED)
    await set_policy(world.acct, "an-agent", LIMITED)
    c = world.api.client()
    for _ in range(2):
        assert (await c.post("/v1/chat/completions", json=OA, headers=world.oa())).status_code == 200
    r = await c.post("/v1/chat/completions", json=OA, headers=world.oa())
    assert r.status_code == 429 and r.json()["error"]["code"] == "budget_exceeded" and int(r.headers["retry-after"]) > 0
    r = await c.post("/v1/messages", json=AN, headers=world.an())
    assert r.status_code == 200
    for _ in range(2):
        r = await c.post("/v1/messages", json=AN, headers=world.an())
    assert r.status_code == 429 and r.json()["error"]["type"] == "rate_limit_error"
    ev = [e for e in await events_of(world.acct, worker, type="budget.exceeded")]
    assert len(ev) == 2 and ev[0]["rule_id"] == "budget:calls" and ev[0]["severity"] == "medium"


async def test_rpm_limit_and_rate_limit_headers(world, stub):
    await set_policy(world.acct, "oa-agent", "version: 1\nbudgets: { max_rpm: 2 }\n")
    c = world.api.client()
    r1 = await c.post("/v1/chat/completions", json=OA, headers=world.oa())
    assert r1.headers["ratelimit-limit"] == "2" and r1.headers["ratelimit-remaining"] == "1"
    r2 = await c.post("/v1/chat/completions", json=OA, headers=world.oa())
    assert r2.headers["ratelimit-remaining"] == "0"
    r3 = await c.post("/v1/chat/completions", json=OA, headers=world.oa())
    assert r3.status_code == 429 and r3.json()["error"]["code"] == "rate_limit_exceeded" and "retry-after" in r3.headers


async def test_usage_is_recorded_against_the_daily_budget(world, stub, app):
    c = world.api.client()
    await c.post("/v1/chat/completions", json=OA, headers=world.oa())
    async with c.stream("POST", "/v1/chat/completions", json={**OA, "stream": True}, headers=world.oa()) as r:
        _ = [x async for x in r.aiter_bytes()]
    u = await app.state.s.budgets.usage(world.acct.tenant_id, "oa-agent")
    assert u["calls"] == 2 and u["tokens"] == 36                      # 2 x (11 in + 7 out)
    assert u["cost"] == 2 * 78                                        # (11*2.0 + 7*8.0) micro-USD per Mtok price


async def test_price_missing_warning_once_per_day(world, stub, worker):
    c = world.api.client()
    for _ in range(3):
        await c.post("/v1/chat/completions", json={**OA, "model": "unpriced-model"}, headers=world.oa())
    assert len(await events_of(world.acct, worker, type="budget.price_missing")) == 1


# ── failure modes ───────────────────────────────────────────────────────────────────────────────
async def test_budget_service_down_blocks_effectful_tools_but_not_reads(guarded, stub, app, monkeypatch, worker):
    async def down(*a, **kw):
        raise BudgetUnavailable("redis down")

    monkeypatch.setattr(app.state.s.budgets, "admit", down)
    c = guarded.api.client()
    stub.queue.append(Turn(tool_calls=[StubToolCall("send_email", {"to": "bob@acme.com"})]))      # normally allowed
    r = await c.post("/v1/chat/completions", json=OA, headers=guarded.oa())
    assert r.status_code == 200 and "rule budget-service-unavailable" in r.json()["choices"][0]["message"]["content"]
    stub.queue.append(READ)
    r = await c.post("/v1/chat/completions", json=OA, headers=guarded.oa())
    assert "tool_calls" in r.json()["choices"][0]["message"]
    assert [e for e in await events_of(guarded.acct, worker, type="error") if e["payload"].get("component") == "budgets"]


async def test_policy_load_failure_fails_closed_for_effectful_and_open_for_read(guarded, stub, app, monkeypatch):
    async def boom(*a, **kw):
        raise RuntimeError("db down")

    monkeypatch.setattr(app.state.s.policies, "get", boom)
    c = guarded.api.client()
    stub.queue.append(Turn(tool_calls=[StubToolCall("send_email", {"to": "bob@acme.com"})]))
    r = await c.post("/v1/chat/completions", json=OA, headers=guarded.oa())
    assert r.status_code == 200 and "rule evaluator-error" in r.json()["choices"][0]["message"]["content"]


async def test_redis_failure_during_decision_fails_closed(guarded, stub, app, monkeypatch):
    import agentshield.policy.decide as decide

    async def boom(*a, **kw):
        raise ConnectionError("redis down")

    monkeypatch.setattr(decide, "get_risk", boom)
    stub.queue.append(Turn(tool_calls=[StubToolCall("send_email", {"to": "bob@acme.com"})]))
    r = await guarded.api.client().post("/v1/chat/completions", json=OA, headers=guarded.oa())
    assert "rule evaluator-error" in r.json()["choices"][0]["message"]["content"]


async def test_tool_arguments_secrets_are_redacted_in_the_audit_log(guarded, stub, worker):
    stub.queue.append(Turn(tool_calls=[StubToolCall("send_email", {"to": "bob@acme.com", "body": "key sk-ant-api03-abcdefghijklmnopqrstuvwx"})]))
    await guarded.api.client().post("/v1/chat/completions", json=OA, headers=guarded.oa())
    dump = json.dumps(await events_of(guarded.acct, worker))
    assert "sk-ant-api03" not in dump and "[REDACTED:anthropic_key:" in dump


def test_tracker_type():
    assert BudgetTracker
