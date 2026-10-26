"""Human approvals end to end: ask -> queue + webhook -> decision -> allowance -> expiry."""

import asyncio
import json
from datetime import UTC, datetime, timedelta

import pytest
from tests.conftest import events_of, set_policy

from agentshield.audit.worker import AuditWorker
from agentshield.testing.stub_upstream import StubToolCall, Turn

pytestmark = pytest.mark.integration

OA = {"model": "gpt-4.1", "messages": [{"role": "user", "content": "Pay the ACME invoice"}]}
PAY = Turn(tool_calls=[StubToolCall("pay_invoice", {"amount": 5000, "payee": "ACME Ltd", "note": "key sk-ant-api03-abcdefghijklmnopqrstuvwx"})])
HOOK = "https://hooks.example.com/services/T000/B000/XXXX"


@pytest.fixture
def worker(worker_engine, redis_client):
    return AuditWorker(worker_engine, redis_client)


@pytest.fixture
async def desk(world, stub, webhook):
    await set_policy(world.acct, "oa-agent")
    etag = (await world.acct.get("/v1/admin/settings")).headers["etag"]
    r = await world.acct.patch("/v1/admin/settings", {"webhook_url": HOOK}, headers={"If-Match": etag})
    assert r.status_code == 200, r.text
    return world


async def ask_for_payment(desk, stub, session="s-pay", args=None):
    turn = PAY if args is None else Turn(tool_calls=[StubToolCall("pay_invoice", args)])
    stub.queue.append(turn)
    r = await desk.api.client().post("/v1/chat/completions", json=OA, headers=desk.oa(**{"X-AgentShield-Session": session}))
    return r


async def pending(desk):
    return (await desk.acct.get("/v1/admin/approvals?status=pending")).json()["items"]


async def decide(desk, approval, approve=True, note=None, who=None):
    who = who or desk.acct
    etag = (await who.get(f"/v1/admin/approvals/{approval['id']}")).headers["etag"]
    return await who.post(f"/v1/admin/approvals/{approval['id']}/decision", {"approve": approve, "note": note},
                          headers={"If-Match": etag})


async def test_ask_creates_pending_approval_with_exact_notice_and_webhook(desk, stub, webhook, app):
    r = await ask_for_payment(desk, stub)
    (item,) = await pending(desk)
    text = r.json()["choices"][0]["message"]["content"]
    assert text == f"Action needs human approval (approval {item['id']}, rule ask-large-payment); it was not executed."
    assert "tool_calls" not in r.json()["choices"][0]["message"] and r.json()["choices"][0]["finish_reason"] == "stop"
    assert (item["status"], item["tool"], item["rule_id"], item["agent_slug"]) == ("pending", "pay_invoice", "ask-large-payment", "oa-agent")
    assert item["args_redacted"]["amount"] == 5000 and item["args_redacted"]["payee"] == "ACME Ltd"
    assert "sk-ant-api03" not in json.dumps(item)                       # secrets masked, business data visible
    await app.state.s.approvals.drain_notifications()
    (url, body), = webhook["requests"]
    assert url == HOOK
    assert set(body) == {"text", "approval_id", "agent", "tool", "arguments_redacted", "rule_id", "expires_at", "dashboard_url"}
    assert body["approval_id"] == item["id"] and body["arguments_redacted"]["payee"] == "ACME Ltd"
    assert "pay_invoice" in body["text"] and body["dashboard_url"].endswith(f"/approvals/{item['id']}")
    assert "Pay the ACME invoice" not in json.dumps(body)               # no user/model prose reaches the reviewer


async def test_retry_while_pending_reuses_the_same_approval(desk, stub, webhook, app):
    await ask_for_payment(desk, stub)
    await ask_for_payment(desk, stub)
    assert len(await pending(desk)) == 1
    await app.state.s.approvals.drain_notifications()
    assert len(webhook["requests"]) == 1
    await ask_for_payment(desk, stub, args={"amount": 9999, "payee": "Other"})      # a different call is a new request
    assert len(await pending(desk)) == 2


async def test_approve_grants_the_exact_call_an_allowance_in_that_session_only(desk, stub):
    await ask_for_payment(desk, stub)
    (item,) = await pending(desk)
    r = await decide(desk, item, True, "ok, invoice verified")
    assert r.status_code == 200 and r.json()["status"] == "approved" and r.json()["note"] == "ok, invoice verified"
    assert r.json()["decided_by_email"] == desk.acct.email
    again = await ask_for_payment(desk, stub)                                         # same session, same call
    assert again.json()["choices"][0]["message"]["tool_calls"][0]["function"]["name"] == "pay_invoice"
    other = await ask_for_payment(desk, stub, session="s-other")                      # different session: not covered
    assert "needs human approval" in other.json()["choices"][0]["message"]["content"]
    changed = await ask_for_payment(desk, stub, args={"amount": 5000, "payee": "ACME Ltd", "note": "changed"})
    assert "needs human approval" in changed.json()["choices"][0]["message"]["content"]


async def test_deny_blocks_and_the_same_call_is_not_re_requested(desk, stub, worker):
    await ask_for_payment(desk, stub)
    (item,) = await pending(desk)
    assert (await decide(desk, item, False, "wrong payee")).json()["status"] == "denied"
    r = await ask_for_payment(desk, stub)
    assert f"denied by {desk.acct.email}" in r.json()["choices"][0]["message"]["content"] and "rule approval-denied" in r.text
    assert await pending(desk) == []                                                  # the reviewer is not nagged again


async def test_approval_does_not_survive_the_allowance_window(desk, stub, redis_client, app):
    await ask_for_payment(desk, stub)
    (item,) = await pending(desk)
    await decide(desk, item, True)
    keys = await redis_client.keys("allow:*")
    assert len(keys) == 1 and 0 < await redis_client.ttl(keys[0]) <= 900
    await redis_client.delete(*keys)                                                  # 15 minutes later
    r = await ask_for_payment(desk, stub)
    assert "needs human approval" in r.json()["choices"][0]["message"]["content"]


async def test_unanswered_approvals_expire_after_the_ttl_and_count_as_denied(desk, stub, app, worker):
    await ask_for_payment(desk, stub)
    (item,) = await pending(desk)
    tid = desk.acct.tenant_id
    assert await app.state.s.approvals.expire_due(tenant_id=tid, now=datetime.now(UTC)) == 0   # not yet due
    due = datetime.fromisoformat(item["expires_at"]) + timedelta(seconds=1)
    assert await app.state.s.approvals.expire_due(tenant_id=tid, now=due) == 1
    got = (await desk.acct.get(f"/v1/admin/approvals/{item['id']}")).json()
    assert got["status"] == "expired"
    r = await decide(desk, item, True)
    assert r.status_code == 409 and "expired" in r.json()["detail"]                   # too late to approve
    again = await ask_for_payment(desk, stub)                                          # expiry is not a standing denial
    assert "needs human approval" in again.json()["choices"][0]["message"]["content"]
    ev = [e for e in await events_of(desk.acct, worker, type="approval.decided")]
    assert ev and ev[0]["payload"]["status"] == "expired" and ev[0]["decision"] == "block"


async def test_global_sweep_finds_due_approvals_across_tenants(desk, stub, app):
    await ask_for_payment(desk, stub)
    (item,) = await pending(desk)
    due = datetime.fromisoformat(item["expires_at"]) + timedelta(seconds=1)
    assert await app.state.s.approvals.expire_due(now=due) >= 1
    assert (await desk.acct.get(f"/v1/admin/approvals/{item['id']}")).json()["status"] == "expired"


async def test_ttl_is_five_minutes(desk, stub):
    await ask_for_payment(desk, stub)
    (item,) = await pending(desk)
    left = (datetime.fromisoformat(item["expires_at"]) - datetime.now(UTC)).total_seconds()
    assert 290 < left <= 300


async def test_expiry_is_applied_lazily_when_the_item_is_read(desk, stub, owner_conn):
    await ask_for_payment(desk, stub)
    (item,) = await pending(desk)
    await owner_conn.execute("update approvals set expires_at = now() - interval '1 second' where id = $1::uuid", item["id"])
    assert await pending(desk) == []
    assert (await desk.acct.get(f"/v1/admin/approvals/{item['id']}")).json()["status"] == "expired"


async def test_agents_cannot_decide_viewers_cannot_analysts_can(desk, stub, api):
    await ask_for_payment(desk, stub)
    (item,) = await pending(desk)
    c = api.client()
    url = f"/v1/admin/approvals/{item['id']}/decision"
    assert (await c.post(url, json={"approve": True}, headers={"Authorization": f"Bearer {desk.openai_key}", "If-Match": "*"})).status_code == 401
    viewer = await api.add_user(desk.acct, "viewer")
    assert (await viewer.post(url, {"approve": True}, headers={"If-Match": "*"})).status_code == 403
    assert (await viewer.get("/v1/admin/approvals")).status_code == 403
    analyst = await api.add_user(desk.acct, "analyst")
    assert (await decide(desk, item, True, who=analyst)).status_code == 200


async def test_decision_needs_if_match_and_rejects_stale_and_double_decisions(desk, stub, api):
    await ask_for_payment(desk, stub)
    (item,) = await pending(desk)
    url = f"/v1/admin/approvals/{item['id']}/decision"
    assert (await desk.acct.post(url, {"approve": True})).status_code == 428
    assert (await desk.acct.post(url, {"approve": True}, headers={"If-Match": 'W/"stale"'})).status_code == 412
    assert (await decide(desk, item, True)).status_code == 200
    second = await decide(desk, item, False)
    assert second.status_code == 409 and "already approved" in second.json()["detail"]


async def test_two_analysts_racing_only_one_wins(desk, stub, api):
    await ask_for_payment(desk, stub)
    (item,) = await pending(desk)
    a, b = await api.add_user(desk.acct, "analyst"), await api.add_user(desk.acct, "analyst")
    ea = (await a.get(f"/v1/admin/approvals/{item['id']}")).headers["etag"]
    eb = (await b.get(f"/v1/admin/approvals/{item['id']}")).headers["etag"]
    url = f"/v1/admin/approvals/{item['id']}/decision"
    ra, rb = await asyncio.gather(a.post(url, {"approve": True}, headers={"If-Match": ea}),
                                  b.post(url, {"approve": False}, headers={"If-Match": eb}))
    assert sorted([ra.status_code, rb.status_code]) == [200, 409]


async def test_webhook_failure_is_audited_and_the_approval_stays_pending(desk, stub, webhook, app, worker):
    webhook["fail"] = 99
    await ask_for_payment(desk, stub)
    await app.state.s.approvals.drain_notifications()
    assert len(await pending(desk)) == 1
    ev = await events_of(desk.acct, worker, type="approval.notify_failed")
    assert len(ev) == 1 and "HTTP 500" in ev[0]["payload"]["error"]


async def test_webhook_retries_before_giving_up(desk, stub, webhook, app, worker):
    webhook["fail"] = 2
    await ask_for_payment(desk, stub)
    await app.state.s.approvals.drain_notifications()
    assert len(webhook["requests"]) == 1 and await events_of(desk.acct, worker, type="approval.notify_failed") == []


async def test_webhook_to_a_private_address_is_never_called(desk, stub, webhook, app, worker, owner_conn):
    await owner_conn.execute("update tenants set settings = jsonb_set(settings, '{webhook_url}', '\"http://169.254.169.254/x\"') "
                             "where id = $1::uuid", desk.acct.tenant_id)
    await ask_for_payment(desk, stub)
    await app.state.s.approvals.drain_notifications()
    assert webhook["requests"] == []
    ev = await events_of(desk.acct, worker, type="approval.notify_failed")
    assert "rejected" in ev[0]["payload"]["error"]


async def test_agent_can_poll_its_own_approval_but_not_others(desk, stub, api):
    await ask_for_payment(desk, stub)
    (item,) = await pending(desk)
    c = api.client()
    r = await c.get(f"/v1/approvals/{item['id']}", headers={"Authorization": f"Bearer {desk.openai_key}"})
    assert r.json()["status"] == "pending" and r.json()["decision"] == "ask"
    await decide(desk, item, True)
    r = await c.get(f"/v1/approvals/{item['id']}", headers={"Authorization": f"Bearer {desk.openai_key}"})
    assert (r.json()["status"], r.json()["decision"]) == ("approved", "allow")
    other = await c.get(f"/v1/approvals/{item['id']}", headers={"Authorization": f"Bearer {desk.anthropic_key}"})
    assert other.status_code == 404
    assert (await c.get(f"/v1/approvals/{item['id']}")).status_code == 401


async def test_other_tenants_cannot_see_or_decide(desk, stub, api):
    await ask_for_payment(desk, stub)
    (item,) = await pending(desk)
    stranger = await api.signup()
    assert (await stranger.get("/v1/admin/approvals")).json()["items"] == []
    assert (await stranger.get(f"/v1/admin/approvals/{item['id']}")).status_code == 404
    r = await stranger.post(f"/v1/admin/approvals/{item['id']}/decision", {"approve": True}, headers={"If-Match": "*"})
    assert r.status_code == 404


async def test_list_filters_and_pagination(desk, stub):
    for i in range(3):
        await ask_for_payment(desk, stub, args={"amount": 5000 + i, "payee": "p"})
    page = (await desk.acct.get("/v1/admin/approvals?limit=2")).json()
    assert len(page["items"]) == 2 and page["next_cursor"]
    rest = (await desk.acct.get(f"/v1/admin/approvals?limit=2&cursor={page['next_cursor']}")).json()
    assert len(rest["items"]) == 1
    await decide(desk, page["items"][0], True)
    assert len((await desk.acct.get("/v1/admin/approvals?status=approved")).json()["items"]) == 1
    assert (await desk.acct.get("/v1/admin/approvals?status=bogus")).status_code == 422


async def test_check_api_long_poll_wakes_on_approval(desk, stub, api):
    acct = desk.acct
    key = (await acct.make_key("oa-agent"))["key"]
    body = {"agent_id": "oa-agent", "tenant": acct.slug, "session_id": "s-lp",
            "action": {"tool": "pay_invoice", "arguments": {"amount": 5000, "payee": "ACME"}}, "wait_seconds": 10}
    c = api.client()
    first = asyncio.create_task(c.post("/v1/check", json=body, headers={"Authorization": f"Bearer {key}"}))
    for _ in range(50):
        await asyncio.sleep(0.1)
        items = await pending(desk)
        if items:
            break
    assert items
    started = asyncio.get_running_loop().time()
    await decide(desk, items[0], True)
    r = await asyncio.wait_for(first, 5)
    assert asyncio.get_running_loop().time() - started < 3
    assert r.json()["decision"] == "allow" and "Approved by" in r.json()["reason"]


async def test_check_api_long_poll_returns_ask_when_nobody_answers_in_time(desk, stub, api):
    acct = desk.acct
    key = (await acct.make_key("oa-agent"))["key"]
    body = {"agent_id": "oa-agent", "tenant": acct.slug, "session_id": "s-lp2",
            "action": {"tool": "pay_invoice", "arguments": {"amount": 5000}}, "wait_seconds": 1}
    r = await api.client().post("/v1/check", json=body, headers={"Authorization": f"Bearer {key}"})
    assert r.json()["decision"] == "ask" and r.json()["approval_id"]
    del body["wait_seconds"]
    r2 = await api.client().post("/v1/check", json=body, headers={"Authorization": f"Bearer {key}"})
    assert r2.json()["approval_id"] == r.json()["approval_id"]                       # polling mode reuses the pending item


async def test_check_api_denial_comes_back_as_block(desk, stub, api):
    acct = desk.acct
    key = (await acct.make_key("oa-agent"))["key"]
    body = {"agent_id": "oa-agent", "tenant": acct.slug, "session_id": "s-lp3",
            "action": {"tool": "pay_invoice", "arguments": {"amount": 5000}}, "wait_seconds": 10}
    task = asyncio.create_task(api.client().post("/v1/check", json=body, headers={"Authorization": f"Bearer {key}"}))
    for _ in range(50):
        await asyncio.sleep(0.1)
        if items := await pending(desk):
            break
    await decide(desk, items[0], False)
    r = await asyncio.wait_for(task, 5)
    assert r.json()["decision"] == "block" and "Denied" in r.json()["reason"]


async def test_events_cover_the_whole_approval_story(desk, stub, worker):
    r = await ask_for_payment(desk, stub)
    (item,) = await pending(desk)
    await decide(desk, item, True)
    events = await events_of(desk.acct, worker, trace=r.headers["x-agentshield-trace"])
    types = [e["type"] for e in events]
    assert {"tool.requested", "policy.decision", "approval.requested", "tool.rewritten", "approval.decided"} <= set(types)
    req = next(e for e in events if e["type"] == "approval.requested")
    assert req["decision"] == "ask" and req["payload"]["approval_id"] == item["id"]
