"""POST /v1/check: the prompt §9 contract, auth, rate limits and failure modes."""

import pytest
from tests.conftest import events_of, set_policy

from agentshield.audit.worker import AuditWorker

pytestmark = pytest.mark.integration


@pytest.fixture
def worker(worker_engine, redis_client):
    return AuditWorker(worker_engine, redis_client)


@pytest.fixture
async def bot(api):
    acct = await api.signup()
    await acct.make_agent("email-reader-01")
    key = (await acct.make_key("email-reader-01"))["key"]
    await set_policy(acct, "email-reader-01")
    return acct, {"Authorization": f"Bearer {key}"}, api


def req(acct, **over):
    body = {
        "agent_id": "email-reader-01", "tenant": acct.slug, "session_id": "s-9f2c",
        "action": {"tool": "send_email", "arguments": {"to": "x@unknown.com", "body": "..."}},
        "context": {"user_request": "Summarize my unread mail",
                    "untrusted_inputs": [{"source": "email", "id": "m-441", "text": "..."}]},
    }
    body.update(over)
    return body


async def test_prompt_section9_example_is_blocked_with_the_documented_response(bot):
    acct, auth, api = bot
    r = await api.client().post("/v1/check", json=req(acct), headers=auth)
    assert r.status_code == 200
    body = r.json()
    assert body["decision"] == "block" and body["rule_id"] == "deny-external-send"
    assert body["reason"] == "External email is not permitted for this agent"
    assert body["trace_id"].startswith("t-") and r.headers["x-agentshield-trace"] == body["trace_id"]
    assert body["mode"] == "enforce" and body["would_have"] is None and body["approval_id"] is None
    assert 0 <= body["risk_score"] <= 1 and body["findings"] == []
    assert set(body) >= {"decision", "reason", "rule_id", "risk_score", "findings", "trace_id"}


async def test_allow_unknown_tool_and_ask(bot):
    acct, auth, api = bot
    c = api.client()
    ok = (await c.post("/v1/check", json=req(acct, action={"tool": "read_email", "arguments": {"folder": "INBOX"}}), headers=auth)).json()
    assert (ok["decision"], ok["rule_id"]) == ("allow", "allow-read-mail")
    deny = (await c.post("/v1/check", json=req(acct, action={"tool": "format_disk", "arguments": {}}), headers=auth)).json()
    assert (deny["decision"], deny["rule_id"]) == ("block", "default-deny")
    ask = (await c.post("/v1/check", json=req(acct, action={"tool": "pay_invoice", "arguments": {"amount": 5000}}), headers=auth)).json()
    assert (ask["decision"], ask["rule_id"]) == ("ask", "ask-large-payment")


async def test_string_arguments_are_not_accepted_but_nested_objects_are(bot):
    acct, auth, api = bot
    c = api.client()
    r = await c.post("/v1/check", json=req(acct, action={"tool": "send_email", "arguments": "not an object"}), headers=auth)
    assert r.status_code == 422 and r.json()["code"] == "validation_failed"
    r = await c.post("/v1/check", json=req(acct, action={"tool": "send_email", "arguments": {"payload": {"to": ["a@acme.com"]}}}), headers=auth)
    assert r.status_code == 200 and r.json()["rule_id"] == "deny-external-send"      # no top-level `to`


async def test_caller_advised_tag_cannot_loosen_the_policy_and_only_tightens_unknown_tools(bot):
    acct, auth, api = bot
    c = api.client()
    r = await c.post("/v1/check", json=req(acct, action={"tool": "send_email", "effect_tag": "read",
                                                         "arguments": {"to": "x@evil.com"}}), headers=auth)
    assert r.json()["decision"] == "block"
    r = await c.post("/v1/check", json=req(acct, action={"tool": "wipe", "effect_tag": "execute", "arguments": {}}), headers=auth)
    assert r.json()["rule_id"] == "tag-default:execute"


async def test_credential_mismatches_are_403(bot):
    acct, auth, api = bot
    c = api.client()
    r = await c.post("/v1/check", json=req(acct, agent_id="someone-else"), headers=auth)
    assert r.status_code == 403 and r.json()["code"] == "credential_mismatch"
    r = await c.post("/v1/check", json=req(acct, tenant="other-tenant"), headers=auth)
    assert r.status_code == 403 and r.json()["code"] == "credential_mismatch"
    other = await api.signup()
    r = await c.post("/v1/check", json=req(other), headers=auth)          # right agent id, someone else's tenant slug
    assert r.status_code == 403


async def test_tenant_may_be_given_as_slug_or_id(bot):
    acct, auth, api = bot
    assert (await api.client().post("/v1/check", json=req(acct, tenant=acct.tenant_id), headers=auth)).status_code == 200


async def test_auth_required_and_jwt_accepted_and_user_session_rejected(bot):
    acct, auth, api = bot
    c = api.client()
    assert (await c.post("/v1/check", json=req(acct))).status_code == 401
    tok = (await c.post("/v1/token", headers=auth)).json()["access_token"]
    assert (await c.post("/v1/check", json=req(acct), headers={"Authorization": f"Bearer {tok}"})).status_code == 200
    assert (await acct.post("/v1/check", req(acct))).status_code == 401      # dashboard session is not an agent credential


async def test_suspended_agent_is_refused(bot):
    acct, auth, api = bot
    etag = (await acct.get("/v1/admin/agents/email-reader-01")).headers["etag"]
    await acct.patch("/v1/admin/agents/email-reader-01", {"status": "suspended"}, headers={"If-Match": etag})
    assert (await api.client().post("/v1/check", json=req(acct), headers=auth)).status_code == 403


async def test_monitor_mode_reports_would_have(bot):
    acct, auth, api = bot
    etag = (await acct.get("/v1/admin/agents/email-reader-01")).headers["etag"]
    await acct.patch("/v1/admin/agents/email-reader-01", {"mode": "monitor"}, headers={"If-Match": etag})
    body = (await api.client().post("/v1/check", json=req(acct), headers=auth)).json()
    assert (body["decision"], body["would_have"], body["mode"]) == ("allow", "block", "monitor")
    assert body["rule_id"] == "deny-external-send"


async def test_session_risk_from_the_firewall_tightens_check_decisions(bot, redis_client, owner_conn):
    from agentshield.policy.session_state import raise_risk
    acct, auth, api = bot
    c = api.client()
    read = req(acct, action={"tool": "read_email", "arguments": {"folder": "INBOX"}})
    assert (await c.post("/v1/check", json=read, headers=auth)).json()["decision"] == "allow"
    sid = await owner_conn.fetchval("select id from sessions where session_key = 's-9f2c' and tenant_id = $1::uuid", acct.tenant_id)
    await raise_risk(redis_client, acct.tenant_id, sid, 0.92)
    body = (await c.post("/v1/check", json=read, headers=auth)).json()
    assert (body["decision"], body["rule_id"], body["risk_score"]) == ("block", "tighten-on-risk", 0.92)


async def test_check_rate_limit_is_separate_from_model_budget(bot, app, monkeypatch):
    acct, auth, api = bot
    monkeypatch.setattr(app.state.s.settings, "check_rpm", 3)
    c = api.client()
    codes = [(await c.post("/v1/check", json=req(acct), headers=auth)).status_code for _ in range(4)]
    assert codes == [200, 200, 200, 429]
    r = await c.post("/v1/check", json=req(acct), headers=auth)
    assert r.json()["code"] == "rate_limited" and "retry-after" in r.headers
    assert (await app.state.s.budgets.usage(acct.tenant_id, "email-reader-01")) == {}      # no daily call consumed


async def test_budget_service_down_fails_closed_for_effectful_and_open_for_read(bot, app, monkeypatch):
    from agentshield.policy.budgets import BudgetUnavailable

    async def down(*a, **kw):
        raise BudgetUnavailable("down")

    monkeypatch.setattr(app.state.s.budgets, "admit", down)
    acct, auth, api = bot
    c = api.client()
    internal = req(acct, action={"tool": "send_email", "arguments": {"to": "bob@acme.com"}})
    assert (await c.post("/v1/check", json=internal, headers=auth)).json()["rule_id"] == "budget-service-unavailable"
    read = req(acct, action={"tool": "read_email", "arguments": {"folder": "INBOX"}})
    assert (await c.post("/v1/check", json=read, headers=auth)).json()["decision"] == "allow"


async def test_decision_failure_uses_the_advised_tag_for_the_failure_rule(bot, monkeypatch):
    import agentshield.policy.decide as decide

    async def boom(*a, **kw):
        raise ConnectionError("redis down")

    monkeypatch.setattr(decide, "get_risk", boom)
    acct, auth, api = bot
    c = api.client()
    r = (await c.post("/v1/check", json=req(acct, action={"tool": "lookup", "effect_tag": "read", "arguments": {}}), headers=auth)).json()
    assert (r["decision"], r["rule_id"]) == ("allow", "evaluator-error-fail-open")
    r = (await c.post("/v1/check", json=req(acct, action={"tool": "lookup", "arguments": {}}), headers=auth)).json()
    assert (r["decision"], r["rule_id"]) == ("block", "evaluator-error")


async def test_check_decisions_are_audited_with_session_and_user(bot, worker):
    acct, auth, api = bot
    body = req(acct)
    body["context"]["end_user"] = "u-1234"
    r = await api.client().post("/v1/check", json=body, headers=auth)
    events = await events_of(acct, worker, trace=r.json()["trace_id"])
    assert {e["type"] for e in events} == {"tool.requested", "policy.decision"}
    dec = next(e for e in events if e["type"] == "policy.decision")
    assert dec["end_user"] == "u-1234" and dec["agent_slug"] == "email-reader-01" and dec["payload"]["source"] == "check"
    assert dec["session_id"] is not None


async def test_validation_errors(bot):
    acct, auth, api = bot
    c = api.client()
    for bad in [{**req(acct), "extra": 1}, {**req(acct), "session_id": ""}, {**req(acct), "wait_seconds": 31},
                {**req(acct), "action": {"tool": "", "arguments": {}}}]:
        assert (await c.post("/v1/check", json=bad, headers=auth)).status_code == 422
