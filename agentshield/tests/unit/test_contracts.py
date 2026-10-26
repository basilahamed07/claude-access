import json

import pytest
from pydantic import ValidationError

from agentshield.contracts.check import CheckRequest, CheckResponse
from agentshield.contracts.decision import Decision, EffectTag
from agentshield.contracts.errors import Problem
from agentshield.contracts.events import AUDIT_EVENT_COLUMNS, AuditEvent, EventType
from agentshield.contracts.ids import SLUG_RE, new_event_id, new_trace_id

PROMPT_SECTION9 = {
    "agent_id": "email-reader-01",
    "tenant": "acme",
    "session_id": "s-9f2c",
    "action": {"tool": "send_email", "arguments": {"to": "x@unknown.com", "body": "..."}},
    "context": {
        "user_request": "Summarize my unread mail",
        "untrusted_inputs": [{"source": "email", "id": "m-441", "text": "..."}],
    },
}


def test_decision_has_exactly_three_values():
    assert {d.value for d in Decision} == {"allow", "block", "ask"}


def test_effect_tags_are_the_six_spec_values():
    assert {t.value for t in EffectTag} == {
        "read", "write", "destructive", "external", "financial", "execute",
    }


def test_check_request_accepts_prompt_section9_example():
    req = CheckRequest.model_validate(PROMPT_SECTION9)
    dumped = req.model_dump(mode="json", exclude_none=True, exclude_defaults=True)
    for key, value in PROMPT_SECTION9.items():
        assert dumped[key] == value


def test_check_request_forbids_extra_fields():
    bad = {**PROMPT_SECTION9, "tenant_id": "other"}
    with pytest.raises(ValidationError):
        CheckRequest.model_validate(bad)


def test_check_response_roundtrips_prompt_example():
    resp = CheckResponse.model_validate({
        "decision": "block",
        "reason": "Tool send_email is not allowed",
        "rule_id": "deny-external-send",
        "risk_score": 0.92,
        "findings": [{"module": "injection", "span": "m-441:120-210"}],
        "trace_id": "t-77ab",
    })
    assert resp.decision is Decision.block
    assert resp.mode == "enforce"
    json.dumps(resp.model_dump(mode="json"))


def test_check_response_rejects_unknown_decision():
    with pytest.raises(ValidationError):
        CheckResponse.model_validate({
            "decision": "maybe", "reason": "x", "rule_id": "r", "risk_score": 0.1, "trace_id": "t-1",
        })


def test_ids_have_prefixes_and_sort_by_time():
    a, b = new_trace_id(), new_trace_id()
    assert a.startswith("t-") and b.startswith("t-")
    import time
    first = new_event_id()
    time.sleep(0.003)
    second = new_event_id()
    assert first.startswith("evt_") and first < second


def test_slug_regex():
    assert SLUG_RE.match("email-reader-01")
    assert not SLUG_RE.match("Email")
    assert not SLUG_RE.match("-bad")
    assert not SLUG_RE.match("a")


def test_event_type_enum_matches_spec_list():
    expected = {
        "request.received", "content.untrusted", "model.response", "tool.requested",
        "tool.rewritten", "budget.exceeded", "budget.price_missing", "error", "content.scanned",
        "policy.decision", "approval.requested", "approval.decided", "approval.notify_failed",
        "audit.gap", "audit.checkpoint", "mcp.scan.started", "mcp.scan.finished",
        "mcp.drift_detected", "mcp.tool_call", "shadow.tool_seen", "shadow.dlp_hit",
        "shadow.source_stale",
    }
    assert {e.value for e in EventType} == expected


def test_audit_event_requires_trace_and_schema():
    with pytest.raises(ValidationError):
        AuditEvent.model_validate({"module": "gateway", "type": "request.received"})
    ev = AuditEvent(
        tenant_id="00000000-0000-0000-0000-000000000001", trace_id="t-1", module="gateway",
        type=EventType.request_received, severity="info", summary="x",
    )
    assert ev.schema_ == "agentshield.event/1"
    assert ev.id.startswith("evt_")


def test_audit_event_fields_match_audit_events_columns():
    envelope = {f.alias or n for n, f in AuditEvent.model_fields.items()} - {"payload"}
    cols = set(AUDIT_EVENT_COLUMNS)
    # envelope == table columns minus chain columns (seq, prev_hash, hash)
    assert envelope == cols - {"seq", "prev_hash", "hash"}


def test_problem_serializes_with_problem_json_fields():
    p = Problem(code="not_found", title="Not found", status=404, detail="nope", request_id="req_1")
    d = p.model_dump(mode="json", exclude_none=True)
    assert d["status"] == 404 and d["code"] == "not_found"
    assert d["type"].endswith("/not_found")
