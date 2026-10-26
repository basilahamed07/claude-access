"""Audit event envelope (arch §4.2). Envelope fields == `audit_events` columns minus the
chain columns (`seq`, `prev_hash`, `hash`); the redacted payload travels next to it."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from .decision import Decision
from .ids import new_event_id

SCHEMA_ID = "agentshield.event/1"


class EventType(StrEnum):
    request_received = "request.received"
    content_untrusted = "content.untrusted"
    model_response = "model.response"
    tool_requested = "tool.requested"
    tool_rewritten = "tool.rewritten"
    budget_exceeded = "budget.exceeded"
    budget_price_missing = "budget.price_missing"
    error = "error"
    content_scanned = "content.scanned"
    policy_decision = "policy.decision"
    approval_requested = "approval.requested"
    approval_decided = "approval.decided"
    approval_notify_failed = "approval.notify_failed"
    audit_gap = "audit.gap"
    audit_checkpoint = "audit.checkpoint"
    mcp_scan_started = "mcp.scan.started"
    mcp_scan_finished = "mcp.scan.finished"
    mcp_drift_detected = "mcp.drift_detected"
    mcp_tool_call = "mcp.tool_call"
    shadow_tool_seen = "shadow.tool_seen"
    shadow_dlp_hit = "shadow.dlp_hit"
    shadow_source_stale = "shadow.source_stale"


Module = Literal["gateway", "policy", "injection", "mcp", "shadow", "approval", "audit"]
Severity = Literal["info", "low", "medium", "high", "critical"]

# Mirror of the audit_events columns (db §B.3). B2's migration test compares against this.
AUDIT_EVENT_COLUMNS: tuple[str, ...] = (
    "tenant_id", "seq", "ts", "schema", "id", "trace_id", "session_id", "agent_slug", "end_user",
    "parent_id", "module", "type", "decision", "rule_id", "reason", "severity", "summary",
    "payload_sha256", "payload_truncated", "prev_hash", "hash", "otel_span_id",
)


class AuditEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    schema_: str = Field(default=SCHEMA_ID, alias="schema")
    id: str = Field(default_factory=new_event_id)
    ts: datetime = Field(default_factory=lambda: datetime.now(UTC))
    tenant_id: str
    agent_slug: str | None = None
    session_id: str | None = None
    trace_id: str
    parent_id: str | None = None
    end_user: str | None = None
    module: Module
    type: EventType
    decision: Decision | None = None
    rule_id: str | None = None
    reason: str | None = None
    severity: Severity = "info"
    summary: str = ""
    payload_sha256: str = ""
    payload_truncated: bool = False
    otel_span_id: str | None = None
    payload: dict[str, Any] = Field(default_factory=dict)

    def envelope(self) -> dict[str, Any]:
        """The hashed part: everything except the payload body (the digest is included)."""
        data = self.model_dump(mode="json", by_alias=True, exclude={"payload"})
        return data
