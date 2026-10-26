"""Small helper to build events from a proxy/check context."""

from __future__ import annotations

from typing import Any, Literal

from ..contracts.decision import Decision
from ..contracts.events import AuditEvent, EventType, Module, Severity
from ..proxy.sessions import SessionRef
from ..tenants.context import TenantContext


def make_event(ctx: TenantContext, trace_id: str, module: Module, etype: EventType, summary: str, *,
               session: SessionRef | None = None, decision: Decision | None = None, rule_id: str | None = None,
               reason: str | None = None, severity: Severity = "info", parent_id: str | None = None,
               ) -> AuditEvent:
    return AuditEvent(
        tenant_id=str(ctx.tenant_id), agent_slug=ctx.agent_slug, session_id=str(session.id) if session else None,
        end_user=session.end_user if session else None, trace_id=trace_id, module=module, type=etype,
        decision=decision, rule_id=rule_id, reason=reason, severity=severity, summary=summary, parent_id=parent_id)


_ = (Any, Literal)
