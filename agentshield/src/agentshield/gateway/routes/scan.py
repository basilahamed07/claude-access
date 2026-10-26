"""POST /v1/scan: scan one piece of untrusted content (the SDK / custom-agent integration mode)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from ...contracts.errors import ApiError
from ...contracts.ids import new_trace_id
from ...contracts.scan import ScanFinding, ScanRequest, ScanResult
from ...db.tenant_tx import tenant_tx
from ...observability import link_trace
from ...policy.budgets import BudgetUnavailable
from ...policy.session_state import accumulate_risk
from ...proxy.sessions import upsert_session
from ...scan.action_check import ACTION_RISK, action_in_scope, policy_domains
from ...tenants import registry
from ...tenants.auth import agent_ctx
from ...tenants.context import TenantContext
from ..state import get_state

router = APIRouter(tags=["scan"])


@router.post("/v1/scan", response_model=ScanResult)
async def scan_content(body: ScanRequest, request: Request, ctx: TenantContext = Depends(agent_ctx)) -> ScanResult:
    state = get_state(request)
    if len(body.text.encode("utf-8", "replace")) > state.settings.scan_max_item_bytes:
        raise ApiError("payload_too_large", f"Content exceeds {state.settings.scan_max_item_bytes} bytes")
    try:
        rate = await state.budgets.admit(ctx.tenant_id, ctx.agent_slug or "", None, scope=":scan", count_call=False,
                                         default_rpm=state.settings.check_rpm)
        if not rate.ok:
            raise ApiError("rate_limited", rate.message(), headers={"Retry-After": str(rate.retry_after)})
    except BudgetUnavailable:
        pass                                           # scanning is read-only: rate limiting is best effort
    trace_id = new_trace_id()
    link_trace(trace_id)
    session = None
    row = None
    async with tenant_tx(state.engine, ctx.tenant_id) as conn:
        row = await registry.get_proxy_config(conn, ctx.actor_id)
        if row is None or row["status"] != "active":
            raise ApiError("forbidden", "Agent is suspended or no longer exists")
        if body.session_id:
            session = await upsert_session(conn, ctx.tenant_id, ctx.actor_id, body.session_id, None, None)
    result = await state.scanner.scan_content(ctx, trace_id=trace_id, session=session, source=body.source,
                                              content_id=body.id, text_=body.text)
    action = body.planned_action
    if isinstance(action, dict) and action.get("tool") and session is not None:
        args = action.get("arguments")
        policy = await state.policies.get(state.engine, ctx.tenant_id, row["agent_id"], row["active_policy_version"])
        check = action_in_scope(session.user_request, str(action["tool"]), args if isinstance(args, dict) else None,
                                policy_domains(policy))
        if not check.ok:
            result.flags.append("action_out_of_scope")
            result.findings.append(ScanFinding(rule_id="action-out-of-scope", category="action_check", text=check.reason,
                                               layer="action_check"))
            result.risk_score = await accumulate_risk(state.redis, ctx.tenant_id, session.id, ACTION_RISK)
    return result
