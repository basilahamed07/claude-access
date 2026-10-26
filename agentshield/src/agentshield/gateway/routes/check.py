"""POST /v1/check: ask whether a planned tool call is allowed (the SDK / custom-agent integration mode)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy import text

from ...contracts.check import CheckRequest, CheckResponse
from ...contracts.errors import ApiError
from ...contracts.ids import new_trace_id
from ...db.tenant_tx import tenant_tx
from ...policy.budgets import BudgetUnavailable
from ...policy.decide import AgentInfo
from ...proxy.sessions import upsert_session
from ...tenants import registry
from ...tenants.auth import agent_ctx
from ...tenants.context import TenantContext
from ..state import get_state

router = APIRouter(tags=["check"])


@router.post("/v1/check", response_model=CheckResponse)
async def check(body: CheckRequest, request: Request, ctx: TenantContext = Depends(agent_ctx)) -> JSONResponse:
    state = get_state(request)
    if body.agent_id != ctx.agent_slug:
        raise ApiError("credential_mismatch", f"This credential belongs to agent '{ctx.agent_slug}', not '{body.agent_id}'")
    async with tenant_tx(state.engine, ctx.tenant_id) as conn:
        tenant_slug = (await conn.execute(text("select slug from tenants"))).scalar_one()
    if body.tenant.lower() not in {str(tenant_slug).lower(), str(ctx.tenant_id)}:
        raise ApiError("credential_mismatch", "This credential belongs to a different tenant")

    unavailable = False
    try:
        rate = await state.budgets.admit(ctx.tenant_id, ctx.agent_slug or "", None, scope=":check", count_call=False,
                                         default_rpm=state.settings.check_rpm)
        if not rate.ok:
            raise ApiError("rate_limited", rate.message(), headers={"Retry-After": str(rate.retry_after)})
    except BudgetUnavailable:
        unavailable = True

    trace_id = new_trace_id()
    async with tenant_tx(state.engine, ctx.tenant_id) as conn:
        row = await registry.get_proxy_config(conn, ctx.actor_id)
        if row is None or row["status"] != "active":
            raise ApiError("forbidden", "Agent is suspended or no longer exists")
        session = await upsert_session(conn, ctx.tenant_id, ctx.actor_id, body.session_id,
                                       body.context.user_request, body.context.end_user)
    resp = await state.enforcer.decide(
        ctx, AgentInfo.from_row(row), session, body.action.tool, body.action.arguments, trace_id=trace_id,
        source="check", advised_tag=body.action.effect_tag, budget_unavailable=unavailable)
    return JSONResponse(resp.model_dump(mode="json"), headers={"X-AgentShield-Trace": trace_id})
