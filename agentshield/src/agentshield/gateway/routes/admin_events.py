"""Audit log search (api spec §A.3). Timeline, replay and export arrive with task B17."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request

from ...audit.read import EventFilter, list_events
from ...contracts.admin import EventRead, Page
from ...contracts.errors import ApiError
from ...db.tenant_tx import tenant_tx
from ...tenants.auth import user_ctx
from ...tenants.context import TenantContext
from ..state import get_state

router = APIRouter(prefix="/v1/admin/events", tags=["audit"])


@router.get("", response_model=Page[EventRead])
async def search_events(
    request: Request, agent: str | None = None, session: UUID | None = None, trace: str | None = None,
    user: str | None = None, module: str | None = None, type: str | None = None, decision: str | None = None,
    severity: str | None = None, tool: str | None = None, since: datetime | None = None,
    until: datetime | None = None, limit: int = Query(50, ge=1, le=200), cursor: str | None = None,
    include_payload: bool = False, ctx: TenantContext = Depends(user_ctx("viewer")),
) -> Page[EventRead]:
    if include_payload and not ctx.has_role("analyst"):
        raise ApiError("forbidden", "Reading event payloads requires the analyst role")
    flt = EventFilter(agent=agent, session=session, trace=trace, user=user, module=module, type=type,
                      decision=decision, severity=severity, tool=tool, since=since, until=until)
    async with tenant_tx(get_state(request).engine, ctx.tenant_id) as conn:
        rows, nxt = await list_events(conn, ctx.tenant_id, flt, limit, cursor, include_payload=include_payload)
    return Page[EventRead](items=[EventRead(**r) for r in rows], next_cursor=nxt)
