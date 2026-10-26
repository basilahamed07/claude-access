"""Alerts and the overview numbers: derived from the audit log, nothing is stored twice."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Literal

from fastapi import APIRouter, Depends, Query, Request

from ...audit.read import ALERT_KINDS, list_alerts, overview
from ...contracts.admin import AlertRead, Page, StatsOverview
from ...contracts.errors import ApiError
from ...db.tenant_tx import tenant_tx
from ...tenants.auth import user_ctx
from ...tenants.context import TenantContext
from ..state import get_state

router = APIRouter(tags=["alerts"])


@router.get("/v1/admin/alerts", response_model=Page[AlertRead])
async def alerts(request: Request, kind: str | None = None, since_hours: int = Query(24, ge=1, le=24 * 30),
                 limit: int = Query(50, ge=1, le=200), cursor: str | None = None,
                 ctx: TenantContext = Depends(user_ctx("viewer"))) -> Page[AlertRead]:
    if kind is not None and kind not in ALERT_KINDS:
        raise ApiError("validation_failed", f"Unknown alert kind; use one of: {', '.join(ALERT_KINDS)}")
    since = datetime.now(UTC) - timedelta(hours=since_hours)
    async with tenant_tx(get_state(request).engine, ctx.tenant_id) as conn:
        rows, nxt = await list_alerts(conn, ctx.tenant_id, since=since, kind=kind, limit=limit, cursor=cursor)
    return Page[AlertRead](items=[AlertRead(**r) for r in rows], next_cursor=nxt)


@router.get("/v1/admin/stats/overview", response_model=StatsOverview)
async def stats_overview(request: Request, window: Literal["24h", "7d"] = "24h",
                         ctx: TenantContext = Depends(user_ctx("viewer"))) -> StatsOverview:
    async with tenant_tx(get_state(request).engine, ctx.tenant_id) as conn:
        data = await overview(conn, ctx.tenant_id, window, datetime.now(UTC))
    return StatsOverview(**data)
