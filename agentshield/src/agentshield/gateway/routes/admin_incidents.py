"""Incidents: a marked session. Marking one keeps its payloads for the longer incident retention."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import text

from ...contracts.admin import IncidentCreate, IncidentPatch, IncidentRead, Page
from ...contracts.errors import ApiError
from ...db.tenant_tx import tenant_tx
from ...tenants import registry
from ...tenants.auth import user_ctx
from ...tenants.context import TenantContext
from ..state import get_state

router = APIRouter(prefix="/v1/admin/incidents", tags=["incidents"])
_COLS = "id, session_id, title, severity, status, created_by, created_at, updated_at"


@router.get("", response_model=Page[IncidentRead])
async def list_incidents(request: Request, status: str | None = Query(None, pattern="^(open|investigating|closed)$"),
                         limit: int = Query(50, ge=1, le=200), cursor: str | None = None,
                         ctx: TenantContext = Depends(user_ctx("viewer"))) -> Page[IncidentRead]:
    sql = f"select {_COLS} from incidents where true"
    params: dict[str, Any] = {"n": limit + 1}
    if status:
        sql += " and status = :status"
        params["status"] = status
    cur = registry.decode_cursor(cursor)
    if cur:
        sql += " and id < :cur"
        params["cur"] = cur
    async with tenant_tx(get_state(request).engine, ctx.tenant_id) as conn:
        rows = [dict(r) for r in (await conn.execute(text(sql + " order by id desc limit :n"), params)).mappings().all()]
    items, nxt = registry.page(rows, limit)
    return Page[IncidentRead](items=[IncidentRead(**r) for r in items], next_cursor=nxt)


@router.post("", status_code=201, response_model=IncidentRead)
async def create_incident(body: IncidentCreate, request: Request,
                          ctx: TenantContext = Depends(user_ctx("analyst"))) -> IncidentRead:
    async with tenant_tx(get_state(request).engine, ctx.tenant_id) as conn:
        found = (await conn.execute(text("select 1 from sessions where id = :s"), {"s": body.session_id})).first()
        if found is None:
            raise ApiError("not_found", "Session not found")
        row = (await conn.execute(text(
            f"insert into incidents (tenant_id, session_id, title, severity, created_by) "
            f"values (:t, :s, :title, :sev, :u) returning {_COLS}"),
            {"t": ctx.tenant_id, "s": body.session_id, "title": body.title, "sev": body.severity,
             "u": ctx.actor_id})).mappings().one()
    return IncidentRead(**dict(row))


@router.patch("/{incident_id}", response_model=IncidentRead)
async def patch_incident(incident_id: UUID, body: IncidentPatch, request: Request,
                         ctx: TenantContext = Depends(user_ctx("analyst"))) -> IncidentRead:
    fields = body.model_dump(exclude_unset=True, exclude_none=True)
    async with tenant_tx(get_state(request).engine, ctx.tenant_id) as conn:
        if fields:
            sets = ", ".join(f"{k} = :{k}" for k in fields)       # keys come from the model, never from the client
            row = (await conn.execute(text(f"update incidents set {sets} where id = :i returning {_COLS}"),
                                      {**fields, "i": incident_id})).mappings().first()
        else:
            row = (await conn.execute(text(f"select {_COLS} from incidents where id = :i"), {"i": incident_id})).mappings().first()
    if row is None:
        raise ApiError("not_found", "Incident not found")
    return IncidentRead(**dict(row))
