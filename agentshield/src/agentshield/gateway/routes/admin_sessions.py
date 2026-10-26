"""Sessions: list, timeline, replay against a policy version, signed-off export (api spec §A.3)."""

from __future__ import annotations

from datetime import UTC, datetime
from itertools import groupby
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import text

from ...audit.chain import verify_chain
from ...audit.read import MAX_TIMELINE_EVENTS, get_session, list_sessions, session_events
from ...audit.replay import replay_session
from ...contracts.admin import (
    EventRead,
    ExportVerification,
    Page,
    ReplayRequest,
    ReplayResult,
    SessionExport,
    SessionRead,
    Timeline,
    TimelineTrace,
)
from ...db.tenant_tx import tenant_tx
from ...tenants.auth import user_ctx
from ...tenants.context import TenantContext
from ..state import get_state

router = APIRouter(prefix="/v1/admin/sessions", tags=["sessions"])


@router.get("", response_model=Page[SessionRead])
async def sessions(request: Request, agent: str | None = None, user: str | None = None,
                   min_risk: float | None = Query(None, ge=0, le=1), limit: int = Query(50, ge=1, le=200),
                   cursor: str | None = None, ctx: TenantContext = Depends(user_ctx("viewer"))) -> Page[SessionRead]:
    async with tenant_tx(get_state(request).engine, ctx.tenant_id) as conn:
        rows, nxt = await list_sessions(conn, ctx.tenant_id, agent=agent, user=user, min_risk=min_risk,
                                        limit=limit, cursor=cursor)
    return Page[SessionRead](items=[SessionRead(**r) for r in rows], next_cursor=nxt)


@router.get("/{session_id}", response_model=SessionRead)
async def session(session_id: UUID, request: Request, ctx: TenantContext = Depends(user_ctx("viewer"))) -> SessionRead:
    async with tenant_tx(get_state(request).engine, ctx.tenant_id) as conn:
        return SessionRead(**await get_session(conn, ctx.tenant_id, session_id))


@router.get("/{session_id}/timeline", response_model=Timeline)
async def timeline(session_id: UUID, request: Request, ctx: TenantContext = Depends(user_ctx("viewer"))) -> Timeline:
    """Events in chain order, grouped by trace. Viewers see envelopes only; analysts also see redacted payloads."""
    analyst = ctx.has_role("analyst")
    async with tenant_tx(get_state(request).engine, ctx.tenant_id) as conn:
        head = await get_session(conn, ctx.tenant_id, session_id)
        events = await session_events(conn, ctx.tenant_id, session_id, include_payload=analyst)
    traces = [TimelineTrace(trace_id=tid, started_at=items[0]["ts"], events=[EventRead(**e) for e in items])
              for tid, grp in groupby(events, key=lambda e: e["trace_id"]) if (items := list(grp))]
    return Timeline(session=SessionRead(**head), traces=traces, truncated=len(events) >= MAX_TIMELINE_EVENTS)


@router.post("/{session_id}/replay", response_model=ReplayResult)
async def replay(session_id: UUID, body: ReplayRequest, request: Request,
                 ctx: TenantContext = Depends(user_ctx("analyst"))) -> ReplayResult:
    state = get_state(request)
    return await replay_session(state.engine, state.policies, ctx.tenant_id, session_id, policy_version=body.policy_version)


@router.get("/{session_id}/export.json", response_model=SessionExport)
async def export(session_id: UUID, request: Request, ctx: TenantContext = Depends(user_ctx("analyst"))) -> SessionExport:
    state = get_state(request)
    async with tenant_tx(state.engine, ctx.tenant_id) as conn:
        head = await get_session(conn, ctx.tenant_id, session_id)
        events = await session_events(conn, ctx.tenant_id, session_id, include_payload=True)
        chain = (await conn.execute(text(
            "select last_seq, encode(last_hash, 'hex') as last_hash from audit_chain_heads where tenant_id = :t"),
            {"t": ctx.tenant_id})).mappings().first()
    report = await verify_chain(state.engine, ctx.tenant_id)
    return SessionExport(
        exported_at=datetime.now(UTC), session=SessionRead(**head), events=[EventRead(**e) for e in events],
        chain_head=dict(chain) if chain else None,
        verification=ExportVerification(verified=report.ok, checked=report.checked, first_seq=report.first_seq,
                                        last_seq=report.last_seq, first_bad_seq=report.first_bad_seq, reason=report.reason))
