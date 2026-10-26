"""Approval queue: reviewers (control plane) and the waiting agent (data plane)."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, Response

from ...contracts.admin import AgentApprovalRead, ApprovalDecision, ApprovalRead, Page
from ...policy.approvals import approval_etag
from ...tenants import registry
from ...tenants.auth import agent_ctx, user_ctx
from ...tenants.context import TenantContext
from ..state import get_state

router = APIRouter(tags=["approvals"])


@router.get("/v1/admin/approvals", response_model=Page[ApprovalRead])
async def list_approvals(request: Request, status: str | None = Query(None, pattern="^(pending|approved|denied|expired)$"),
                         limit: int = Query(50, ge=1, le=200), cursor: str | None = None,
                         ctx: TenantContext = Depends(user_ctx("analyst"))) -> Page[ApprovalRead]:
    rows, nxt = await get_state(request).approvals.list(ctx.tenant_id, status=status, limit=limit,
                                                        cursor=registry.decode_cursor(cursor))
    return Page[ApprovalRead](items=[ApprovalRead(**r) for r in rows], next_cursor=nxt)


@router.get("/v1/admin/approvals/{approval_id}", response_model=ApprovalRead)
async def get_approval(approval_id: UUID, request: Request, response: Response,
                       ctx: TenantContext = Depends(user_ctx("analyst"))) -> ApprovalRead:
    row = await get_state(request).approvals.get(ctx.tenant_id, approval_id)
    response.headers["ETag"] = approval_etag(row)
    return ApprovalRead(**row)


@router.post("/v1/admin/approvals/{approval_id}/decision", response_model=ApprovalRead)
async def decide_approval(approval_id: UUID, body: ApprovalDecision, request: Request, response: Response,
                          ctx: TenantContext = Depends(user_ctx("analyst"))) -> ApprovalRead:
    row = await get_state(request).approvals.decide(ctx, approval_id, body.approve, body.note,
                                                    request.headers.get("if-match"))
    response.headers["ETag"] = approval_etag(row)
    return ApprovalRead(**row)


@router.get("/v1/approvals/{approval_id}", response_model=AgentApprovalRead)
async def agent_poll(approval_id: UUID, request: Request, ctx: TenantContext = Depends(agent_ctx)) -> AgentApprovalRead:
    row = await get_state(request).approvals.get(ctx.tenant_id, approval_id, agent_slug=ctx.agent_slug)
    decision = {"approved": "allow", "pending": "ask"}.get(row["status"], "block")
    return AgentApprovalRead(id=row["id"], status=row["status"], decision=decision,
                             expires_at=row["expires_at"], decided_at=row["decided_at"])
