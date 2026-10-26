from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request

from ...contracts.admin import Page, UserCreate, UserRead, UserUpdate
from ...db.tenant_tx import tenant_tx
from ...tenants import registry
from ...tenants.auth import user_ctx
from ...tenants.context import TenantContext
from ...tenants.passwords import hash_password
from ..state import get_state

router = APIRouter(prefix="/v1/admin/users", tags=["users"])


@router.get("", response_model=Page[UserRead])
async def list_users(request: Request, limit: int = Query(50, ge=1, le=200), cursor: str | None = None,
                     ctx: TenantContext = Depends(user_ctx("admin"))) -> Page[UserRead]:
    async with tenant_tx(get_state(request).engine, ctx.tenant_id) as conn:
        rows, nxt = await registry.list_users(conn, limit, cursor)
    return Page[UserRead](items=[UserRead(**r) for r in rows], next_cursor=nxt)


@router.post("", status_code=201, response_model=UserRead)
async def create_user(body: UserCreate, request: Request, ctx: TenantContext = Depends(user_ctx("admin"))) -> UserRead:
    async with tenant_tx(get_state(request).engine, ctx.tenant_id) as conn:
        row = await registry.create_user(conn, ctx.tenant_id, str(body.email).lower(),
                                         hash_password(body.password), body.role)
    return UserRead(**row)


@router.patch("/{user_id}", response_model=UserRead)
async def update_user(user_id: UUID, body: UserUpdate, request: Request,
                      ctx: TenantContext = Depends(user_ctx("admin"))) -> UserRead:
    async with tenant_tx(get_state(request).engine, ctx.tenant_id) as conn:
        row = await registry.update_user(
            conn, user_id, role=body.role, disabled=body.disabled,
            password_hash=hash_password(body.password) if body.password else None)
    return UserRead(**row)
