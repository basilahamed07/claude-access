"""MCP server registry (design §2.3): register, scan, review, approve, watch for drift."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Request, Response

from ...contracts.admin import In
from ...contracts.errors import ApiError
from ...contracts.mcp import McpApprove, McpServerCreate, McpServerDetail, McpServerRead, ToolManifest
from ...db.tenant_tx import tenant_tx
from ...mcp import registry
from ...mcp.analysis import Tool
from ...tenants.auth import user_ctx
from ...tenants.context import TenantContext
from ...tenants.crypto import encrypt_secret
from ...tenants.urls import UnsafeURL, avalidate_outbound_url
from ..state import get_state

router = APIRouter(prefix="/v1/admin/mcp-servers", tags=["mcp"])


class RescanBody(In):
    tools: list[ToolManifest] | None = None
    source_files: dict[str, str] | None = None


def _manifest(tools: list[ToolManifest] | None) -> list[Tool] | None:
    return [Tool(t.name, t.description, t.inputSchema) for t in tools] if tools else None


@router.post("", status_code=201, response_model=McpServerDetail)
async def register(body: McpServerCreate, request: Request, ctx: TenantContext = Depends(user_ctx("analyst"))) -> McpServerDetail:
    state = get_state(request)
    if body.url:
        try:
            body.url = await avalidate_outbound_url(body.url, allow_private=state.settings.private_hosts)
        except UnsafeURL as exc:
            raise ApiError("validation_failed", f"url rejected: {exc}", errors=[{"path": "url", "message": str(exc)}]) from exc
    cipher = encrypt_secret(state.master_key, body.auth_token) if body.auth_token else None
    async with tenant_tx(state.engine, ctx.tenant_id) as conn:
        row = await registry.create(conn, ctx.tenant_id, body.model_dump(), cipher)
    detail = await state.mcp.scan(ctx, row["id"], manifest=_manifest(body.tools), source_files=body.source_files)
    return McpServerDetail(**detail)


@router.get("", response_model=list[McpServerRead])
async def list_servers(request: Request, ctx: TenantContext = Depends(user_ctx("viewer"))) -> list[McpServerRead]:
    async with tenant_tx(get_state(request).engine, ctx.tenant_id) as conn:
        return [McpServerRead(**r) for r in await registry.list_all(conn)]


@router.get("/{server_id}", response_model=McpServerDetail)
async def get_server(server_id: UUID, request: Request, ctx: TenantContext = Depends(user_ctx("viewer"))) -> McpServerDetail:
    async with tenant_tx(get_state(request).engine, ctx.tenant_id) as conn:
        return McpServerDetail(**await registry.get_detail(conn, server_id))


@router.post("/{server_id}/scan", response_model=McpServerDetail)
async def scan_again(server_id: UUID, body: RescanBody, request: Request, ctx: TenantContext = Depends(user_ctx("analyst"))) -> McpServerDetail:
    """A full scan of the server as it is now. A server that was approved and has changed is suspended until a person approves the new version."""
    return McpServerDetail(**await get_state(request).mcp.scan(ctx, server_id, manifest=_manifest(body.tools), source_files=body.source_files))


@router.post("/{server_id}/check")
async def check_for_drift(server_id: UUID, request: Request, ctx: TenantContext = Depends(user_ctx("analyst"))) -> dict[str, str]:
    """Compare the live tool list with the approved one. Drift suspends the server."""
    state = get_state(request)
    async with tenant_tx(state.engine, ctx.tenant_id) as conn:
        usable = [r for r in await registry.usable_servers(conn) if r["id"] == server_id]
        base = await registry.get(conn, server_id)
    if not usable:
        return {"status": "not_approved", "verdict": str(base["verdict"])}
    row = {**usable[0], "approved_fingerprint": usable[0]["approved_fingerprint"], "tools": usable[0]["tools"], "url": usable[0]["url"], "name": base["name"], "id": server_id}
    status = await state.mcp.check_drift(ctx, row)
    async with tenant_tx(state.engine, ctx.tenant_id) as conn:
        return {"status": status, "verdict": str((await registry.get(conn, server_id))["verdict"])}


@router.post("/{server_id}/approve", response_model=McpServerDetail)
async def approve(server_id: UUID, body: McpApprove, request: Request, ctx: TenantContext = Depends(user_ctx("admin"))) -> McpServerDetail:
    return McpServerDetail(**await get_state(request).mcp.approve(ctx, server_id, body.allowed_tools, body.acknowledge_findings))


@router.post("/{server_id}/reject", response_model=McpServerDetail)
async def reject(server_id: UUID, request: Request, ctx: TenantContext = Depends(user_ctx("admin"))) -> McpServerDetail:
    return McpServerDetail(**await get_state(request).mcp.reject(ctx, server_id))


@router.delete("/{server_id}", status_code=204)
async def delete_server(server_id: UUID, request: Request, ctx: TenantContext = Depends(user_ctx("admin"))) -> Response:
    async with tenant_tx(get_state(request).engine, ctx.tenant_id) as conn:
        await registry.delete(conn, server_id)
    return Response(status_code=204)
