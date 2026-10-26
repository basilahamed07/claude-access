"""MCP server registry: persistence, scanning, approval and drift. Every query runs inside the tenant's RLS transaction."""

from __future__ import annotations

import json
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncConnection

from ..contracts.errors import ApiError
from ..tenants.registry import is_unique_violation

_COLS = ("id, name, owner, purpose, url, pinned_version, verdict, declared_capabilities, allowed_tools, encode(fingerprint, 'hex') as fingerprint, "
         "encode(approved_fingerprint, 'hex') as approved_fingerprint, coalesce(jsonb_array_length(tools), 0) as tool_count, "
         "(auth_ciphertext is not null) as has_auth, scanned_at, created_at, updated_at")


async def create(conn: AsyncConnection, tenant_id: UUID, data: dict[str, Any], auth_cipher: bytes | None) -> dict[str, Any]:
    try:
        row = (await conn.execute(text(
            "insert into mcp_servers (tenant_id, name, ref, url, owner, purpose, pinned_version, declared_capabilities, auth_ciphertext) "
            "values (:t, :name, :ref, :url, :owner, :purpose, :ver, :caps, :auth) returning id"),
            {"t": tenant_id, "name": data["name"], "ref": (data.get("url") or "manifest")[:500], "url": data.get("url"), "owner": data["owner"],
             "purpose": data["purpose"], "ver": data["pinned_version"], "caps": list(data["declared_capabilities"]), "auth": auth_cipher})).mappings().one()
    except IntegrityError as exc:
        if is_unique_violation(exc):
            raise ApiError("conflict", f"An MCP server named '{data['name']}' already exists") from exc
        raise
    return await get(conn, row["id"])


async def get(conn: AsyncConnection, server_id: UUID) -> dict[str, Any]:
    row = (await conn.execute(text(f"select {_COLS} from mcp_servers where id = :i"), {"i": server_id})).mappings().first()
    if row is None:
        raise ApiError("not_found", "MCP server not found")
    return dict(row)


async def get_detail(conn: AsyncConnection, server_id: UUID) -> dict[str, Any]:
    row = (await conn.execute(text(f"select {_COLS}, coalesce(tools, '[]'::jsonb) as tools, report from mcp_servers where id = :i"), {"i": server_id})).mappings().first()
    if row is None:
        raise ApiError("not_found", "MCP server not found")
    return dict(row)


async def secret(conn: AsyncConnection, server_id: UUID) -> dict[str, Any]:
    row = (await conn.execute(text("select id, name, url, auth_ciphertext, declared_capabilities from mcp_servers where id = :i"), {"i": server_id})).mappings().first()
    if row is None:
        raise ApiError("not_found", "MCP server not found")
    return dict(row)


async def list_all(conn: AsyncConnection) -> list[dict[str, Any]]:
    return [dict(r) for r in (await conn.execute(text(f"select {_COLS} from mcp_servers order by name"))).mappings().all()]


async def delete(conn: AsyncConnection, server_id: UUID) -> None:
    res = await conn.execute(text("delete from mcp_servers where id = :i"), {"i": server_id})
    if res.rowcount == 0:
        raise ApiError("not_found", "MCP server not found")


async def other_tools(conn: AsyncConnection, exclude: UUID | None) -> dict[str, list[str]]:
    """Tool names exposed by the tenant's other approved servers, for shadowing checks."""
    rows = (await conn.execute(text(
        "select name, report->'approved'->'tools' as tools from mcp_servers where verdict in ('approved','approved_with_limits') and id is distinct from :x"),
        {"x": exclude})).mappings().all()
    return {r["name"]: [t["name"] for t in (r["tools"] or [])] for r in rows}


async def save_scan(conn: AsyncConnection, server_id: UUID, tools: list[dict[str, Any]], fingerprint: bytes, report: dict[str, Any], *, verdict: str | None = None) -> None:
    sets = "tools = cast(:tools as jsonb), fingerprint = :fp, report = coalesce(report, '{}'::jsonb) || cast(:report as jsonb), scanned_at = now()"
    params: dict[str, Any] = {"i": server_id, "tools": json.dumps(tools), "fp": fingerprint, "report": json.dumps(report)}
    if verdict:
        sets += ", verdict = :v"
        params["v"] = verdict
    await conn.execute(text(f"update mcp_servers set {sets} where id = :i"), params)


async def set_verdict(conn: AsyncConnection, server_id: UUID, verdict: str, *, approved: dict[str, Any] | None = None, fingerprint: bytes | None = None,
                      allowed_tools: list[str] | None = None) -> None:
    if approved is not None:
        await conn.execute(text(
            "update mcp_servers set verdict = :v, approved_fingerprint = :fp, allowed_tools = :allowed, "
            "report = coalesce(report, '{}'::jsonb) || cast(:rep as jsonb) where id = :i"),
            {"v": verdict, "fp": fingerprint, "allowed": allowed_tools, "rep": json.dumps({"approved": approved}), "i": server_id})
    else:
        await conn.execute(text("update mcp_servers set verdict = :v where id = :i"), {"v": verdict, "i": server_id})


async def usable_servers(conn: AsyncConnection) -> list[dict[str, Any]]:
    """Servers an agent may reach through the proxy: approved, with the tool snapshot a person signed off."""
    rows = (await conn.execute(text(
        "select id, name, url, auth_ciphertext, approved_fingerprint, allowed_tools, report->'approved'->'tools' as tools from mcp_servers "
        "where verdict in ('approved','approved_with_limits') order by name"))).mappings().all()
    return [dict(r) for r in rows]
