"""Policy version persistence. Versions are immutable (a DB trigger rejects UPDATE/DELETE)."""

from __future__ import annotations

import json
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncConnection

from ..contracts.errors import ApiError
from ..tenants.registry import is_unique_violation
from .loader import CompiledPolicy

_COLS = "pv.version, pv.created_at, pv.created_by, encode(pv.sha256, 'hex') as sha256"


async def create_version(conn: AsyncConnection, tenant_id: UUID, agent_id: UUID, yaml_text: str,
                         policy: CompiledPolicy, created_by: UUID, requested: int | None) -> dict[str, Any]:
    nxt = int((await conn.execute(text("select coalesce(max(version), 0) + 1 from policy_versions where agent_id = :a"),
                                  {"a": agent_id})).scalar_one())
    if requested is not None and requested != nxt:
        raise ApiError("conflict", f"Version {requested} cannot be created: the next version is {nxt} "
                                   "(policy versions are immutable and numbered in order)")
    try:
        row = (await conn.execute(text(
            "insert into policy_versions (tenant_id, agent_id, version, yaml, parsed, sha256, created_by) "
            "values (:t, :a, :v, :y, cast(:p as jsonb), :h, :u) returning version, created_at, created_by, "
            "encode(sha256, 'hex') as sha256"),
            {"t": tenant_id, "a": agent_id, "v": nxt, "y": yaml_text,
             "p": json.dumps(policy.doc.model_dump(mode="json")), "h": policy.sha256, "u": created_by})).mappings().one()
    except IntegrityError as exc:
        if is_unique_violation(exc):
            raise ApiError("conflict", "Another version was created at the same time; retry") from exc
        raise
    return dict(row)


async def list_versions(conn: AsyncConnection, agent_id: UUID, active: int | None) -> list[dict[str, Any]]:
    rows = (await conn.execute(text(f"select {_COLS} from policy_versions pv where pv.agent_id = :a "
                                    "order by pv.version desc"), {"a": agent_id})).mappings().all()
    return [{**dict(r), "active": r["version"] == active} for r in rows]


async def get_version(conn: AsyncConnection, agent_id: UUID, version: int) -> dict[str, Any]:
    row = (await conn.execute(text(f"select {_COLS}, pv.yaml, pv.parsed from policy_versions pv "
                                   "where pv.agent_id = :a and pv.version = :v"),
                              {"a": agent_id, "v": version})).mappings().first()
    if row is None:
        raise ApiError("not_found", f"Policy version {version} not found")
    return dict(row)


async def activate(conn: AsyncConnection, slug: str, version: int, expected_updated_at: Any) -> None:
    res = await conn.execute(text("update agents set active_policy_version = :v where slug = :s and updated_at = :ts"),
                             {"v": version, "s": slug, "ts": expected_updated_at})
    if res.rowcount == 0:
        raise ApiError("precondition_failed", "The agent changed since you loaded it; reload and retry")
