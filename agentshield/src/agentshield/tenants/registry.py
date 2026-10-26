"""SQL repositories for tenants, users, agents, keys and upstreams.

Every function takes a connection from `tenant_tx` (RLS already scoped to the caller's tenant);
none accepts a tenant id from the request. Cross-tenant ids simply find no row -> 404.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncConnection

from ..contracts.errors import ApiError
from .keys import IssuedSecret

Row = dict[str, Any]


def is_unique_violation(exc: IntegrityError) -> bool:
    return getattr(exc.orig, "sqlstate", None) == "23505" or "unique" in str(exc.orig).lower()


def encode_cursor(value: str) -> str:
    return base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")


def decode_cursor(cursor: str | None) -> UUID | None:
    """Cursors are opaque base64 of a row id (ids are time-ordered uuidv7, so id order == time order)."""
    if not cursor:
        return None
    try:
        return UUID(base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)).decode())
    except (binascii.Error, UnicodeDecodeError, ValueError) as exc:
        raise ApiError("validation_failed", "Invalid cursor") from exc


def page(rows: list[Row], limit: int, key: str = "id") -> tuple[list[Row], str | None]:
    if len(rows) > limit:
        rows = rows[:limit]
        return rows, encode_cursor(str(rows[-1][key]))
    return rows, None


def etag(*parts: object) -> str:
    return 'W/"' + hashlib.sha1("|".join(str(p) for p in parts).encode(), usedforsecurity=False).hexdigest()[:16] + '"'


def as_dict(row: Any) -> Row:
    return dict(row)


# ── tenants / users ─────────────────────────────────────────────────────────────────────────────
async def get_tenant(conn: AsyncConnection) -> Row:
    row = (await conn.execute(text("select id, name, slug, settings, created_at from tenants"))).mappings().first()
    if row is None:
        raise ApiError("not_found", "Tenant not found")
    return as_dict(row)


async def update_tenant_settings(conn: AsyncConnection, settings: dict[str, Any]) -> None:
    await conn.execute(text("update tenants set settings = cast(:s as jsonb)"), {"s": json.dumps(settings)})


_USER_COLS = "id, email, role, created_at, disabled_at"


async def list_users(conn: AsyncConnection, limit: int, cursor: str | None) -> tuple[list[Row], str | None]:
    after = decode_cursor(cursor)
    rows = (await conn.execute(
        text(f"select {_USER_COLS} from users where (cast(:c as uuid) is null or id < cast(:c as uuid)) "
             "order by id desc limit :n"), {"c": after, "n": limit + 1})).mappings().all()
    return page([as_dict(r) for r in rows], limit)


async def create_user(conn: AsyncConnection, tenant_id: UUID, email: str, password_hash: str, role: str) -> Row:
    try:
        row = (await conn.execute(
            text(f"insert into users (tenant_id, email, password_hash, role) values (:t, :e, :p, :r) "
                 f"returning {_USER_COLS}"), {"t": tenant_id, "e": email, "p": password_hash, "r": role})
        ).mappings().one()
    except IntegrityError as exc:
        if is_unique_violation(exc):
            raise ApiError("conflict", "A user with this e-mail already exists") from exc
        raise
    return as_dict(row)


async def get_user(conn: AsyncConnection, user_id: UUID) -> Row:
    row = (await conn.execute(text(f"select {_USER_COLS} from users where id = :u"),
                              {"u": user_id})).mappings().first()
    if row is None:
        raise ApiError("not_found", "User not found")
    return as_dict(row)


async def active_admin_count(conn: AsyncConnection) -> int:
    return int((await conn.execute(text(
        "select count(*) from users where role = 'admin' and disabled_at is null"))).scalar_one())


async def update_user(conn: AsyncConnection, user_id: UUID, *, role: str | None, disabled: bool | None,
                      password_hash: str | None) -> Row:
    current = await get_user(conn, user_id)
    losing_admin = current["role"] == "admin" and current["disabled_at"] is None and (
        (role is not None and role != "admin") or disabled is True)
    if losing_admin and await active_admin_count(conn) <= 1:
        raise ApiError("conflict", "Cannot remove the last active admin")
    sets: list[str] = []
    params: dict[str, Any] = {"u": user_id}
    if role is not None:
        sets.append("role = :role")
        params["role"] = role
    if disabled is not None:
        sets.append("disabled_at = case when :dis then now() else null end")
        params["dis"] = disabled
    if password_hash is not None:
        sets.append("password_hash = :ph, failed_logins = 0, locked_until = null")
        params["ph"] = password_hash
    if sets:
        await conn.execute(text(f"update users set {', '.join(sets)} where id = :u"), params)
    return await get_user(conn, user_id)


# ── upstreams ───────────────────────────────────────────────────────────────────────────────────
_UP_COLS = "id, name, kind, base_url, (key_ciphertext is not null) as has_key, model_map, judge_model, created_at"


async def create_upstream(conn: AsyncConnection, tenant_id: UUID, *, name: str, kind: str, base_url: str,
                          key_ciphertext: bytes | None, model_map: dict[str, Any], judge_model: str | None) -> Row:
    try:
        row = (await conn.execute(text(
            f"insert into upstreams (tenant_id, name, kind, base_url, key_ciphertext, model_map, judge_model) "
            f"values (:t, :n, :k, :u, :c, cast(:m as jsonb), :j) returning {_UP_COLS}"),
            {"t": tenant_id, "n": name, "k": kind, "u": base_url, "c": key_ciphertext,
             "m": json.dumps(model_map), "j": judge_model})).mappings().one()
    except IntegrityError as exc:
        if is_unique_violation(exc):
            raise ApiError("conflict", "An upstream with this name already exists") from exc
        raise
    return as_dict(row)


async def list_upstreams(conn: AsyncConnection) -> list[Row]:
    rows = (await conn.execute(text(f"select {_UP_COLS} from upstreams order by name"))).mappings().all()
    return [as_dict(r) for r in rows]


async def get_upstream(conn: AsyncConnection, upstream_id: UUID) -> Row:
    row = (await conn.execute(text(f"select {_UP_COLS} from upstreams where id = :u"),
                              {"u": upstream_id})).mappings().first()
    if row is None:
        raise ApiError("not_found", "Upstream not found")
    return as_dict(row)


async def get_upstream_secret(conn: AsyncConnection, upstream_id: UUID) -> Row:
    """Includes the ciphertext: only for the proxy and the connection test, never for API output."""
    row = (await conn.execute(text(
        "select id, name, kind, base_url, key_ciphertext, model_map, judge_model from upstreams where id = :u"),
        {"u": upstream_id})).mappings().first()
    if row is None:
        raise ApiError("not_found", "Upstream not found")
    return as_dict(row)


async def update_upstream(conn: AsyncConnection, upstream_id: UUID, fields: dict[str, Any]) -> Row:
    allowed = {"name": "name", "base_url": "base_url", "key_ciphertext": "key_ciphertext",
               "judge_model": "judge_model", "model_map": "model_map"}
    sets: list[str] = []
    params: dict[str, Any] = {"u": upstream_id}
    for k, v in fields.items():
        col = allowed[k]
        if k == "model_map":
            sets.append("model_map = cast(:model_map as jsonb)")
            params["model_map"] = json.dumps(v)
        else:
            sets.append(f"{col} = :{k}")
            params[k] = v
    if sets:
        try:
            res = await conn.execute(text(f"update upstreams set {', '.join(sets)} where id = :u"), params)
        except IntegrityError as exc:
            if is_unique_violation(exc):
                raise ApiError("conflict", "An upstream with this name already exists") from exc
            raise
        if res.rowcount == 0:
            raise ApiError("not_found", "Upstream not found")
    return await get_upstream(conn, upstream_id)


async def delete_upstream(conn: AsyncConnection, upstream_id: UUID) -> None:
    used = (await conn.execute(text("select count(*) from agents where upstream_id = :u"),
                               {"u": upstream_id})).scalar_one()
    if used:
        raise ApiError("conflict", f"Upstream is used by {used} agent(s)")
    res = await conn.execute(text("delete from upstreams where id = :u"), {"u": upstream_id})
    if res.rowcount == 0:
        raise ApiError("not_found", "Upstream not found")


async def require_upstream(conn: AsyncConnection, upstream_id: UUID) -> None:
    """FK checks bypass RLS, so a foreign tenant's upstream id must be rejected explicitly."""
    ok = (await conn.execute(text("select 1 from upstreams where id = :u"), {"u": upstream_id})).first()
    if ok is None:
        raise ApiError("validation_failed", "upstream_id does not exist",
                       errors=[{"path": "upstream_id", "message": "unknown upstream"}])


# ── agents ──────────────────────────────────────────────────────────────────────────────────────
_AGENT_COLS = (
    "a.id, a.slug, a.name, a.owner, a.purpose, a.risk_tier, a.mode, a.key_mode, a.upstream_id, "
    "a.active_policy_version, a.status, a.last_seen_at, a.created_at, a.updated_at, "
    "(select count(*) from agent_keys k where k.agent_id = a.id and k.revoked_at is null "
    " and (k.expires_at is null or k.expires_at > now())) as key_count"
)


async def create_agent(conn: AsyncConnection, tenant_id: UUID, data: dict[str, Any]) -> Row:
    if data.get("upstream_id"):
        await require_upstream(conn, data["upstream_id"])
    try:
        agent_id = (await conn.execute(text(
            "insert into agents (tenant_id, slug, name, owner, purpose, risk_tier, mode, key_mode, upstream_id) "
            "values (:t, :slug, :name, :owner, :purpose, :risk_tier, :mode, :key_mode, :upstream_id) returning id"),
            {"t": tenant_id, **data})).scalar_one()
    except IntegrityError as exc:
        if is_unique_violation(exc):
            raise ApiError("conflict", f"Agent '{data['slug']}' already exists") from exc
        raise
    return await get_agent_by_id(conn, agent_id)


async def get_agent_by_id(conn: AsyncConnection, agent_id: UUID) -> Row:
    row = (await conn.execute(text(f"select {_AGENT_COLS} from agents a where a.id = :i"),
                              {"i": agent_id})).mappings().first()
    if row is None:
        raise ApiError("not_found", "Agent not found")
    return as_dict(row)


async def get_agent(conn: AsyncConnection, slug: str) -> Row:
    row = (await conn.execute(text(f"select {_AGENT_COLS} from agents a where a.slug = :s"),
                              {"s": slug})).mappings().first()
    if row is None:
        raise ApiError("not_found", f"Agent '{slug}' not found")
    return as_dict(row)


async def list_agents(conn: AsyncConnection, limit: int, cursor: str | None) -> tuple[list[Row], str | None]:
    after = decode_cursor(cursor)
    rows = (await conn.execute(text(
        f"select {_AGENT_COLS} from agents a where (cast(:c as uuid) is null or a.id < cast(:c as uuid)) "
        "order by a.id desc limit :n"), {"c": after, "n": limit + 1})).mappings().all()
    return page([as_dict(r) for r in rows], limit)


def agent_etag(row: Row) -> str:
    return etag(row["id"], row["updated_at"].isoformat())


async def update_agent(conn: AsyncConnection, slug: str, fields: dict[str, Any], expected_updated_at: datetime) -> Row:
    if fields.get("upstream_id"):
        await require_upstream(conn, fields["upstream_id"])
    cols = {"name", "owner", "purpose", "risk_tier", "mode", "key_mode", "upstream_id", "status"}
    sets = [f"{k} = :{k}" for k in fields if k in cols]
    if sets:
        res = await conn.execute(
            text(f"update agents set {', '.join(sets)} where slug = :slug and updated_at = :ts"),
            {**fields, "slug": slug, "ts": expected_updated_at})
        if res.rowcount == 0:
            raise ApiError("precondition_failed", "The agent changed since you loaded it")
    return await get_agent(conn, slug)


# ── agent keys ──────────────────────────────────────────────────────────────────────────────────
async def insert_agent_key(conn: AsyncConnection, tenant_id: UUID, agent_id: UUID, issued: IssuedSecret,
                           expires_at: datetime | None = None) -> Row:
    row = (await conn.execute(text(
        "insert into agent_keys (tenant_id, agent_id, prefix, key_hash, expires_at) "
        "values (:t, :a, :p, :h, :e) returning id, prefix, created_at, expires_at"),
        {"t": tenant_id, "a": agent_id, "p": issued.prefix, "h": issued.hash, "e": expires_at})).mappings().one()
    return as_dict(row)


async def list_agent_keys(conn: AsyncConnection, agent_id: UUID) -> list[Row]:
    rows = (await conn.execute(text(
        "select id, prefix, created_at, expires_at, revoked_at from agent_keys where agent_id = :a "
        "order by id desc"), {"a": agent_id})).mappings().all()
    return [as_dict(r) for r in rows]


async def revoke_agent_key(conn: AsyncConnection, agent_id: UUID, key_id: UUID) -> Row:
    row = (await conn.execute(text(
        "update agent_keys set revoked_at = coalesce(revoked_at, now()) where id = :k and agent_id = :a "
        "returning id, prefix, created_at, expires_at, revoked_at"), {"k": key_id, "a": agent_id})).mappings().first()
    if row is None:
        raise ApiError("not_found", "Key not found")
    return as_dict(row)


async def expire_key_after(conn: AsyncConnection, agent_id: UUID, key_id: UUID, overlap_seconds: int) -> None:
    res = await conn.execute(text(
        "update agent_keys set expires_at = least(coalesce(expires_at, 'infinity'::timestamptz), "
        "now() + make_interval(secs => :s)) where id = :k and agent_id = :a and revoked_at is null"),
        {"s": overlap_seconds, "k": key_id, "a": agent_id})
    if res.rowcount == 0:
        raise ApiError("not_found", "Active key not found")
