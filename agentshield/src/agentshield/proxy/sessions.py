"""Session identity for proxy traffic (arch §7.2a): header first, else a hash of agent + first user message."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

SESSION_HEADER = "x-agentshield-session"
USER_HEADER = "x-agentshield-user"


@dataclass(frozen=True)
class SessionRef:
    id: UUID
    key: str
    user_request: str | None
    end_user: str | None
    risk_score: float = 0.0


def _text_of(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for block in content:
            if isinstance(block, dict) and block.get("type") in {"text", None} and isinstance(block.get("text"), str):
                parts.append(block["text"])
        return "\n".join(parts)
    return ""


def first_user_message(messages: list[Any]) -> str | None:
    for m in messages:
        if isinstance(m, dict) and m.get("role") == "user":
            t = _text_of(m.get("content")).strip()
            if t:
                return t[:20_000]
    return None


def session_key(headers: dict[str, str], agent_slug: str, user_request: str | None) -> str:
    explicit = headers.get(SESSION_HEADER, "").strip()
    if explicit:
        return explicit[:200]
    seed = f"{agent_slug}\x00{user_request or ''}"
    return "auto-" + hashlib.sha256(seed.encode()).hexdigest()[:32]


async def upsert_session(conn: AsyncConnection, tenant_id: UUID, agent_id: UUID, key: str,
                         user_request: str | None, end_user: str | None) -> SessionRef:
    row = (await conn.execute(text(
        "insert into sessions (tenant_id, agent_id, session_key, user_request, end_user) "
        "values (:t, :a, :k, :u, :e) "
        "on conflict (tenant_id, agent_id, session_key) do update set last_seen_at = now(), "
        "  end_user = coalesce(sessions.end_user, excluded.end_user), "
        "  user_request = coalesce(sessions.user_request, excluded.user_request) "
        "returning id, user_request, end_user, risk_score"),
        {"t": tenant_id, "a": agent_id, "k": key, "u": user_request, "e": end_user})).mappings().one()
    return SessionRef(id=row["id"], key=key, user_request=row["user_request"], end_user=row["end_user"],
                      risk_score=float(row["risk_score"]))
