"""Per-session state kept in Redis: risk score (raised by the injection firewall) and human approvals."""

from __future__ import annotations

from typing import Any

RISK_TTL = 24 * 3600


def risk_key(tenant_id: Any, session_id: Any) -> str:
    return f"risk:{tenant_id}:{session_id}"


def allow_key(tenant_id: Any, session_id: Any, tool: str, args_hash: str) -> str:
    return f"allow:{tenant_id}:{session_id}:{tool}:{args_hash}"


async def get_risk(redis: Any, tenant_id: Any, session_id: Any, fallback: float = 0.0) -> float:
    raw = await redis.get(risk_key(tenant_id, session_id))
    return max(float(raw), fallback) if raw is not None else fallback


async def raise_risk(redis: Any, tenant_id: Any, session_id: Any, new_risk: float) -> float:
    """Risk only ever goes up within a session."""
    key = risk_key(tenant_id, session_id)
    current = await get_risk(redis, tenant_id, session_id)
    value = max(current, min(max(new_risk, 0.0), 1.0))
    await redis.set(key, repr(value), ex=RISK_TTL)
    return value


async def is_approved(redis: Any, tenant_id: Any, session_id: Any, tool: str, args_hash: str) -> bool:
    return bool(await redis.exists(allow_key(tenant_id, session_id, tool, args_hash)))


async def grant_allowance(redis: Any, tenant_id: Any, session_id: Any, tool: str, args_hash: str, ttl: int) -> None:
    await redis.set(allow_key(tenant_id, session_id, tool, args_hash), "1", ex=ttl)
