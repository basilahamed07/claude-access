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


ACCUMULATE_LUA = """
local cur = tonumber(redis.call('GET', KEYS[1]) or '0')
local amount = tonumber(ARGV[1])
local new = 1 - (1 - cur) * (1 - amount)
if new > 1 then new = 1 end
redis.call('SET', KEYS[1], tostring(new), 'EX', ARGV[2])
return tostring(new)
"""


async def accumulate_risk(redis: Any, tenant_id: Any, session_id: Any, amount: float) -> float:
    """Atomically apply r' = 1 - (1 - r)(1 - amount); repeated weak signals add up, risk never falls (arch §2.2)."""
    amount = min(max(amount, 0.0), 1.0)
    raw = await redis.eval(ACCUMULATE_LUA, 1, risk_key(tenant_id, session_id), repr(amount), RISK_TTL)
    return float(raw.decode() if isinstance(raw, bytes) else raw)
