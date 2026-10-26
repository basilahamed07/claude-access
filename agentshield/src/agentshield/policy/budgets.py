"""Per-agent daily budgets (tokens, cost, calls) and a sliding-window request rate limit.

Admission is one atomic Lua script, so two concurrent requests can never both squeeze under a limit.
Usage (tokens, cost) is recorded after the provider answers. Redis trouble raises `BudgetUnavailable`;
the caller applies the fail rule (read tools may proceed, everything else is denied).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

from ..contracts.policy import Budgets

Exceeded = Literal["tokens", "cost", "calls", "rpm"]
BUDGET_TTL = 48 * 3600

ADMIT_LUA = """
local budget, rpm, rpm_seq = KEYS[1], KEYS[2], KEYS[3]
local now = tonumber(ARGV[1])
local rpm_limit, calls_limit = tonumber(ARGV[2]), tonumber(ARGV[3])
local tokens_limit, cost_limit, ttl = tonumber(ARGV[4]), tonumber(ARGV[5]), tonumber(ARGV[6])
local count_call = ARGV[7] == '1'
if tokens_limit > 0 and tonumber(redis.call('HGET', budget, 'tokens') or '0') >= tokens_limit then return {'tokens', 0, 0} end
if cost_limit > 0 and tonumber(redis.call('HGET', budget, 'cost') or '0') >= cost_limit then return {'cost', 0, 0} end
if calls_limit > 0 and tonumber(redis.call('HGET', budget, 'calls') or '0') >= calls_limit then return {'calls', 0, 0} end
local count = 0
if rpm_limit > 0 then
  redis.call('ZREMRANGEBYSCORE', rpm, 0, now - 60000)
  count = redis.call('ZCARD', rpm)
  if count >= rpm_limit then
    local oldest = redis.call('ZRANGE', rpm, 0, 0, 'WITHSCORES')
    local retry = 1
    if oldest[2] then retry = math.max(1, math.ceil((tonumber(oldest[2]) + 60000 - now) / 1000)) end
    return {'rpm', retry, 0}
  end
  redis.call('ZADD', rpm, now, now .. '-' .. redis.call('INCR', rpm_seq))
  redis.call('EXPIRE', rpm, 120)
  redis.call('EXPIRE', rpm_seq, 120)
end
if count_call then
  redis.call('HINCRBY', budget, 'calls', 1)
  redis.call('EXPIRE', budget, ttl)
end
return {'', 0, rpm_limit > 0 and (rpm_limit - count - 1) or -1}
"""

RECORD_LUA = """
redis.call('HINCRBY', KEYS[1], 'tokens', ARGV[1])
redis.call('HINCRBY', KEYS[1], 'cost', ARGV[2])
redis.call('EXPIRE', KEYS[1], ARGV[3])
return 1
"""


class BudgetUnavailable(Exception):
    pass


@dataclass
class BudgetStatus:
    ok: bool
    exceeded: Exceeded | None = None
    retry_after: int = 0
    rpm_limit: int = 0
    rpm_remaining: int = -1
    usage: dict[str, int] = field(default_factory=dict)

    def message(self) -> str:
        return {"tokens": "Daily token budget exhausted", "cost": "Daily cost budget exhausted",
                "calls": "Daily call budget exhausted", "rpm": "Request rate limit exceeded"}.get(self.exceeded or "", "")


def price_micro_usd(entry: dict[str, Any] | None, input_tokens: int, output_tokens: int) -> tuple[int, bool]:
    """(cost in micro-USD, price_missing). Prices are micro-USD per million tokens, set by the tenant."""
    if not entry:
        return 0, bool(input_tokens or output_tokens)
    pin, pout = int(entry.get("input_micro_usd_per_mtok", 0) or 0), int(entry.get("output_micro_usd_per_mtok", 0) or 0)
    if not pin and not pout:
        return 0, bool(input_tokens or output_tokens)
    return round((input_tokens * pin + output_tokens * pout) / 1_000_000), False


def _day(now: datetime | None = None) -> str:
    return (now or datetime.now(UTC)).strftime("%Y%m%d")


class BudgetTracker:
    def __init__(self, redis: Any, *, default_rpm: int = 600) -> None:
        self.redis = redis
        self.default_rpm = default_rpm
        self._admit = redis.register_script(ADMIT_LUA)
        self._record = redis.register_script(RECORD_LUA)

    @staticmethod
    def budget_key(tenant_id: Any, agent_slug: str, day: str) -> str:
        return f"budget:{tenant_id}:{agent_slug}:{day}"

    async def admit(self, tenant_id: Any, agent_slug: str, budgets: Budgets | None, *,
                    now: datetime | None = None, now_ms: int | None = None, scope: str = "",
                    count_call: bool = True, default_rpm: int | None = None) -> BudgetStatus:
        """Count one request against rpm and daily calls; refuse when any limit is already reached.

        `scope` separates the rate-limit window of another API (e.g. "check") from model requests;
        `count_call=False` rate-limits without consuming the daily call budget."""
        b = budgets or Budgets()
        now = now or datetime.now(UTC)
        ms = now_ms if now_ms is not None else int(now.timestamp() * 1000)
        rpm_limit = b.max_rpm or default_rpm or self.default_rpm
        cost_limit = round((b.max_cost_usd_per_day or 0) * 1_000_000)
        try:
            exceeded, retry, remaining = await self._admit(
                keys=[self.budget_key(tenant_id, agent_slug, _day(now)), f"rpm:{tenant_id}:{agent_slug}{scope}",
                      f"rpmseq:{tenant_id}:{agent_slug}{scope}"],
                args=[ms, rpm_limit, b.max_calls_per_day or 0, b.max_tokens_per_day or 0, cost_limit, BUDGET_TTL,
                      "1" if count_call else "0"])
        except Exception as exc:                                    # noqa: BLE001
            raise BudgetUnavailable(str(exc)) from exc
        ex = exceeded.decode() if isinstance(exceeded, bytes) else exceeded
        if ex:
            return BudgetStatus(False, ex, int(retry) or (_seconds_to_midnight(now) if ex != "rpm" else 1), rpm_limit)  # type: ignore[arg-type]
        return BudgetStatus(True, None, 0, rpm_limit, int(remaining))

    async def record(self, tenant_id: Any, agent_slug: str, tokens: int, cost_micro_usd: int, *,
                     now: datetime | None = None) -> None:
        if tokens <= 0 and cost_micro_usd <= 0:
            return
        try:
            await self._record(keys=[self.budget_key(tenant_id, agent_slug, _day(now))],
                               args=[max(tokens, 0), max(cost_micro_usd, 0), BUDGET_TTL])
        except Exception as exc:                                    # noqa: BLE001
            raise BudgetUnavailable(str(exc)) from exc

    async def usage(self, tenant_id: Any, agent_slug: str, *, now: datetime | None = None) -> dict[str, int]:
        try:
            raw = await self.redis.hgetall(self.budget_key(tenant_id, agent_slug, _day(now)))
        except Exception as exc:                                    # noqa: BLE001
            raise BudgetUnavailable(str(exc)) from exc
        return {(k.decode() if isinstance(k, bytes) else k): int(v) for k, v in raw.items()}


def _seconds_to_midnight(now: datetime) -> int:
    tomorrow = datetime(now.year, now.month, now.day, tzinfo=UTC).timestamp() + 86400
    return max(1, int(tomorrow - now.timestamp()))


async def mirror_to_postgres(engine: Any, redis: Any, *, days: int = 2) -> int:
    """Copy today's/yesterday's Redis counters into `budget_counters` for reporting. Returns rows written."""
    import re
    from datetime import timedelta

    from sqlalchemy import text

    from ..db.tenant_tx import tenant_tx

    wanted = {_day(datetime.now(UTC) - timedelta(days=d)) for d in range(days)}
    pattern = re.compile(r"^budget:([0-9a-f-]{36}):([a-z0-9-]+):(\d{8})$")
    written = 0
    async for raw in redis.scan_iter(match="budget:*", count=500):
        key = raw.decode() if isinstance(raw, bytes) else raw
        m = pattern.match(key)
        if not m or m.group(3) not in wanted:
            continue
        tenant_id, slug, day = m.groups()
        data = {(k.decode() if isinstance(k, bytes) else k): int(v) for k, v in (await redis.hgetall(key)).items()}
        async with tenant_tx(engine, tenant_id) as conn:
            res = await conn.execute(text(
                "insert into budget_counters (tenant_id, agent_id, day, tokens, cost_micro_usd, calls) "
                "select :t, a.id, :d, :tok, :cost, :calls from agents a where a.slug = :s "
                "on conflict (tenant_id, agent_id, day) do update set tokens = excluded.tokens, "
                "cost_micro_usd = excluded.cost_micro_usd, calls = excluded.calls"),
                {"t": tenant_id, "d": datetime.strptime(day, "%Y%m%d").date(), "tok": data.get("tokens", 0),
                 "cost": data.get("cost", 0), "calls": data.get("calls", 0), "s": slug})
            written += res.rowcount
    return written
