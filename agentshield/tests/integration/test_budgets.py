import asyncio
from datetime import UTC, datetime, timedelta

import pytest

from agentshield.contracts.policy import Budgets
from agentshield.policy.budgets import BudgetTracker, BudgetUnavailable, mirror_to_postgres, price_micro_usd

pytestmark = pytest.mark.integration
T = "00000000-0000-0000-0000-0000000000aa"


@pytest.fixture
def tracker(redis_client):
    return BudgetTracker(redis_client, default_rpm=600)


async def test_calls_limit_trips_and_reports_retry_until_midnight(tracker):
    b = Budgets(max_calls_per_day=3)
    for _ in range(3):
        assert (await tracker.admit(T, "bot", b)).ok
    s = await tracker.admit(T, "bot", b)
    assert not s.ok and s.exceeded == "calls" and s.retry_after > 0 and "call budget" in s.message()
    assert (await tracker.usage(T, "bot"))["calls"] == 3                    # a refused call is not counted


async def test_cost_and_token_limits_trip_after_recording(tracker):
    b = Budgets(max_cost_usd_per_day=1.0, max_tokens_per_day=1000)
    assert (await tracker.admit(T, "bot", b)).ok
    await tracker.record(T, "bot", 400, 600_000)
    assert (await tracker.admit(T, "bot", b)).ok
    await tracker.record(T, "bot", 700, 450_000)                           # 1100 tokens, $1.05
    s = await tracker.admit(T, "bot", b)
    assert not s.ok and s.exceeded == "tokens"
    b2 = Budgets(max_cost_usd_per_day=1.0)
    s = await tracker.admit(T, "bot", b2)
    assert not s.ok and s.exceeded == "cost"


async def test_no_limits_means_unlimited_daily(tracker):
    for _ in range(50):
        assert (await tracker.admit(T, "bot", Budgets())).ok


async def test_rpm_sliding_window(tracker):
    b = Budgets(max_rpm=3)
    t0 = 1_700_000_000_000
    for i in range(3):
        s = await tracker.admit(T, "bot", b, now_ms=t0 + i * 1000)
        assert s.ok and s.rpm_remaining == 2 - i and s.rpm_limit == 3
    s = await tracker.admit(T, "bot", b, now_ms=t0 + 5_000)
    assert not s.ok and s.exceeded == "rpm" and s.retry_after == 55         # oldest entry leaves the window in 55 s
    assert (await tracker.admit(T, "bot", b, now_ms=t0 + 60_500)).ok         # the first request has aged out
    assert not (await tracker.admit(T, "bot", b, now_ms=t0 + 60_600)).ok     # but 2 + 1 new are still inside


async def test_default_rpm_applies_when_policy_sets_none(redis_client):
    t = BudgetTracker(redis_client, default_rpm=2)
    assert (await t.admit(T, "bot", Budgets())).ok and (await t.admit(T, "bot", Budgets())).ok
    assert (await t.admit(T, "bot", Budgets())).exceeded == "rpm"


async def test_counters_reset_at_utc_midnight(tracker):
    b = Budgets(max_calls_per_day=1)
    today = datetime(2026, 10, 26, 23, 59, 59, tzinfo=UTC)
    assert (await tracker.admit(T, "bot", b, now=today)).ok
    assert not (await tracker.admit(T, "bot", b, now=today)).ok
    tomorrow = today + timedelta(seconds=2)
    assert (await tracker.admit(T, "bot", b, now=tomorrow)).ok


async def test_agents_and_tenants_are_isolated(tracker):
    b = Budgets(max_calls_per_day=1, max_rpm=1)
    assert (await tracker.admit(T, "a", b)).ok
    assert (await tracker.admit(T, "b", b)).ok
    assert (await tracker.admit("00000000-0000-0000-0000-0000000000bb", "a", b)).ok


async def test_concurrent_admissions_never_exceed_the_limit(tracker):
    b = Budgets(max_calls_per_day=10)
    results = await asyncio.gather(*[tracker.admit(T, "bot", b) for _ in range(60)])
    assert sum(r.ok for r in results) == 10 and (await tracker.usage(T, "bot"))["calls"] == 10


async def test_concurrent_records_sum_exactly(tracker):
    await asyncio.gather(*[tracker.record(T, "bot", 3, 7) for _ in range(100)])
    u = await tracker.usage(T, "bot")
    assert u["tokens"] == 300 and u["cost"] == 700


async def test_redis_failure_raises_budget_unavailable():
    class Dead:
        def register_script(self, _):
            async def call(**kw):
                raise ConnectionError("down")
            return call

        async def hgetall(self, *a):
            raise ConnectionError("down")

    t = BudgetTracker(Dead())
    with pytest.raises(BudgetUnavailable):
        await t.admit(T, "bot", Budgets())
    with pytest.raises(BudgetUnavailable):
        await t.record(T, "bot", 1, 1)
    with pytest.raises(BudgetUnavailable):
        await t.usage(T, "bot")


async def test_zero_usage_is_not_written(tracker, redis_client):
    await tracker.record(T, "bot", 0, 0)
    assert await redis_client.keys("budget:*") == []


def test_price_micro_usd():
    entry = {"input_micro_usd_per_mtok": 400_000, "output_micro_usd_per_mtok": 1_600_000}
    assert price_micro_usd(entry, 1_000_000, 500_000) == (400_000 + 800_000, False)
    assert price_micro_usd(entry, 1000, 1000) == (2000, False)        # 400 + 1600 micro-USD
    assert price_micro_usd(None, 100, 50) == (0, True)
    assert price_micro_usd({"model": "x"}, 100, 50) == (0, True)
    assert price_micro_usd(None, 0, 0) == (0, False)


async def test_mirror_to_postgres_upserts_counters(api, tracker, redis_client, app_engine, owner_conn):
    acct = await api.signup()
    await acct.make_agent("mirror-me")
    await tracker.admit(acct.tenant_id, "mirror-me", Budgets())
    await tracker.record(acct.tenant_id, "mirror-me", 123, 456)
    await tracker.admit("00000000-0000-0000-0000-0000000000cc", "ghost-agent", Budgets())   # unknown tenant/agent: ignored
    assert await mirror_to_postgres(app_engine, redis_client) == 1
    assert await mirror_to_postgres(app_engine, redis_client) == 1              # idempotent upsert
    row = await owner_conn.fetchrow("select tokens, cost_micro_usd, calls from budget_counters where tenant_id = $1::uuid",
                                    acct.tenant_id)
    assert (row["tokens"], row["cost_micro_usd"], row["calls"]) == (123, 456, 1)
