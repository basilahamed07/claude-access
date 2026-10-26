import pytest
from sqlalchemy import text

from agentshield.db.tenant_tx import system_tx, tenant_tx

pytestmark = [pytest.mark.integration, pytest.mark.security]

TENANT_TABLES = [
    "users", "user_tokens", "upstreams", "agents", "agent_keys", "policy_versions", "sessions",
    "approvals", "budget_counters", "incidents", "scan_rule_sets", "mcp_servers", "ai_tools_seen",
    "audit_events", "audit_payloads", "audit_chain_heads",
]


@pytest.mark.parametrize("table", TENANT_TABLES)
async def test_rls_hides_other_tenant_rows(app_engine, two_tenants, table):
    a, b = two_tenants
    async with tenant_tx(app_engine, a["tenant_id"]) as conn:
        mine = (await conn.execute(text(f"select count(*) from {table} where tenant_id = :t"),
                                   {"t": a["tenant_id"]})).scalar_one()
        theirs = (await conn.execute(text(f"select count(*) from {table} where tenant_id = :t"),
                                     {"t": b["tenant_id"]})).scalar_one()
    assert mine >= 1
    assert theirs == 0


async def test_tenants_table_is_isolated(app_engine, two_tenants):
    a, b = two_tenants
    async with tenant_tx(app_engine, a["tenant_id"]) as conn:
        ids = {r[0] for r in (await conn.execute(text("select id from tenants"))).all()}
    assert ids == {a["tenant_id"]}


@pytest.mark.parametrize("table", TENANT_TABLES + ["tenants"])
async def test_missing_tenant_setting_returns_zero_rows(app_engine, two_tenants, table):
    async with system_tx(app_engine) as conn:
        n = (await conn.execute(text(f"select count(*) from {table}"))).scalar_one()
    assert n == 0


async def test_rls_rejects_insert_for_other_tenant(app_engine, two_tenants):
    a, b = two_tenants
    from sqlalchemy.exc import DBAPIError
    with pytest.raises(DBAPIError):
        async with tenant_tx(app_engine, a["tenant_id"]) as conn:
            await conn.execute(
                text("insert into agents (tenant_id, slug, name, owner, risk_tier) values (:t,'evil','e','o','low')"),
                {"t": b["tenant_id"]})


async def test_rls_blocks_cross_tenant_update(app_engine, two_tenants):
    a, b = two_tenants
    async with tenant_tx(app_engine, a["tenant_id"]) as conn:
        res = await conn.execute(text("update agents set name='hacked' where tenant_id = :t"),
                                 {"t": b["tenant_id"]})
    assert res.rowcount == 0


async def test_scan_rule_sets_platform_defaults_readable_but_not_writable(app_engine, owner_conn, two_tenants):
    a, _ = two_tenants
    await owner_conn.execute("delete from scan_rule_sets where tenant_id is null")
    await owner_conn.execute("insert into scan_rule_sets (tenant_id, version, yaml, sha256) values (null, 1, 'p: 1', '\\x00')")
    async with tenant_tx(app_engine, a["tenant_id"]) as conn:
        n = (await conn.execute(text("select count(*) from scan_rule_sets where tenant_id is null"))).scalar_one()
        assert n == 1
    from sqlalchemy.exc import DBAPIError
    with pytest.raises(DBAPIError):
        async with tenant_tx(app_engine, a["tenant_id"]) as conn:
            await conn.execute(text("insert into scan_rule_sets (tenant_id, version, yaml, sha256) values (null, 9, 'x', '\\x00')"))


async def test_app_role_cannot_update_or_delete_audit_events(app_engine, two_tenants):
    a, _ = two_tenants
    from sqlalchemy.exc import DBAPIError
    for stmt in ("update audit_events set summary='x'", "delete from audit_events"):
        with pytest.raises(DBAPIError):
            async with tenant_tx(app_engine, a["tenant_id"]) as conn:
                await conn.execute(text(stmt))


async def test_app_role_cannot_insert_audit_events(app_engine, two_tenants):
    a, _ = two_tenants
    from sqlalchemy.exc import DBAPIError
    with pytest.raises(DBAPIError):
        async with tenant_tx(app_engine, a["tenant_id"]) as conn:
            await conn.execute(text(
                "insert into audit_events (tenant_id, seq, ts, id, trace_id, module, type, severity, summary, "
                "payload_sha256, prev_hash, hash) values (:t, 99, now(), 'e', 't', 'gateway', 'x', 'info', 's', '\\x00', '\\x00', '\\x00')"),
                {"t": a["tenant_id"]})


async def test_worker_can_insert_but_not_update_or_delete_audit_events(worker_engine, two_tenants):
    a, _ = two_tenants
    from sqlalchemy.exc import DBAPIError
    async with tenant_tx(worker_engine, a["tenant_id"]) as conn:
        await conn.execute(text(
            "insert into audit_events (tenant_id, seq, ts, id, trace_id, module, type, severity, summary, "
            "payload_sha256, prev_hash, hash) values (:t, 2, now(), 'e2', 't', 'gateway', 'x', 'info', 's', '\\x00', '\\x00', '\\x00')"),
            {"t": a["tenant_id"]})
    for stmt in ("update audit_events set summary='x'", "delete from audit_events"):
        with pytest.raises(DBAPIError):
            async with tenant_tx(worker_engine, a["tenant_id"]) as conn:
                await conn.execute(text(stmt))


async def test_policy_versions_are_immutable(owner_conn, two_tenants):
    a, _ = two_tenants
    import asyncpg
    with pytest.raises(asyncpg.PostgresError):
        await owner_conn.execute("update policy_versions set yaml = 'changed' where tenant_id = $1", a["tenant_id"])
    with pytest.raises(asyncpg.PostgresError):
        await owner_conn.execute("delete from policy_versions where tenant_id = $1", a["tenant_id"])


async def test_audit_events_trigger_blocks_even_superuser(owner_conn, two_tenants):
    a, _ = two_tenants
    import asyncpg
    with pytest.raises(asyncpg.PostgresError):
        await owner_conn.execute("update audit_events set summary='x' where tenant_id = $1", a["tenant_id"])
