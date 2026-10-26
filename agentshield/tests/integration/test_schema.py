import asyncio

import pytest
from sqlalchemy import text

from agentshield.contracts.events import AUDIT_EVENT_COLUMNS
from agentshield.db.migrate import migrate
from agentshield.db.partitions import ensure_partitions
from agentshield.db.tenant_tx import system_tx

pytestmark = pytest.mark.integration

EXPECTED_TABLES = {
    "tenants", "users", "user_tokens", "upstreams", "agents", "agent_keys", "policy_versions",
    "sessions", "approvals", "budget_counters", "incidents", "scan_rule_sets", "mcp_servers",
    "ai_tools_seen", "audit_events", "audit_payloads", "audit_events_archive",
    "audit_payloads_archive", "audit_chain_heads",
}


async def test_migration_creates_all_tables(owner_conn):
    rows = await owner_conn.fetch(
        "select relname from pg_class c join pg_namespace n on n.oid=c.relnamespace "
        "where n.nspname='public' and c.relkind in ('r','p') and not c.relispartition")
    assert EXPECTED_TABLES <= {r["relname"] for r in rows}


async def test_migrate_is_idempotent(db_urls):
    assert await migrate(db_urls.owner) == []


async def test_every_tenant_table_has_forced_rls_and_tenant_policy(owner_conn):
    rows = await owner_conn.fetch(
        "select c.relname, c.relrowsecurity, c.relforcerowsecurity, "
        "(select count(*) from pg_policy p where p.polrelid = c.oid) as npol "
        "from pg_class c join pg_namespace n on n.oid=c.relnamespace "
        "where n.nspname='public' and c.relkind in ('r','p') and not c.relispartition "
        "and c.relname <> 'schema_migrations'")
    assert rows
    for r in rows:
        assert r["relrowsecurity"] and r["relforcerowsecurity"], r["relname"]
        assert r["npol"] >= 2, r["relname"]


async def test_every_table_except_tenants_has_tenant_id(owner_conn):
    rows = await owner_conn.fetch(
        "select c.relname from pg_class c join pg_namespace n on n.oid=c.relnamespace "
        "where n.nspname='public' and c.relkind in ('r','p') and not c.relispartition "
        "and c.relname not in ('tenants','schema_migrations') and not exists ("
        " select 1 from pg_attribute a where a.attrelid=c.oid and a.attname='tenant_id' and not a.attisdropped)")
    assert [r["relname"] for r in rows] == []


async def test_no_unindexed_foreign_keys(owner_conn):
    """Every FK column leads an index, or is the second column behind tenant_id (db spec §B.1)."""
    rows = await owner_conn.fetch("""
        select conrelid::regclass::text as table_name, a.attname as fk_column
        from pg_constraint c
        join pg_attribute a on a.attrelid = c.conrelid and a.attnum = any(c.conkey)
        where c.contype = 'f'
          and not exists (
            select 1 from pg_index i
            where i.indrelid = c.conrelid
              and ((i.indkey::int2[])[0] = a.attnum
                   or ((i.indkey::int2[])[1] = a.attnum and (i.indkey::int2[])[0] =
                       (select t.attnum from pg_attribute t where t.attrelid = c.conrelid and t.attname = 'tenant_id'))))""")
    assert [tuple(r) for r in rows] == []


async def test_audit_events_columns_match_contract(owner_conn):
    rows = await owner_conn.fetch(
        "select attname from pg_attribute where attrelid='audit_events'::regclass "
        "and attnum > 0 and not attisdropped")
    assert {r["attname"] for r in rows} == set(AUDIT_EVENT_COLUMNS)


async def test_uuidv7_ids_sort_by_creation_time(owner_conn):
    ids = []
    for _ in range(5):
        ids.append(await owner_conn.fetchval("select uuidv7()"))
        await asyncio.sleep(0.003)
    assert ids == sorted(ids)
    assert all(i.version == 7 for i in ids)


async def test_ensure_partitions_is_idempotent(db_urls):
    assert await ensure_partitions(db_urls.owner, 3) == 0
    assert await ensure_partitions(db_urls.owner, 5) > 0
    assert await ensure_partitions(db_urls.owner, 5) == 0


async def test_resolve_agent_key_returns_only_listed_columns(app_engine, two_tenants, owner_conn):
    a, _ = two_tenants
    prefix = await owner_conn.fetchval("select prefix from agent_keys where tenant_id=$1", a["tenant_id"])
    async with system_tx(app_engine) as conn:
        res = await conn.execute(text("select * from private.resolve_agent_key(:p)"), {"p": prefix})
        assert set(res.keys()) == {"tenant_id", "agent_id", "agent_slug", "agent_status", "key_id",
                                   "key_hash", "expires_at", "revoked_at"}
        assert len(res.all()) == 1


async def test_app_cannot_read_users_without_tenant_context_but_can_resolve_login(app_engine, two_tenants):
    a, _ = two_tenants
    async with system_tx(app_engine) as conn:
        n = (await conn.execute(text("select count(*) from users"))).scalar_one()
        assert n == 0
        rows = (await conn.execute(text("select * from private.resolve_login(:e)"), {"e": a["email"]})).all()
    assert len(rows) == 1


async def test_concurrent_migrate_calls_are_serialised(db_urls):
    results = await asyncio.gather(migrate(db_urls.owner), migrate(db_urls.owner))
    assert results == [[], []]
