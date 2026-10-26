"""Tiny forward-only migration runner.

The SQL files in ``migrations/`` are the single source of truth for the schema, including row
level security, partitions, triggers and grants, none of which an ORM can express. Files run as
the owner/superuser, in name order, once each, serialised by an advisory lock.
"""

from __future__ import annotations

from importlib import resources
from pathlib import Path

import asyncpg

MIGRATIONS_DIR = Path(str(resources.files("agentshield.db") / "migrations"))
_LOCK_ID = 7_243_001


def to_asyncpg_dsn(url: str) -> str:
    """Accept SQLAlchemy-style URLs (postgresql+asyncpg://) as well as plain DSNs."""
    return url.replace("postgresql+asyncpg://", "postgresql://", 1)


def _load_migrations() -> list[tuple[str, str]]:
    return [(p.stem, p.read_text()) for p in sorted(MIGRATIONS_DIR.glob("*.sql"))]


async def migrate(dsn: str) -> list[str]:
    """Apply pending migrations; returns the versions applied by this call."""
    conn = await asyncpg.connect(to_asyncpg_dsn(dsn))
    applied: list[str] = []
    try:
        await conn.execute("select pg_advisory_lock($1)", _LOCK_ID)
        await conn.execute(
            "create table if not exists public.schema_migrations ("
            "version text primary key, applied_at timestamptz not null default now())"
        )
        done = {r["version"] for r in await conn.fetch("select version from public.schema_migrations")}
        for version, sql in _load_migrations():
            if version in done:
                continue
            async with conn.transaction():
                await conn.execute(sql)
                await conn.execute("insert into public.schema_migrations (version) values ($1)", version)
            applied.append(version)
        await conn.execute("select pg_advisory_unlock($1)", _LOCK_ID)
    finally:
        await conn.close()
    return applied
