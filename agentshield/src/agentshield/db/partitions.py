"""Audit partition maintenance (run as the owner role)."""

from __future__ import annotations

import asyncpg

from .migrate import to_asyncpg_dsn


async def ensure_partitions(owner_dsn: str, months_ahead: int = 3) -> int:
    """Create monthly audit partitions up to ``months_ahead``; returns how many were created."""
    conn = await asyncpg.connect(to_asyncpg_dsn(owner_dsn))
    try:
        created = await conn.fetchval("select private.ensure_audit_partitions($1)", months_ahead)
    finally:
        await conn.close()
    return int(created)
