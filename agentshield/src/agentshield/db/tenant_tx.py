"""Per-request transactions that carry the tenant context into Postgres RLS (db spec §B.2).

``set_config(..., true)`` is transaction-local, so it is safe behind a transaction-mode pooler.
If code forgets to use ``tenant_tx`` the setting is unset and RLS matches no rows (fail closed).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine


@asynccontextmanager
async def tenant_tx(engine: AsyncEngine, tenant_id: UUID | str) -> AsyncIterator[AsyncConnection]:
    async with engine.connect() as conn, conn.begin():
        await conn.execute(
            text("select set_config('app.tenant_id', :t, true)"), {"t": str(tenant_id)}
        )
        yield conn


@asynccontextmanager
async def system_tx(engine: AsyncEngine) -> AsyncIterator[AsyncConnection]:
    """A transaction with NO tenant context: only for the SECURITY DEFINER lookups in `private`."""
    async with engine.connect() as conn, conn.begin():
        yield conn
