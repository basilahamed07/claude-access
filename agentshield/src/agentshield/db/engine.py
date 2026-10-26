"""Async engine factory with the connection hygiene of db spec §B.8."""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine


def create_engine(url: str, *, pool_size: int = 10, statement_timeout_ms: int = 5000) -> AsyncEngine:
    if url.startswith("postgresql://"):
        url = url.replace("postgresql://", "postgresql+asyncpg://", 1)
    return create_async_engine(
        url,
        pool_size=pool_size,
        max_overflow=5,
        pool_pre_ping=True,
        connect_args={
            "server_settings": {
                "statement_timeout": str(statement_timeout_ms),
                "idle_in_transaction_session_timeout": "10000",
                "application_name": "agentshield",
            }
        },
    )
