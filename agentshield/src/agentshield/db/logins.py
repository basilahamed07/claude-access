"""Create the login roles the services connect as, in the groups the migration defined. Idempotent; run as the owner."""

from __future__ import annotations

import asyncpg

from .migrate import to_asyncpg_dsn

LOGINS = {"agentshield_app_login": "agentshield_app", "agentshield_worker_login": "agentshield_worker",
          "agentshield_retention_login": "agentshield_retention"}


async def create_logins(owner_dsn: str, passwords: dict[str, str]) -> list[str]:
    """`passwords` maps each login name to its password. Existing logins get the new password (rotation). Returns the logins touched."""
    conn = await asyncpg.connect(to_asyncpg_dsn(owner_dsn))
    done: list[str] = []
    try:
        for login, group in LOGINS.items():
            pw = passwords.get(login)
            if not pw:
                continue
            quoted = await conn.fetchval("select quote_literal($1)", pw)
            exists = await conn.fetchval("select 1 from pg_roles where rolname = $1", login)
            if exists:
                await conn.execute(f"alter role {login} login password {quoted}")
            else:
                await conn.execute(f"create role {login} login password {quoted} in role {group}")
            done.append(login)
    finally:
        await conn.close()
    return done
