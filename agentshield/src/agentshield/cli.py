"""`agentshield` command line (db upgrade, ensure-partitions; more commands arrive with later tasks)."""

from __future__ import annotations

import argparse
import asyncio
import sys

from .db.migrate import migrate
from .db.partitions import ensure_partitions
from .settings import get_settings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agentshield")
    sub = parser.add_subparsers(dest="cmd", required=True)
    db = sub.add_parser("db")
    db_sub = db.add_subparsers(dest="db_cmd", required=True)
    db_sub.add_parser("upgrade")
    ep = db_sub.add_parser("ensure-partitions")
    ep.add_argument("--months-ahead", type=int, default=3)
    register_extra_commands(sub)
    args = parser.parse_args(argv)
    settings = get_settings()
    if args.cmd == "db" and args.db_cmd == "upgrade":
        applied = asyncio.run(migrate(settings.owner_database_url))
        print("applied:", ", ".join(applied) or "nothing to do")
        return 0
    if args.cmd == "db" and args.db_cmd == "ensure-partitions":
        n = asyncio.run(ensure_partitions(settings.owner_database_url, args.months_ahead))
        print(f"created {n} partitions")
        return 0
    return run_extra_command(args)


def register_extra_commands(sub: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
    vc = sub.add_parser("verify-chain", help="recompute the audit hash chain for a tenant")
    vc.add_argument("--tenant", required=True, help="tenant slug or id")
    sub.add_parser("worker", help="run the audit worker (consumes the event stream)")


async def _resolve_tenant(engine: object, ref: str) -> str | None:
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import AsyncEngine
    assert isinstance(engine, AsyncEngine)
    async with engine.connect() as conn:
        row = (await conn.execute(text("select id from tenants where slug = :r or id::text = :r"), {"r": ref})).first()
    return str(row[0]) if row else None


async def _verify(ref: str) -> int:
    from .audit.chain import verify_chain
    from .db.engine import create_engine
    engine = create_engine(get_settings().owner_database_url, pool_size=2)
    try:
        tenant_id = await _resolve_tenant(engine, ref)
        if tenant_id is None:
            print(f"unknown tenant: {ref}", file=sys.stderr)
            return 2
        report = await verify_chain(engine, tenant_id)
    finally:
        await engine.dispose()
    if report.ok:
        print(f"OK: {report.checked} events verified (seq {report.first_seq}..{report.last_seq})")
        return 0
    print(f"FAILED at seq {report.first_bad_seq}: {report.reason} ({report.checked} events verified before it)",
          file=sys.stderr)
    return 1


async def _worker() -> int:
    import redis.asyncio as aioredis

    from .audit.worker import AuditWorker
    from .db.engine import create_engine
    s = get_settings()
    engine = create_engine(s.worker_database_url or s.database_url, pool_size=4, statement_timeout_ms=30_000)
    redis = aioredis.from_url(s.redis_url)
    try:
        await AuditWorker(engine, redis).run()
    finally:
        await redis.aclose()
        await engine.dispose()
    return 0


def run_extra_command(args: argparse.Namespace) -> int:
    if args.cmd == "verify-chain":
        return asyncio.run(_verify(args.tenant))
    if args.cmd == "worker":
        return asyncio.run(_worker())
    print(f"unknown command: {args.cmd}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
