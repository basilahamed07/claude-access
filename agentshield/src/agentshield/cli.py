"""`agentshield` command line (db upgrade, ensure-partitions; more commands arrive with later tasks)."""

from __future__ import annotations

import argparse
import asyncio
import os
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
    db_sub.add_parser("create-logins", help="create the app/worker/retention login roles from AGENTSHIELD_*_PASSWORD (idempotent)")
    register_extra_commands(sub)
    args = parser.parse_args(argv)
    settings = get_settings()
    if args.cmd == "db" and args.db_cmd == "upgrade":
        applied = asyncio.run(migrate(settings.owner_database_url))
        print("applied:", ", ".join(applied) or "nothing to do")
        return 0
    if args.cmd == "db" and args.db_cmd == "create-logins":
        from .db.logins import create_logins
        pw = {"agentshield_app_login": os.environ.get("AGENTSHIELD_APP_PASSWORD", ""), "agentshield_worker_login": os.environ.get("AGENTSHIELD_WORKER_PASSWORD", ""),
              "agentshield_retention_login": os.environ.get("AGENTSHIELD_RETENTION_PASSWORD", "")}
        done = asyncio.run(create_logins(settings.owner_database_url, pw))
        print("logins ready:", ", ".join(done) or "none (set AGENTSHIELD_APP_PASSWORD and AGENTSHIELD_WORKER_PASSWORD)")
        return 0 if done else 1
    if args.cmd == "db" and args.db_cmd == "ensure-partitions":
        n = asyncio.run(ensure_partitions(settings.owner_database_url, args.months_ahead))
        print(f"created {n} partitions")
        return 0
    return run_extra_command(args)


def register_extra_commands(sub: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
    vc = sub.add_parser("verify-chain", help="recompute the audit hash chain for a tenant")
    vc.add_argument("--tenant", required=True, help="tenant slug or id")
    sub.add_parser("worker", help="run the audit worker (consumes the event stream)")
    sub.add_parser("retention-run", help="purge old payloads and drop expired audit partitions")
    sd = sub.add_parser("seed-demo", help="create a demo tenant with an example attack (idempotent)")
    sd.add_argument("--password", help="password for the demo login (default: random, printed once)")


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


async def _retention() -> int:
    import redis.asyncio as aioredis

    from .audit.emitter import Emitter
    from .audit.retention import retention_run
    from .audit.spool import Spool
    from .db.engine import create_engine
    s = get_settings()
    engine = create_engine(s.retention_database_url or s.owner_database_url, pool_size=2, statement_timeout_ms=120_000)
    redis = aioredis.from_url(s.redis_url)
    try:
        report = await retention_run(engine, emitter=Emitter(redis, Spool(s.spool_dir)))
    finally:
        await redis.aclose()
        await engine.dispose()
    print(f"payloads deleted: {report.payloads_deleted} (+{report.incident_payloads_deleted} past incident retention); "
          f"partitions dropped: {', '.join(report.partitions_dropped) or 'none'}; checkpoints: {report.checkpoints}")
    return 0


async def _seed_demo(password: str | None) -> int:
    from .demo.seed import seed_demo
    result = await seed_demo(get_settings(), password=password)
    if not result.created:
        print(f"demo tenant '{result.tenant_slug}' already exists; nothing changed")
        return 0
    print(f"demo tenant created. Sign in as {result.email} with password: {result.password}")
    return 0


def run_extra_command(args: argparse.Namespace) -> int:
    if args.cmd == "verify-chain":
        return asyncio.run(_verify(args.tenant))
    if args.cmd == "worker":
        return asyncio.run(_worker())
    if args.cmd == "retention-run":
        return asyncio.run(_retention())
    if args.cmd == "seed-demo":
        return asyncio.run(_seed_demo(args.password))
    print(f"unknown command: {args.cmd}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
