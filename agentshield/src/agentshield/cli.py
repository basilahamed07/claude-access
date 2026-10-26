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
    """Hook for commands defined by later tasks (verify-chain, seed-demo, worker, ...)."""


def run_extra_command(args: argparse.Namespace) -> int:
    print(f"unknown command: {args.cmd}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
