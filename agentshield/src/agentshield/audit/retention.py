"""Retention (db spec §B.7): purge payloads early, keep envelopes at least 180 days, keep incidents longer.

* payloads older than the tenant's `payload_days` are deleted, except those of incident sessions, which
  are kept for `incident_days`. Envelopes (and so the hash chain) are untouched.
* a monthly partition is dropped only when it is older than every tenant's `envelope_days` (and never
  younger than 180 days: the database function enforces that floor too). Before it goes, each tenant's
  last sequence number and hash in it are recorded in an `audit.checkpoint` event and incident sessions
  are copied to the archive tables.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from ..contracts.admin import Retention
from ..contracts.events import AuditEvent, EventType
from ..contracts.ids import new_trace_id
from ..db.tenant_tx import system_tx, tenant_tx
from .emitter import Emitter

log = logging.getLogger("agentshield.retention")
BATCH = 10_000
ENVELOPE_FLOOR_DAYS = 180


@dataclass
class RetentionReport:
    payloads_deleted: int = 0
    incident_payloads_deleted: int = 0
    archived_events: int = 0
    partitions_dropped: list[str] = field(default_factory=list)
    checkpoints: int = 0


def _settings(raw: dict[str, Any] | None) -> Retention:
    return Retention.model_validate((raw or {}).get("retention") or {})


async def _tenants(engine: AsyncEngine) -> list[UUID]:
    async with system_tx(engine) as conn:
        return [r[0] for r in (await conn.execute(text("select tenant_id from private.tenants_with_audit_backlog()"))).all()]


async def _delete_batches(engine: AsyncEngine, tenant_id: UUID, where: str, params: dict[str, Any]) -> int:
    total = 0
    while True:
        async with tenant_tx(engine, tenant_id) as conn:
            res = await conn.execute(text(
                "delete from audit_payloads where (tenant_id, seq, ts) in ("
                f"select p.tenant_id, p.seq, p.ts from audit_payloads p where p.tenant_id = :t and {where} limit {BATCH})"),
                {"t": tenant_id, **params})
        total += res.rowcount
        if res.rowcount < BATCH:
            return total


async def retention_run(engine: AsyncEngine, now: datetime | None = None, *, emitter: Emitter | None = None) -> RetentionReport:
    now = now or datetime.now(UTC)
    report = RetentionReport()
    tenants = await _tenants(engine)
    floor_days = ENVELOPE_FLOOR_DAYS
    for tid in tenants:
        async with tenant_tx(engine, tid) as conn:
            raw = (await conn.execute(text("select settings from tenants where id = :t"), {"t": tid})).scalar_one_or_none()
        cfg = _settings(raw)
        floor_days = max(floor_days, cfg.envelope_days)
        in_incident = ("exists (select 1 from incidents i where i.tenant_id = p.tenant_id and i.session_id = p.session_id)")
        report.payloads_deleted += await _delete_batches(
            engine, tid, f"p.ts < :cut and not (p.session_id is not null and {in_incident})",
            {"cut": now - timedelta(days=cfg.payload_days)})
        report.incident_payloads_deleted += await _delete_batches(
            engine, tid, f"p.ts < :cut and p.session_id is not null and {in_incident}",
            {"cut": now - timedelta(days=cfg.incident_days)})
    if emitter is not None:
        await _drop_old_partitions(engine, tenants, now, floor_days, emitter, report)
    return report


async def _drop_old_partitions(engine: AsyncEngine, tenants: list[UUID], now: datetime, floor_days: int,
                               emitter: Emitter, report: RetentionReport) -> None:
    async with system_tx(engine) as conn:
        parts = [(int(r[0]), int(r[1])) for r in (await conn.execute(text("select year, month from private.audit_partitions()"))).all()]
    for year, month in sorted(parts):
        start = datetime(year, month, 1, tzinfo=UTC)
        end = datetime(year + (month == 12), month % 12 + 1, 1, tzinfo=UTC)
        if end > now - timedelta(days=floor_days):
            continue
        for tid in tenants:
            async with tenant_tx(engine, tid) as conn:
                p = {"t": tid, "s": start, "e": end}
                last = (await conn.execute(text(
                    "select seq, encode(hash, 'hex') as hash, (select count(*) from audit_events where tenant_id = :t "
                    "and ts >= :s and ts < :e) as n from audit_events where tenant_id = :t and ts >= :s and ts < :e "
                    "order by seq desc limit 1"), p)).mappings().first()
                if last is None:
                    continue
                archived = (await conn.execute(text(
                    "insert into audit_events_archive select e.* from audit_events e where e.tenant_id = :t and e.ts >= :s "
                    "and e.ts < :e and e.session_id in (select session_id from incidents where tenant_id = :t) "
                    "on conflict do nothing"), p)).rowcount
                await conn.execute(text(
                    "insert into audit_payloads_archive select q.* from audit_payloads q where q.tenant_id = :t and q.ts >= :s "
                    "and q.ts < :e and q.session_id in (select session_id from incidents where tenant_id = :t) "
                    "on conflict do nothing"), p)
            report.archived_events += archived
            await emitter.emit(
                AuditEvent(tenant_id=str(tid), trace_id=new_trace_id(), module="audit", type=EventType.audit_checkpoint,
                           summary=f"partition {year}-{month:02d} dropped; chain checkpoint at seq {last['seq']}"),
                {"partition": f"{year}-{month:02d}", "last_seq": int(last["seq"]), "last_hash": last["hash"],
                 "events": int(last["n"])})
            report.checkpoints += 1
        async with system_tx(engine) as conn:
            dropped = (await conn.execute(text("select private.drop_audit_partition(:y, :m, :now)"),
                                          {"y": year, "m": month, "now": now})).scalar_one()
        if dropped:
            report.partitions_dropped.append(f"{year}-{month:02d}")
            log.info("dropped audit partition %d-%02d", year, month)
