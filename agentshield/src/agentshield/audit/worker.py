"""The only writer of `audit_events`: consumes the stream and appends hash-chained rows per tenant."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import socket
from collections import defaultdict
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from ..db.tenant_tx import tenant_tx
from ..observability import AUDIT_LAG
from .chain import GENESIS, compute_hash
from .emitter import STREAM

log = logging.getLogger("agentshield.audit")
GROUP = "audit-writers"
CLAIM_IDLE_MS = 30_000


class AuditWorker:
    def __init__(self, engine: AsyncEngine, redis: Any, *, stream: str = STREAM, group: str = GROUP,
                 consumer: str | None = None, batch: int = 500) -> None:
        self.engine, self.redis, self.stream, self.group = engine, redis, stream, group
        self.consumer = consumer or f"{socket.gethostname()}-{os.getpid()}"
        self.batch = batch

    async def ensure_group(self) -> None:
        try:
            await self.redis.xgroup_create(self.stream, self.group, id="0", mkstream=True)
        except Exception as exc:                              # noqa: BLE001
            if "BUSYGROUP" not in str(exc):
                raise

    async def process_once(self, *, block_ms: int = 0) -> int:
        """Read one batch (new messages, then abandoned ones), write it, ack it. Returns rows written."""
        await self.ensure_group()
        resp = await self.redis.xreadgroup(self.group, self.consumer, {self.stream: ">"}, count=self.batch,
                                           block=block_ms or None)
        messages: list[tuple[bytes, dict[bytes, bytes]]] = []
        for _stream, items in resp or []:
            messages += items
        if not messages:
            claimed = await self.redis.xautoclaim(self.stream, self.group, self.consumer, CLAIM_IDLE_MS,
                                                  start_id="0-0", count=self.batch)
            messages = list(claimed[1]) if claimed and len(claimed) > 1 else []
        if not messages:
            return 0
        by_tenant: dict[str, list[tuple[bytes, dict[str, Any], str]]] = defaultdict(list)
        poison: list[bytes] = []
        for msg_id, fields in messages:
            try:
                event = json.loads(fields[b"event"])
                by_tenant[str(event["tenant_id"])].append((msg_id, event, fields[b"payload"].decode()))
            except (KeyError, ValueError):
                log.error("dropping malformed audit message %s", msg_id)
                poison.append(msg_id)
        written = 0
        newest = max((datetime.fromisoformat(e["ts"]) for items in by_tenant.values() for _, e, _ in items), default=None)
        for tenant_id, items in by_tenant.items():
            written += await self._write_tenant(tenant_id, items)
            await self.redis.xack(self.stream, self.group, *[i[0] for i in items])
        if poison:
            await self.redis.xack(self.stream, self.group, *poison)
        if newest is not None:
            AUDIT_LAG.set(max(0.0, (datetime.now(UTC) - newest).total_seconds()))
        return written

    async def _write_tenant(self, tenant_id: str, items: list[tuple[bytes, dict[str, Any], str]]) -> int:
        async with tenant_tx(self.engine, tenant_id) as conn:
            await conn.execute(text("select pg_advisory_xact_lock(hashtextextended(:t, 0))"), {"t": tenant_id})
            ids = [e["id"] for _, e, _ in items]
            seen = {r[0] for r in (await conn.execute(
                text("select id from audit_events where tenant_id = :t and id = any(:ids)"),
                {"t": tenant_id, "ids": ids})).all()}
            head = (await conn.execute(text(
                "select last_seq, last_hash from audit_chain_heads where tenant_id = :t for update"),
                {"t": tenant_id})).first()
            if head is None:
                await conn.execute(text(
                    "insert into audit_chain_heads (tenant_id, last_seq, last_hash) values (:t, 0, :h) "
                    "on conflict (tenant_id) do nothing"), {"t": tenant_id, "h": GENESIS})
                head = (await conn.execute(text(
                    "select last_seq, last_hash from audit_chain_heads where tenant_id = :t for update"),
                    {"t": tenant_id})).one()
            seq, prev = int(head[0]), bytes(head[1])
            n = 0
            for _msg_id, ev, payload in items:
                if ev["id"] in seen:                      # redelivered after a crash before XACK
                    continue
                seq += 1
                ts = datetime.fromisoformat(ev["ts"])
                cols = {**ev, "seq": seq, "ts": ts, "schema": ev.get("schema", "agentshield.event/1")}
                digest = compute_hash(prev, cols)
                session_id = UUID(ev["session_id"]) if ev.get("session_id") else None
                await conn.execute(text(
                    "insert into audit_events (tenant_id, seq, ts, schema, id, trace_id, session_id, agent_slug, "
                    "end_user, parent_id, module, type, decision, rule_id, reason, severity, summary, "
                    "payload_sha256, payload_truncated, prev_hash, hash, otel_span_id) values (:tenant_id, :seq, :ts, "
                    ":schema, :id, :trace_id, :session_id, :agent_slug, :end_user, :parent_id, :module, :type, "
                    ":decision, :rule_id, :reason, :severity, :summary, :payload_sha256, :payload_truncated, "
                    ":prev_hash, :hash, :otel_span_id)"),
                    {"tenant_id": tenant_id, "seq": seq, "ts": ts, "schema": cols["schema"], "id": ev["id"],
                     "trace_id": ev["trace_id"], "session_id": session_id, "agent_slug": ev.get("agent_slug"),
                     "end_user": ev.get("end_user"), "parent_id": ev.get("parent_id"), "module": ev["module"],
                     "type": ev["type"], "decision": ev.get("decision"), "rule_id": ev.get("rule_id"),
                     "reason": ev.get("reason"), "severity": ev.get("severity", "info"),
                     "summary": ev.get("summary", ""), "payload_sha256": bytes.fromhex(ev["payload_sha256"]),
                     "payload_truncated": bool(ev.get("payload_truncated")), "prev_hash": prev, "hash": digest,
                     "otel_span_id": ev.get("otel_span_id")})
                await conn.execute(text(
                    "insert into audit_payloads (tenant_id, seq, ts, session_id, payload) "
                    "values (:t, :seq, :ts, :s, cast(:p as jsonb))"),
                    {"t": tenant_id, "seq": seq, "ts": ts, "s": session_id, "p": payload})
                prev = digest
                n += 1
            if n:
                await conn.execute(text("update audit_chain_heads set last_seq = :s, last_hash = :h "
                                        "where tenant_id = :t"), {"s": seq, "h": prev, "t": tenant_id})
            return n

    async def run(self, stop: asyncio.Event | None = None, *, block_ms: int = 1000) -> None:
        stop = stop or asyncio.Event()
        while not stop.is_set():
            try:
                await self.process_once(block_ms=block_ms)
            except Exception:                                   # noqa: BLE001
                log.exception("audit worker iteration failed; retrying")
                await asyncio.sleep(1.0)
