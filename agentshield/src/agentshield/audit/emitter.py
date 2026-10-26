"""Non-blocking audit emitter: redact -> cap -> hash -> Redis Stream (spool on failure)."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from collections.abc import Mapping
from typing import Any

from ..contracts.events import AuditEvent, EventType
from ..contracts.ids import new_trace_id
from ..observability import DECISIONS, current_span_ref
from .chain import canonical_json
from .redact import redact, redact_text
from .spool import Spool

log = logging.getLogger("agentshield.audit")
STREAM = "stream:audit.events"
MAX_PAYLOAD_BYTES = 64 * 1024
XADD_TIMEOUT = 1.0


class Emitter:
    def __init__(self, redis: Any, spool: Spool, *, stream: str = STREAM, max_payload: int = MAX_PAYLOAD_BYTES,
                 maxlen: int = 1_000_000) -> None:
        self.redis = redis
        self.spool = spool
        self.stream = stream
        self.max_payload = max_payload
        self.maxlen = maxlen
        self._lock = asyncio.Lock()

    def prepare(self, event: AuditEvent, payload: Mapping[str, Any] | None) -> dict[str, str]:
        """Redact everything, cap the payload and compute its digest. Pure and synchronous."""
        red = redact(dict(payload or {}))
        if event.decision is not None:
            DECISIONS.labels(event.decision.value, event.module).inc()
        if event.otel_span_id is None:
            event.otel_span_id = current_span_ref()
        event.summary = redact_text(event.summary, [])[:500]
        if event.reason:
            event.reason = redact_text(event.reason, [])[:1000]
        full = canonical_json(red.value)
        event.payload_sha256 = hashlib.sha256(full).hexdigest()
        body = red.value
        if len(full) > self.max_payload:
            event.payload_truncated = True
            body = {"_truncated": True, "_bytes": len(full), "preview": full[: self.max_payload // 2].decode(errors="ignore")}
        elif red.kinds:
            body = {**body, "_redacted": red.kinds} if isinstance(body, dict) else body
        return {"tenant": event.tenant_id, "event": json.dumps(event.envelope()),
                "payload": json.dumps(body, ensure_ascii=False, default=str)}

    async def _xadd(self, record: Mapping[str, str]) -> None:
        await asyncio.wait_for(self.redis.xadd(self.stream, dict(record), maxlen=self.maxlen, approximate=True),
                               timeout=XADD_TIMEOUT)

    async def emit(self, event: AuditEvent, payload: Mapping[str, Any] | None = None) -> None:
        """Never raises: logging must not break the request it describes."""
        try:
            record = self.prepare(event, payload)
        except Exception:                                   # noqa: BLE001
            log.exception("could not prepare audit event %s", event.type)
            return
        async with self._lock:
            try:
                await self._flush_spool(event.tenant_id)
                await self._xadd(record)
            except Exception as exc:                         # noqa: BLE001
                log.warning("audit stream unavailable (%s); spooling event", type(exc).__name__)
                self.spool.add(record)

    async def _flush_spool(self, tenant_id: str) -> None:
        if not len(self.spool):
            return
        for rec in self.spool.drain():
            await self._xadd(rec)
        n, dropped, first, last = self.spool.clear()
        gap = AuditEvent(tenant_id=tenant_id, trace_id=new_trace_id(), module="audit", type=EventType.audit_gap,
                         severity="medium", summary=f"{n} events were delayed and {dropped} dropped while the "
                                                    "audit stream was unavailable")
        await self._xadd(self.prepare(gap, {"delayed": n, "dropped": dropped, "from": first, "to": last}))
