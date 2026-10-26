"""Reading the audit log (keyset pagination on (ts, seq), newest first)."""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from ..contracts.errors import ApiError
from .chain import iso


@dataclass
class EventFilter:
    agent: str | None = None
    session: UUID | None = None
    trace: str | None = None
    user: str | None = None
    module: str | None = None
    type: str | None = None
    decision: str | None = None
    severity: str | None = None
    tool: str | None = None
    since: datetime | None = None
    until: datetime | None = None


def encode_cursor(ts: datetime, seq: int) -> str:
    return base64.urlsafe_b64encode(f"{iso(ts)}|{seq}".encode()).decode().rstrip("=")


def decode_cursor(cursor: str | None) -> tuple[datetime, int] | None:
    if not cursor:
        return None
    try:
        raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)).decode()
        ts, seq = raw.split("|")
        return datetime.fromisoformat(ts), int(seq)
    except (binascii.Error, UnicodeDecodeError, ValueError) as exc:
        raise ApiError("validation_failed", "Invalid cursor") from exc


_COLS = ("e.seq, e.ts, e.id, e.trace_id, e.session_id, e.agent_slug, e.end_user, e.module, e.type, e.decision, "
         "e.rule_id, e.reason, e.severity, e.summary, e.payload_truncated, encode(e.hash, 'hex') as hash")


async def list_events(conn: AsyncConnection, tenant_id: UUID, f: EventFilter, limit: int, cursor: str | None,
                      *, include_payload: bool = False) -> tuple[list[dict[str, Any]], str | None]:
    where = ["e.tenant_id = :t"]
    params: dict[str, Any] = {"t": tenant_id, "n": limit + 1}
    for col, val in (("agent_slug", f.agent), ("session_id", f.session), ("trace_id", f.trace), ("end_user", f.user),
                     ("module", f.module), ("type", f.type), ("decision", f.decision), ("severity", f.severity)):
        if val is not None:
            where.append(f"e.{col} = :{col}")
            params[col] = val
    if f.tool:
        where.append("exists (select 1 from audit_payloads p where p.tenant_id = e.tenant_id and p.seq = e.seq "
                     "and p.ts = e.ts and p.payload->>'tool' = :tool)")
        params["tool"] = f.tool
    if f.since:
        where.append("e.ts >= :since")
        params["since"] = f.since
    if f.until:
        where.append("e.ts < :until")
        params["until"] = f.until
    cur = decode_cursor(cursor)
    if cur:
        where.append("(e.ts, e.seq) < (:cts, :cseq)")
        params["cts"], params["cseq"] = cur
    payload_col = ", p.payload as payload" if include_payload else ""
    payload_join = ("left join audit_payloads p on p.tenant_id = e.tenant_id and p.seq = e.seq and p.ts = e.ts"
                    if include_payload else "")
    avail = ", exists (select 1 from audit_payloads q where q.tenant_id = e.tenant_id and q.seq = e.seq and q.ts = e.ts) as payload_available"
    rows = (await conn.execute(text(
        f"select {_COLS}{avail}{payload_col} from audit_events e {payload_join} where {' and '.join(where)} "
        "order by e.ts desc, e.seq desc limit :n"), params)).mappings().all()
    items = [dict(r) for r in rows]
    nxt = None
    if len(items) > limit:
        items = items[:limit]
        nxt = encode_cursor(items[-1]["ts"], int(items[-1]["seq"]))
    return items, nxt
