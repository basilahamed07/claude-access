"""Hash chain over audit events. hash = sha256(prev_hash || canonical_json(envelope)) per tenant.

The envelope is every `audit_events` column except `prev_hash` and `hash` (it already contains
`payload_sha256`, so payload bodies can be purged on a shorter schedule without breaking the chain).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from ..db.tenant_tx import tenant_tx

GENESIS = hashlib.sha256(b"agentshield-genesis-v1").digest()
ENVELOPE_FIELDS = ("tenant_id", "seq", "ts", "schema", "id", "trace_id", "session_id", "agent_slug", "end_user",
                   "parent_id", "module", "type", "decision", "rule_id", "reason", "severity", "summary",
                   "payload_sha256", "payload_truncated", "otel_span_id")


def canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode()


def iso(ts: datetime) -> str:
    return ts.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def normalise(cols: dict[str, Any]) -> dict[str, Any]:
    """Map column values (from an event or a DB row) to the one canonical JSON-able envelope."""
    out: dict[str, Any] = {}
    for f in ENVELOPE_FIELDS:
        v = cols.get(f)
        if f == "ts" and isinstance(v, datetime):
            v = iso(v)
        elif f in {"tenant_id", "session_id"} and v is not None:
            v = str(v)
        elif f == "payload_sha256" and isinstance(v, (bytes, bytearray, memoryview)):
            v = bytes(v).hex()
        out[f] = v
    return out


def compute_hash(prev_hash: bytes, envelope: dict[str, Any]) -> bytes:
    return hashlib.sha256(bytes(prev_hash) + canonical_json(normalise(envelope))).digest()


@dataclass
class ChainReport:
    ok: bool
    checked: int
    first_bad_seq: int | None = None
    first_seq: int | None = None
    last_seq: int | None = None
    reason: str | None = None


async def verify_chain(engine: AsyncEngine, tenant_id: UUID | str, *, page: int = 2000) -> ChainReport:
    """Recompute every hash from stored rows. Rows before a retention checkpoint may be gone: verification
    then starts at the first surviving row and trusts its `prev_hash` (reported via `first_seq`)."""
    checked = 0
    prev: bytes | None = None
    first_seq: int | None = None
    last_seq: int | None = None
    after = 0
    cols = ", ".join(f'"{c}"' for c in (*ENVELOPE_FIELDS, "prev_hash", "hash"))
    while True:
        async with tenant_tx(engine, tenant_id) as conn:
            rows = (await conn.execute(text(
                f"select {cols} from audit_events where tenant_id = :t and seq > :a order by seq limit :n"),
                {"t": str(tenant_id), "a": after, "n": page})).mappings().all()
        if not rows:
            break
        for r in rows:
            row = dict(r)
            seq = int(row["seq"])
            if first_seq is None:
                first_seq = seq
                prev = bytes(row["prev_hash"]) if seq > 1 else GENESIS
                if seq == 1 and bytes(row["prev_hash"]) != GENESIS:
                    return ChainReport(False, checked, seq, first_seq, last_seq, "first row does not chain to genesis")
            elif seq != (last_seq or 0) + 1:
                return ChainReport(False, checked, seq, first_seq, last_seq, "sequence gap")
            if bytes(row["prev_hash"]) != prev:
                return ChainReport(False, checked, seq, first_seq, last_seq, "prev_hash mismatch")
            if compute_hash(prev, row) != bytes(row["hash"]):
                return ChainReport(False, checked, seq, first_seq, last_seq, "hash mismatch (row was altered)")
            prev = bytes(row["hash"])
            last_seq = seq
            checked += 1
        after = int(rows[-1]["seq"])
    async with tenant_tx(engine, tenant_id) as conn:
        head = (await conn.execute(text("select last_seq, last_hash from audit_chain_heads where tenant_id = :t"),
                                   {"t": str(tenant_id)})).mappings().first()
    if head is not None and (last_seq is None or int(head["last_seq"]) != last_seq or bytes(head["last_hash"]) != prev):
        return ChainReport(False, checked, (last_seq or 0) + 1, first_seq, last_seq,
                           "chain head does not match the last row (rows removed from the end?)")
    return ChainReport(True, checked, None, first_seq, last_seq)
