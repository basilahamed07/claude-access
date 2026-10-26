"""Shadow AI ingest: turn log lines into the inventory of AI tools seen (design §2.4).

Raw user names are never stored: each is hashed (keyed with the tenant id) into a HyperLogLog, so the inventory can say
"about 14 people" without being able to say who.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import text

from ..audit.events import make_event
from ..contracts.events import EventType
from ..db.tenant_tx import tenant_tx
from ..tenants.context import TenantContext
from .catalog import LARGE_UPLOAD_BYTES, Match, classify_host, suggested_alternative
from .parsers import parse

UNASSIGNED = "unassigned"
BATCH_TTL = 86_400
STALE_AFTER = 24 * 3600


@dataclass
class _Agg:
    match: Match
    hits: int = 0
    bytes_out: int = 0
    max_upload: int = 0
    first: datetime | None = None
    last: datetime | None = None
    users: set[str] = field(default_factory=set)


class ShadowService:
    def __init__(self, *, engine: Any, redis: Any, emitter: Any, pepper: bytes) -> None:
        self.engine, self.redis, self.emitter, self.pepper = engine, redis, emitter, pepper

    def _user_hash(self, ctx: TenantContext, user: str) -> bytes:
        return hmac.new(self.pepper, f"{ctx.tenant_id}:{user}".encode(), hashlib.sha256).digest()[:16]

    async def ingest(self, ctx: TenantContext, *, source: str, fmt: str, batch_id: str, team: str | None,
                     lines: list[str] | None, records: list[dict[str, Any]] | None) -> dict[str, Any]:
        batch_key = f"shadow:batch:{ctx.tenant_id}:{batch_id}"
        if not await self.redis.set(batch_key, "1", nx=True, ex=BATCH_TTL):
            return {"batch_id": batch_id, "duplicate": True, "accepted": 0, "rejected": 0, "reasons": [], "tools_seen": 0, "new_tools": 0}
        try:
            return await self._ingest(ctx, source, fmt, batch_id, team, lines, records)
        except BaseException:
            await self.redis.delete(batch_key)            # a failed batch may be sent again
            raise

    async def _ingest(self, ctx: TenantContext, source: str, fmt: str, batch_id: str, team: str | None,
                      lines: list[str] | None, records: list[dict[str, Any]] | None) -> dict[str, Any]:
        hits, rejected, reasons = parse(fmt, lines, records)
        now = datetime.now(UTC)
        groups: dict[tuple[str, str], _Agg] = {}
        for h in hits:
            m = classify_host(h.host, h.path)
            if m is None:
                continue
            key = (m.domain, (h.team or team or UNASSIGNED)[:100])
            g = groups.setdefault(key, _Agg(m))
            g.hits += 1
            g.bytes_out += h.bytes_out
            g.max_upload = max(g.max_upload, h.bytes_out)
            ts = min(h.ts, now)
            g.first = ts if g.first is None else min(g.first, ts)
            g.last = ts if g.last is None else max(g.last, ts)
            if h.user:
                g.users.add(h.user)
        new_tools = 0
        events: list[tuple[str, str, str, dict[str, Any]]] = []     # (type, severity, summary, payload)
        for (domain, tm), g in groups.items():
            uk = f"shadow:u:{ctx.tenant_id}:{domain}:{tm}"
            if g.users:
                await self.redis.pfadd(uk, *[self._user_hash(ctx, u) for u in g.users])
                await self.redis.expire(uk, 400 * 86_400)
            users_count = int(await self.redis.pfcount(uk))
            async with tenant_tx(self.engine, ctx.tenant_id) as conn:
                row = (await conn.execute(text(
                    "insert into ai_tools_seen (tenant_id, domain, vendor, category, risk, classification, team, source, reason, hits, bytes_out, users_count, first_seen, last_seen) "
                    "values (:t, :d, :v, :c, :r, 'unknown', :tm, :src, :why, :h, :b, :u, :f, :l) "
                    "on conflict (tenant_id, domain, team) do update set hits = ai_tools_seen.hits + excluded.hits, bytes_out = ai_tools_seen.bytes_out + excluded.bytes_out, "
                    "users_count = greatest(ai_tools_seen.users_count, excluded.users_count), first_seen = least(ai_tools_seen.first_seen, excluded.first_seen), "
                    "last_seen = greatest(ai_tools_seen.last_seen, excluded.last_seen), source = excluded.source "
                    "returning classification, (xmax = 0) as inserted"),
                    {"t": ctx.tenant_id, "d": domain, "v": g.match.vendor, "c": g.match.category, "r": g.match.risk, "tm": tm, "src": source, "why": g.match.reason,
                     "h": g.hits, "b": g.bytes_out, "u": users_count, "f": g.first, "l": g.last})).mappings().one()
            cls, inserted = row["classification"], bool(row["inserted"])
            new_tools += int(inserted)
            payload = {"domain": domain, "team": tm, "vendor": g.match.vendor, "category": g.match.category, "risk": g.match.risk, "classification": cls,
                       "reason": g.match.reason, "hits": g.hits, "users": users_count, "source": source, "batch_id": batch_id}
            if cls == "blocked":
                events.append((EventType.shadow_tool_seen, "high", f"Blocked AI tool {domain} was used by team {tm}", payload))
            elif inserted:
                events.append((EventType.shadow_tool_seen, "medium" if g.match.risk == "high" else "low", f"New AI tool seen: {domain} (team {tm})", payload))
            if cls != "approved" and g.max_upload >= LARGE_UPLOAD_BYTES:
                events.append((EventType.shadow_dlp_hit, "high", f"Large upload ({g.max_upload} bytes) to unapproved AI tool {domain}",
                               {**payload, "max_upload_bytes": g.max_upload, "total_bytes": g.bytes_out}))
        trace = f"shadow-{batch_id}"[:80]
        for etype, sev, summary, payload in events:
            await self.emitter.emit(make_event(ctx, trace, "shadow", etype, summary, severity=sev), payload)  # type: ignore[arg-type]
        await self.redis.set(f"shadow:src:{ctx.tenant_id}:{source}", str(time.time()))
        return {"batch_id": batch_id, "duplicate": False, "accepted": len(hits), "rejected": rejected, "reasons": reasons,
                "tools_seen": len(groups), "new_tools": new_tools}

    async def check_stale(self, ctx: TenantContext, *, now: float | None = None) -> list[str]:
        """Sources that reported before but have been silent for 24 h: a blind spot, so it is an event, once a day."""
        now = now or time.time()
        stale: list[str] = []
        for source in ("proxy", "dns"):
            raw = await self.redis.get(f"shadow:src:{ctx.tenant_id}:{source}")
            if raw is None or now - float(raw) < STALE_AFTER:
                continue
            if await self.redis.set(f"shadow:stale:{ctx.tenant_id}:{source}", "1", nx=True, ex=STALE_AFTER):
                await self.emitter.emit(make_event(ctx, f"shadow-stale-{source}", "shadow", EventType.shadow_source_stale,
                                                   f"No {source} logs received for over 24 hours", severity="medium"),
                                        {"source": source, "last_seen": float(raw)})
            stale.append(source)
        return stale

    async def classify(self, ctx: TenantContext, tool_id: Any, classification: str, alternative: str | None) -> dict[str, Any] | None:
        async with tenant_tx(self.engine, ctx.tenant_id) as conn:
            row = (await conn.execute(text(
                "update ai_tools_seen set classification = :c, classified_by = :u, suggested_alternative = coalesce(:alt, suggested_alternative) where id = :i "
                "returning id, domain, vendor, category, risk, classification, team, source, reason, hits, bytes_out, users_count, first_seen, last_seen, suggested_alternative"),
                {"c": classification, "u": ctx.actor_id, "alt": alternative, "i": tool_id})).mappings().first()
        if row is None:
            return None
        out = dict(row)
        if classification == "approved" and not out["suggested_alternative"]:
            out["suggested_alternative"] = suggested_alternative(Match(out["domain"], out["vendor"], out["category"], out["risk"] or "medium", "catalog"))
        return out
