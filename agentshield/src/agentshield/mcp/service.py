"""Scan, approve, reject and watch MCP servers; fetch a server's tools live; the audit trail of all of it."""

from __future__ import annotations

import logging
import time
from typing import Any
from uuid import UUID

import httpx
from sqlalchemy import text

from ..audit.emitter import Emitter
from ..audit.events import make_event
from ..contracts.errors import ApiError
from ..contracts.events import EventType, Severity
from ..contracts.ids import new_trace_id
from ..db.tenant_tx import tenant_tx
from ..scan.pipeline import ScanService
from ..tenants.context import TenantContext
from ..tenants.crypto import decrypt_secret
from . import registry
from .analysis import Tool, build_report, fingerprint
from .client import McpClient, McpError

log = logging.getLogger("agentshield.mcp")
SCAN_TIMEOUT = 20.0


def diff_tools(old: list[Tool], new: list[Tool]) -> dict[str, list[str]]:
    o, n = {t.name: t for t in old}, {t.name: t for t in new}
    return {"added": sorted(set(n) - set(o)), "removed": sorted(set(o) - set(n)),
            "changed": sorted(k for k in set(o) & set(n) if (o[k].description, o[k].input_schema) != (n[k].description, n[k].input_schema))}


class McpService:
    def __init__(self, *, engine: Any, emitter: Emitter, scanner: ScanService, http_provider: Any, master_key: bytes, allow_private: set[str],
                 live_ttl: float = 60.0) -> None:
        self.engine, self.emitter, self.scanner = engine, emitter, scanner
        self._http_provider = http_provider          # callable returning the shared httpx client (tests swap it)
        self.master_key, self.allow_private, self.live_ttl = master_key, allow_private, live_ttl
        self.unreachable_ttl = 5.0
        self._live: dict[tuple[str, str], tuple[float, str]] = {}

    def client(self, row: dict[str, Any]) -> McpClient:
        token = decrypt_secret(self.master_key, row["auth_ciphertext"]) if row.get("auth_ciphertext") else None
        http: httpx.AsyncClient = self._http_provider()
        return McpClient(http, row["url"], token=token, allow_private=self.allow_private, timeout=10.0)

    async def _event(self, ctx: TenantContext, trace_id: str, etype: EventType, summary: str, payload: dict[str, Any], severity: Severity = "info") -> None:
        await self.emitter.emit(make_event(ctx, trace_id, "mcp", etype, summary, severity=severity), payload)

    # ── scan ──────────────────────────────────────────────────────────────────────────────────────────
    async def scan(self, ctx: TenantContext, server_id: UUID, *, manifest: list[Tool] | None = None, source_files: dict[str, str] | None = None) -> dict[str, Any]:
        trace = new_trace_id()
        async with tenant_tx(self.engine, ctx.tenant_id) as conn:
            row = await registry.secret(conn, server_id)
        await self._event(ctx, trace, EventType.mcp_scan_started, f"scan of MCP server {row['name']} started", {"server": row["name"], "mode": "manifest" if manifest else "live"})
        error: str | None = None
        tools = manifest
        if tools is None:
            if not row["url"]:
                raise ApiError("validation_failed", "This server was registered with a tool list, so send the new tool list to rescan it")
            try:
                tools = await self.client(row).list_tools()
            except McpError as exc:
                error = str(exc)
        if tools is None:
            report: dict[str, Any] = {"error": error, "recommended_verdict": "pending", "findings": [], "checks": [], "limitations": ["The server could not be reached, so nothing was scanned."]}
            async with tenant_tx(self.engine, ctx.tenant_id) as conn:
                await registry.save_scan(conn, server_id, [], b"", report, verdict="pending")
                await conn.execute(text("update mcp_servers set fingerprint = null where id = :i"), {"i": server_id})
            await self._event(ctx, trace, EventType.mcp_scan_finished, f"scan of {row['name']} failed: {error}", {"server": row["name"], "error": error}, "medium")
            raise ApiError("upstream_error", f"Could not scan this server: {error}")
        async with tenant_tx(self.engine, ctx.tenant_id) as conn:
            others = await registry.other_tools(conn, server_id)
        cfg = await self.scanner.config_for(ctx.tenant_id)
        report = await build_report(tools, cfg=cfg, declared=list(row["declared_capabilities"] or []), source_files=source_files, other_servers=others)
        fp = fingerprint(tools)
        async with tenant_tx(self.engine, ctx.tenant_id) as conn:
            current = (await registry.get_detail(conn, server_id))["verdict"]
            approved_now = current in {"approved", "approved_with_limits"}
            unchanged = (await registry.get(conn, server_id)).get("approved_fingerprint") == fp.hex()
            # approval is only ever given by a person: a changed approved server is suspended, a suspended one stays suspended, others keep their verdict
            new_verdict = "suspended" if approved_now and not unchanged else None
            await registry.save_scan(conn, server_id, [t.to_mcp() for t in tools], fp, report, verdict=new_verdict)
        sev: Severity = "high" if report["recommended_verdict"] == "rejected" else ("medium" if report["findings"] else "info")
        await self._event(ctx, trace, EventType.mcp_scan_finished, f"scan of {row['name']} finished: {report['recommended_verdict']} recommended",
                          {"server": row["name"], "recommended": report["recommended_verdict"], "findings": len(report["findings"]), "tools": len(tools), "fingerprint": fp.hex()}, sev)
        async with tenant_tx(self.engine, ctx.tenant_id) as conn:
            return await registry.get_detail(conn, server_id)

    # ── decisions by a person ────────────────────────────────────────────────────────────────────────────
    async def approve(self, ctx: TenantContext, server_id: UUID, allowed: list[str] | None, acknowledge: bool) -> dict[str, Any]:
        async with tenant_tx(self.engine, ctx.tenant_id) as conn:
            d = await registry.get_detail(conn, server_id)
            report = d["report"] or {}
            if not d["fingerprint"] or not report.get("fingerprint") or report["fingerprint"] != d["fingerprint"]:
                raise ApiError("conflict", "This server has no current scan. Scan it first.")
            if report.get("recommended_verdict") == "rejected" and not acknowledge:
                raise ApiError("conflict", "The scan recommends rejecting this server. Review the findings and confirm to approve it anyway.",
                               errors=[{"path": "acknowledge_findings", "message": "required"}])
            names = [t["name"] for t in d["tools"]]
            if allowed is not None and not set(allowed) <= set(names):
                raise ApiError("validation_failed", "allowed_tools lists tools the server does not have", errors=[{"path": "allowed_tools", "message": "unknown tool"}])
            chosen = allowed if allowed is not None else (report.get("recommended_allowed_tools") if report.get("recommended_verdict") == "approved_with_limits" else None)
            verdict = "approved_with_limits" if chosen is not None and set(chosen) != set(names) else "approved"
            await registry.set_verdict(conn, server_id, verdict, approved={"tools": d["tools"], "fingerprint": d["fingerprint"], "by": str(ctx.actor_id)},
                                       fingerprint=bytes.fromhex(d["fingerprint"]), allowed_tools=chosen if verdict == "approved_with_limits" else None)
        self._live.pop((str(ctx.tenant_id), str(server_id)), None)
        await self._event(ctx, new_trace_id(), EventType.mcp_scan_finished, f"MCP server {d['name']} {verdict.replace('_', ' ')} by a person", {"server": d["name"], "verdict": verdict, "fingerprint": d["fingerprint"]})
        async with tenant_tx(self.engine, ctx.tenant_id) as conn:
            return await registry.get_detail(conn, server_id)

    async def reject(self, ctx: TenantContext, server_id: UUID) -> dict[str, Any]:
        async with tenant_tx(self.engine, ctx.tenant_id) as conn:
            d = await registry.get(conn, server_id)
            await registry.set_verdict(conn, server_id, "rejected")
        self._live.pop((str(ctx.tenant_id), str(server_id)), None)
        await self._event(ctx, new_trace_id(), EventType.mcp_scan_finished, f"MCP server {d['name']} rejected by a person", {"server": d["name"], "verdict": "rejected"})
        async with tenant_tx(self.engine, ctx.tenant_id) as conn:
            return await registry.get_detail(conn, server_id)

    # ── drift ──────────────────────────────────────────────────────────────────────────────────────────
    async def check_drift(self, ctx: TenantContext, row: dict[str, Any], *, use_cache: bool = False) -> str:
        """Compare the server's live tool list with what was approved. Returns 'unchanged' | 'drifted' | 'unreachable'. Drift suspends the server."""
        key = (str(ctx.tenant_id), str(row["id"]))
        if use_cache and (hit := self._live.get(key)) and hit[0] > time.monotonic():
            return hit[1]
        if not row.get("url"):
            return "unchanged"
        try:
            live = await self.client(row).list_tools()
        except McpError as exc:
            log.warning("could not check MCP server %s: %s", row["name"], exc)
            self._live[key] = (time.monotonic() + self.unreachable_ttl, "unreachable")
            return "unreachable"
        status = "unchanged" if fingerprint(live) == bytes(row["approved_fingerprint"] or b"") else "drifted"
        if status == "drifted":
            approved = [Tool.from_mcp(t) for t in (row.get("tools") or [])]
            changes = diff_tools(approved, live)
            async with tenant_tx(self.engine, ctx.tenant_id) as conn:
                await registry.set_verdict(conn, row["id"], "suspended")
                await registry.save_scan(conn, row["id"], [t.to_mcp() for t in live], fingerprint(live), {"drift": {"changes": changes}})
            await self._event(ctx, new_trace_id(), EventType.mcp_drift_detected, f"MCP server {row['name']} changed after approval and was suspended",
                              {"server": row["name"], "changes": changes, "approved_fingerprint": bytes(row["approved_fingerprint"] or b"").hex(), "live_fingerprint": fingerprint(live).hex()}, "high")
        self._live[key] = (time.monotonic() + self.live_ttl, status)
        return status
