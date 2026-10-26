"""The injection-firewall pipeline (arch §2.2): normalize -> rules -> classifier -> judge -> verdict.

`scan()` is a pure function of (content, config). `ScanService` adds what needs I/O: per-tenant settings, an
isolated judge upstream, a result cache, session-risk accumulation and the audit event.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from sqlalchemy import text

from ..audit.emitter import Emitter
from ..audit.events import make_event
from ..contracts.admin import TenantSettings
from ..contracts.events import EventType, Severity
from ..contracts.scan import ScanFinding, ScanResult
from ..db.tenant_tx import tenant_tx
from ..observability import SCAN_LATENCY, timed
from ..policy.session_state import accumulate_risk, get_risk
from ..proxy.sessions import SessionRef
from ..proxy.upstream import UpstreamClient, UpstreamConfig
from ..tenants.context import TenantContext
from ..tenants.crypto import decrypt_secret
from .classifier import ClassifierHandle
from .judge import JudgeVerdict, judge_text
from .normalizer import Normalized, normalize, to_original_span
from .risk import risk_amount
from .rules import RuleHit, RuleSet, RuleStore, rule_score, run_rules

log = logging.getLogger("agentshield.scan")
CLEAN_BELOW = 0.35
MALICIOUS_AT = 0.80
REMOVED = "[removed by AgentShield]"
QUARANTINED = "[Content withheld by AgentShield: it appeared to contain instructions aimed at the AI agent that reads it.]"
OBFUSCATION = {"homoglyphs", "zero_width", "bidi_controls", "unicode_tags", "decoded_base64", "decoded_hex", "decoded_percent"}
JudgeFn = Callable[[str, str], Awaitable[JudgeVerdict | None]]


@dataclass
class ScanConfig:
    ruleset: RuleSet
    classifier: ClassifierHandle
    judge: JudgeFn | None = None
    on_malicious: str = "sanitize"


def sanitize_text(original: str, spans: list[tuple[int, int]]) -> str:
    merged: list[list[int]] = []
    for s, e in sorted(spans):
        if e <= s:
            continue
        if merged and s <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], e)
        else:
            merged.append([s, e])
    out, pos = [], 0
    for s, e in merged:
        out += [original[pos:s], REMOVED]
        pos = e
    out.append(original[pos:])
    return "".join(out)


def _finding_spans(norm: Normalized, hits: list[RuleHit]) -> list[tuple[int, int]]:
    return [to_original_span(norm, h.span, hidden=h.hidden) for h in hits if h.span[1] > h.span[0]]


async def scan(content: str | bytes, *, source: str, cfg: ScanConfig) -> ScanResult:
    raw_text = content.decode("utf-8", errors="replace") if isinstance(content, (bytes, bytearray)) else content
    with timed(SCAN_LATENCY.labels("normalizer").observe):
        norm = normalize(content) if len(raw_text) < 8_000 else await asyncio.to_thread(normalize, content)
    flags: list[str] = []
    if norm.unscannable:
        return ScanResult(verdict="suspicious", confidence=0.3, layers=["normalizer"], flags=["unscannable"],
                          ruleset=cfg.ruleset.version)
    if norm.truncated:
        flags.append("truncated")
    if norm.has_hidden:
        flags.append("hidden_content")
    if OBFUSCATION & set(norm.transforms):
        flags.append("obfuscated")

    with timed(SCAN_LATENCY.labels("rules").observe):
        hits = run_rules(norm, cfg.ruleset)
    rscore = rule_score(hits)
    layers = ["rules"]
    scores: dict[str, float] = {"rules": round(rscore, 3)}
    cscore = 0.0
    if cfg.classifier.active and rscore < MALICIOUS_AT:
        try:
            visible = norm.text + (("\n" + norm.hidden_text) if norm.hidden_text.strip() else "")
            with timed(SCAN_LATENCY.labels("classifier").observe):
                cscore = await cfg.classifier.ascore(visible)
            layers.append("classifier")
            scores["classifier"] = round(cscore, 3)
        except Exception:                                             # noqa: BLE001
            log.exception("classifier failed; continuing with rules only")
            flags.append("classifier_error")
    elif cfg.classifier.status == "degraded":
        flags.append("classifier_degraded")

    combined = max(rscore, cscore)
    if rscore >= CLEAN_BELOW and cscore >= 0.5:
        combined = min(1.0, combined + 0.1)                           # two independent layers agree
    if "unicode_tags" in norm.transforms:
        combined = max(combined, 0.6)                                 # smuggled tag characters have no legitimate use
    if "obfuscated" in flags and combined >= 0.3:
        combined = min(1.0, combined + 0.1)

    verdict_judge: JudgeVerdict | None = None
    hostility = combined
    if CLEAN_BELOW <= combined < MALICIOUS_AT:
        if cfg.judge is not None:
            with timed(SCAN_LATENCY.labels("judge").observe):
                verdict_judge = await cfg.judge(raw_text if len(raw_text) < 8_000 else norm.text, source)
        if verdict_judge is None:
            flags.append("judge_unavailable")
            verdict = "suspicious"
        else:
            layers.append("judge")
            if verdict_judge.timed_out:
                flags.append("judge_timeout")
            elif verdict_judge.error:
                flags.append("judge_error")
            if verdict_judge.verdict == "clean" and not verdict_judge.error:
                verdict, hostility = "clean", min(combined, 1 - verdict_judge.confidence)
            elif verdict_judge.verdict == "malicious":
                verdict, hostility = "malicious", max(combined, verdict_judge.confidence, MALICIOUS_AT)
            else:
                verdict, hostility = "suspicious", min(MALICIOUS_AT - 0.01, max(combined, 0.5 * verdict_judge.confidence + 0.25, CLEAN_BELOW))
    else:
        verdict = "malicious" if combined >= MALICIOUS_AT else "clean"

    findings = [ScanFinding(rule_id=h.rule_id, category=h.category, span=to_original_span(norm, h.span, hidden=h.hidden),
                            text=h.text, hidden=h.hidden, layer="rules") for h in hits]
    if cscore >= 0.5:
        findings.append(ScanFinding(rule_id="classifier", category="classifier", text=f"score {cscore:.2f}", layer="classifier"))
    if verdict_judge and not verdict_judge.error:
        findings.append(ScanFinding(rule_id="judge", category="judge", text=verdict_judge.reason, layer="judge"))

    sanitized, action = None, "passed"
    if verdict == "malicious":
        if cfg.on_malicious == "flag":
            action = "flagged"
        elif cfg.on_malicious == "quarantine":
            sanitized, action = QUARANTINED, "quarantined"
        else:
            spans = _finding_spans(norm, hits)
            if spans and not norm.truncated:
                sanitized, action = sanitize_text(raw_text, spans), "sanitized"
            else:                                                     # detected without a locatable span: withhold all
                sanitized, action = QUARANTINED, "quarantined"
    return ScanResult(verdict=verdict, confidence=round(hostility, 3), layers=layers,
                      findings=findings, sanitized_text=sanitized, flags=flags, scores=scores,
                      ruleset=cfg.ruleset.version, action=action)


@dataclass
class _TenantScanCfg:
    settings: TenantSettings
    judge_cfg: UpstreamConfig | None
    judge_key: str | None
    judge_model: str | None
    expires: float


class ScanService:
    def __init__(self, *, engine: Any, redis: Any, emitter: Emitter, rules: RuleStore, classifier: ClassifierHandle,
                 upstream: UpstreamClient, master_key: bytes, judge_timeout: float = 1.5, cache_ttl: int = 86_400,
                 cfg_ttl: float = 30.0, max_parallel: int = 4) -> None:
        self.engine, self.redis, self.emitter, self.rules = engine, redis, emitter, rules
        self.classifier, self.upstream, self.master_key = classifier, upstream, master_key
        self.judge_timeout, self.cache_ttl, self.cfg_ttl = judge_timeout, cache_ttl, cfg_ttl
        self._tenant: dict[str, _TenantScanCfg] = {}
        self._sem = asyncio.Semaphore(max_parallel)

    def invalidate(self, tenant_id: Any = None) -> None:
        self._tenant.pop(str(tenant_id), None) if tenant_id else self._tenant.clear()

    async def tenant_cfg(self, tenant_id: UUID | str) -> _TenantScanCfg:
        key = str(tenant_id)
        hit = self._tenant.get(key)
        if hit and hit.expires > time.monotonic():
            return hit
        from ..tenants import registry
        settings, judge_cfg, judge_key, judge_model = TenantSettings(), None, None, None
        try:
            async with tenant_tx(self.engine, tenant_id) as conn:
                row = await registry.get_tenant(conn)
                settings = TenantSettings.model_validate(row["settings"] or {})
                if settings.judge_upstream_id:
                    up = await registry.get_upstream_secret(conn, settings.judge_upstream_id)
                    judge_cfg = UpstreamConfig(id=str(up["id"]), name=up["name"], kind=up["kind"], base_url=up["base_url"],
                                               api_key=None, model_map=up["model_map"] or {}, judge_model=up["judge_model"])
                    judge_key = decrypt_secret(self.master_key, up["key_ciphertext"]) if up["key_ciphertext"] else None
                    first = judge_cfg.model_map[sorted(judge_cfg.model_map)[0]] if judge_cfg.model_map else None
                    judge_model = up["judge_model"] or (first.get("model") if isinstance(first, dict) else None)
        except Exception:                                              # noqa: BLE001  (defaults + no judge; scanning still works)
            log.exception("could not load scan settings")
        cfg = _TenantScanCfg(settings, judge_cfg, judge_key, judge_model, time.monotonic() + self.cfg_ttl)
        self._tenant[key] = cfg
        return cfg

    def _judge_fn(self, tcfg: _TenantScanCfg) -> JudgeFn | None:
        if tcfg.judge_cfg is None or not tcfg.judge_model:
            return None
        cfg, key, model = tcfg.judge_cfg, tcfg.judge_key, tcfg.judge_model

        async def run(text_: str, source: str) -> JudgeVerdict:
            return await judge_text(text_, self.upstream, cfg, key, model, source=source, timeout=self.judge_timeout)
        return run

    async def scan_content(self, ctx: TenantContext, *, trace_id: str, session: SessionRef | None, source: str,
                           content_id: str, text_: str, force: str | None = None) -> ScanResult:
        """Scan one piece of untrusted content, raise the session risk, audit it. Never raises."""
        try:
            tcfg = await self.tenant_cfg(ctx.tenant_id)
            ruleset = await self.rules.for_tenant(self.engine, ctx.tenant_id)
            on_mal = force or tcfg.settings.on_malicious
            digest = hashlib.sha256(text_.encode("utf-8", "replace")).hexdigest()
            ckey = f"scan:{ctx.tenant_id}:{ruleset.sha256[:12] or ruleset.version}:{self.classifier.name}:{on_mal}:{digest}"
            cached = await self.redis.get(ckey)
            if cached:
                res = ScanResult.model_validate_json(cached)
                res.flags = [*res.flags, "cached"]
                res.trace_id = trace_id
                if session is not None:
                    res.risk_score = await get_risk(self.redis, ctx.tenant_id, session.id, session.risk_score)
                return res
            async with self._sem:
                res = await scan(text_, source=source, cfg=ScanConfig(ruleset, self.classifier, self._judge_fn(tcfg), on_mal))
            await self.redis.set(ckey, res.model_dump_json(), ex=self.cache_ttl)
            before = after = 0.0
            if session is not None:
                before = await get_risk(self.redis, ctx.tenant_id, session.id, session.risk_score)
                amount = risk_amount(res.verdict, res.confidence)
                after = await accumulate_risk(self.redis, ctx.tenant_id, session.id, amount) if amount else before
                if amount:
                    await self._mirror_risk(ctx.tenant_id, session.id, after)
                res.risk_score = after
            res.trace_id = trace_id
            await self._audit(ctx, trace_id, session, source, content_id, text_, digest, res, before, after)
            return res
        except Exception:                                              # noqa: BLE001
            log.exception("scan failed")
            if session is not None:
                try:
                    await accumulate_risk(self.redis, ctx.tenant_id, session.id, 0.3)
                except Exception:                                      # noqa: BLE001
                    log.exception("could not raise session risk after a scan failure")
            await self.emitter.emit(make_event(ctx, trace_id, "injection", EventType.error,
                                               f"scan of {source} content failed; session risk raised",
                                               session=session, severity="high"), {"source": source, "id": content_id})
            return ScanResult(verdict="suspicious", confidence=0.5, layers=[], flags=["scan_error"], trace_id=trace_id)

    async def _mirror_risk(self, tenant_id: UUID, session_id: UUID, risk: float) -> None:
        async with tenant_tx(self.engine, tenant_id) as conn:
            await conn.execute(text("update sessions set risk_score = greatest(risk_score, :r) where id = :s"),
                               {"r": float(risk), "s": session_id})

    async def _audit(self, ctx: TenantContext, trace_id: str, session: SessionRef | None, source: str, content_id: str,
                     text_: str, digest: str, res: ScanResult, before: float, after: float) -> None:
        severity: Severity = {"malicious": "high", "suspicious": "medium", "clean": "info"}[res.verdict]  # type: ignore[assignment]
        top = next((f for f in res.findings if f.layer == "rules"), None)
        await self.emitter.emit(
            make_event(ctx, trace_id, "injection", EventType.content_scanned,
                       f"{source} content scanned: {res.verdict}" + (f" ({top.rule_id})" if top else ""),
                       session=session, rule_id=top.rule_id if top else None, severity=severity,
                       reason="; ".join(f"{f.layer}:{f.rule_id}" for f in res.findings[:5]) or None),
            {"source": source, "id": content_id, "bytes": len(text_.encode("utf-8", "replace")), "sha256": digest,
             "verdict": res.verdict, "hostility": res.confidence, "layers": res.layers, "scores": res.scores,
             "flags": res.flags, "ruleset": res.ruleset, "action": res.action, "classifier": self.classifier.name,
             "risk_before": round(before, 3), "risk_after": round(after, 3),
             "findings": [json.loads(f.model_dump_json()) for f in res.findings[:10]]})


_ = Severity
