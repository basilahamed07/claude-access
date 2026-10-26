"""Signature rules: fast, explainable first layer of the injection firewall (arch §2.2, M2 layer 1).

Rules are weighted regexes with categories, descriptions and executable positive/negative examples.
Weights are the standalone confidence that a match is a steering attempt. Matches are discounted when they
sit inside quotation or "training/example" context (visible text only) and boosted when found in hidden text.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from importlib import resources
from typing import Any

import regex
import yaml

from .normalizer import Normalized

REGEX_TIMEOUT = 0.05
MAX_HITS_PER_RULE = 5
HIDDEN_BOOST = 0.1
CONTEXT_DISCOUNT = 0.5
SCAN_LIMIT = 200_000
_QUOTES = "\"'“”‘’«»`"
_CONTEXT = regex.compile(
    r"(?i)\b(?:for example|for instance|e\.g\.|such as|example|attackers?|phishing|social engineering|prompt injection|"
    r"jailbreak(?:s|ing)?|security (?:awareness|training)|training|awareness|beware|warning|suspicious|"
    r"red flags?|how to (?:spot|detect|recognis?e)|detect(?:ing|ion)?|don'?t (?:fall|click|trust))\b")


class RuleSetError(ValueError):
    def __init__(self, errors: list[str]) -> None:
        super().__init__("; ".join(errors))
        self.errors = errors


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    weight: float
    pattern: Any
    description: str = ""
    positive: tuple[str, ...] = ()
    negative: tuple[str, ...] = ()


@dataclass(frozen=True)
class RuleSet:
    version: str
    rules: tuple[Rule, ...]
    sha256: str = ""

    def by_id(self) -> dict[str, Rule]:
        return {r.id: r for r in self.rules}


@dataclass(frozen=True)
class RuleHit:
    rule_id: str
    category: str
    weight: float                       # effective weight after discount / boost
    span: tuple[int, int]               # in normalized `text` (or `hidden_text` when hidden=True)
    text: str
    hidden: bool = False
    quoted: bool = False


def load_ruleset(yaml_text: str, *, version: str | None = None) -> RuleSet:
    try:
        data = yaml.safe_load(yaml_text)
    except yaml.YAMLError as exc:
        raise RuleSetError([f"invalid YAML: {exc}"]) from exc
    if not isinstance(data, dict) or not isinstance(data.get("rules"), list):
        raise RuleSetError(["a rule set must be a mapping with a 'rules' list"])
    errors: list[str] = []
    rules: list[Rule] = []
    seen: set[str] = set()
    for i, raw in enumerate(data["rules"]):
        where = f"rules[{i}]"
        if not isinstance(raw, dict):
            errors.append(f"{where}: must be a mapping")
            continue
        rid = str(raw.get("id", ""))
        where = f"rule '{rid or i}'"
        if not rid or rid in seen:
            errors.append(f"{where}: missing or duplicate id")
        seen.add(rid)
        weight = raw.get("weight")
        if not isinstance(weight, (int, float)) or isinstance(weight, bool) or not 0 < weight <= 1:
            errors.append(f"{where}: weight must be a number in (0, 1]")
            continue
        try:
            pat = regex.compile(str(raw.get("pattern", "")))
        except regex.error as exc:
            errors.append(f"{where}: invalid pattern: {exc}")
            continue
        if not raw.get("pattern") or pat.match("") is not None and pat.fullmatch("") is not None:
            errors.append(f"{where}: pattern must not match the empty string")
            continue
        ex = raw.get("examples") or {}
        rules.append(Rule(rid, str(raw.get("category", "other")), float(weight), pat, str(raw.get("description", "")),
                          tuple(map(str, ex.get("positive") or ())), tuple(map(str, ex.get("negative") or ()))))
    if errors:
        raise RuleSetError(errors)
    digest = hashlib.sha256(yaml_text.encode()).hexdigest()
    return RuleSet(version or digest[:8], tuple(rules), digest)


def disabled_ids(yaml_text: str) -> set[str]:
    try:
        data = yaml.safe_load(yaml_text)
    except yaml.YAMLError:
        return set()
    return {str(x) for x in (data or {}).get("disable", [])} if isinstance(data, dict) else set()


def merge(base: RuleSet, extra: RuleSet | None, disable: set[str] | None = None, *, label: str = "") -> RuleSet:
    if extra is None and not disable:
        return base
    merged = {r.id: r for r in base.rules if r.id not in (disable or set())}
    for r in extra.rules if extra else ():
        merged[r.id] = r
    return RuleSet(f"{base.version}+{label or (extra.version if extra else 'custom')}", tuple(merged.values()),
                   hashlib.sha256((base.sha256 + (extra.sha256 if extra else "") + ",".join(sorted(disable or ()))).encode()).hexdigest())


def default_ruleset() -> RuleSet:
    text = (resources.files("agentshield.scan") / "rules_default.yaml").read_text()
    return load_ruleset(text, version=f"default-{hashlib.sha256(text.encode()).hexdigest()[:8]}")


def _in_quotes(text: str, start: int, end: int) -> bool:
    left = text[max(0, start - 3):start].rstrip(" \t")
    right = text[end:end + 3].lstrip(" \t")
    return bool(left and left[-1] in _QUOTES and right and right[0] in _QUOTES)


def _discount_context(text: str, start: int, end: int) -> bool:
    window = text[max(0, start - 140):start]
    try:
        return _in_quotes(text, start, end) or bool(_CONTEXT.search(window, timeout=REGEX_TIMEOUT))
    except TimeoutError:
        return False


def run_rules(norm: Normalized, ruleset: RuleSet) -> list[RuleHit]:
    hits: list[RuleHit] = []
    channels = ((norm.text[:SCAN_LIMIT], False), (norm.hidden_text[:SCAN_LIMIT], True))
    for rule in ruleset.rules:
        for text, hidden in channels:
            if not text:
                continue
            n = 0
            try:
                for m in rule.pattern.finditer(text, timeout=REGEX_TIMEOUT):
                    weight, quoted = rule.weight, False
                    if hidden:
                        weight = min(1.0, weight + HIDDEN_BOOST)
                    elif _discount_context(text, m.start(), m.end()):
                        weight, quoted = weight * CONTEXT_DISCOUNT, True
                    hits.append(RuleHit(rule.id, rule.category, round(weight, 3), (m.start(), m.end()),
                                        m.group(0)[:300], hidden, quoted))
                    n += 1
                    if n >= MAX_HITS_PER_RULE:
                        break
            except TimeoutError:
                # a pathological input slowed this rule down: report it conservatively rather than skip silently
                hits.append(RuleHit(f"{rule.id}:timeout", rule.category, min(rule.weight, 0.5), (0, 0), "", hidden))
    return hits


def rule_score(hits: list[RuleHit]) -> float:
    """Strongest hit, plus 0.1 for every additional distinct category (corroboration), capped at 1."""
    real = [h for h in hits if not h.rule_id.endswith(":timeout")] or hits
    if not real:
        return 0.0
    categories = {h.category for h in real}
    return min(1.0, max(h.weight for h in real) + 0.1 * (len(categories) - 1))


@dataclass
class RuleStore:
    """Effective rule set per tenant: packaged defaults, an optional platform override and tenant additions.
    Re-read from the database at most every `refresh_seconds`, and immediately on `invalidate`."""

    refresh_seconds: float = 60.0
    base: RuleSet = field(default_factory=default_ruleset)
    _cache: dict[str, tuple[float, RuleSet]] = field(default_factory=dict)

    def invalidate(self, tenant_id: Any | None = None) -> None:
        if tenant_id is None:
            self._cache.clear()
        else:
            self._cache.pop(str(tenant_id), None)

    async def for_tenant(self, engine: Any, tenant_id: Any) -> RuleSet:
        key = str(tenant_id)
        hit = self._cache.get(key)
        if hit and hit[0] > time.monotonic():
            return hit[1]
        from sqlalchemy import text

        from ..db.tenant_tx import tenant_tx
        platform_yaml = tenant_yaml = None
        try:
            async with tenant_tx(engine, tenant_id) as conn:
                rows = (await conn.execute(text(
                    "select tenant_id, yaml from scan_rule_sets where active order by version desc"))).all()
            for tid, y in rows:
                if tid is None and platform_yaml is None:
                    platform_yaml = y
                elif tid is not None and tenant_yaml is None:
                    tenant_yaml = y
            base = load_ruleset(platform_yaml, version="platform") if platform_yaml else self.base
            rs = base
            if tenant_yaml:
                rs = merge(base, load_ruleset(tenant_yaml, version="tenant"), disabled_ids(tenant_yaml), label="tenant")
        except Exception:                                              # noqa: BLE001  (a broken override must not disable scanning)
            rs = hit[1] if hit else self.base
        self._cache[key] = (time.monotonic() + self.refresh_seconds, rs)
        return rs
