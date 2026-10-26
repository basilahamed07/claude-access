"""Redaction that runs BEFORE any event is published (a log full of secrets is a new risk).

Secrets, tokens and card numbers are always masked as ``[REDACTED:<kind>:<sha8>]`` (the 8-hex digest
lets analysts correlate repeats without recovering the value). With ``pii=True`` e-mail local parts and
phone numbers are masked too; e-mail *domains* are kept because the domain is the security-relevant
evidence (where was the agent about to send data?).
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

SENSITIVE_KEYS = re.compile(
    r"^(authorization|proxy-authorization|x-api-key|api[_-]?key|apikey|x-upstream-authorization|password|passwd|"
    r"secret|client[_-]?secret|token|access[_-]?token|refresh[_-]?token|id[_-]?token|cookie|set-cookie|"
    r"private[_-]?key|session[_-]?token)$", re.I)

_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("anthropic_key", re.compile(r"sk-ant-[A-Za-z0-9_-]{16,}")),
    ("openai_key", re.compile(r"sk-(?:proj-|live-|test-)?[A-Za-z0-9_-]{16,}")),
    ("agentshield_key", re.compile(r"\bask_live_[A-Za-z0-9_-]{8,}")),
    ("agentshield_token", re.compile(r"\basu_[A-Za-z0-9_-]{12,}")),
    ("aws_key", re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{20,})")),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("google_key", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("bearer", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{16,}")),
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)")),
]
_EMAIL = re.compile(r"([A-Za-z0-9._%+-]+)@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)")
_PHONE = [re.compile(r"(?<![\w])\+\d{1,3}[\s.-]?\(?\d{2,4}\)?[\s.-]?\d{3,4}[\s.-]?\d{3,4}(?![\w])"),
          re.compile(r"(?<![\w])\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}(?![\w])")]
_CARD = re.compile(r"(?<![\w-])(?:\d[ -]?){12,18}\d(?![\w-])")


def _tag(kind: str, value: str) -> str:
    return f"[REDACTED:{kind}:{hashlib.sha256(value.encode()).hexdigest()[:8]}]"


def luhn_ok(digits: str) -> bool:
    if not 13 <= len(digits) <= 19:
        return False
    total, alt = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


@dataclass
class Redacted:
    value: Any
    kinds: list[str]


def redact_text(text: str, kinds: list[str], *, pii: bool = True) -> str:
    for kind, pattern in _SECRET_PATTERNS:
        def sub(m: re.Match[str], kind: str = kind) -> str:
            kinds.append(kind)
            return _tag(kind, m.group(0))
        text = pattern.sub(sub, text)

    def card(m: re.Match[str]) -> str:
        digits = re.sub(r"\D", "", m.group(0))
        if luhn_ok(digits):
            kinds.append("card")
            return _tag("card", digits)
        return m.group(0)
    text = _CARD.sub(card, text)
    if pii:
        def email(m: re.Match[str]) -> str:
            kinds.append("email")
            return f"{_tag('email', m.group(1).lower())}@{m.group(2)}"
        text = _EMAIL.sub(email, text)
        for pat in _PHONE:
            def phone(m: re.Match[str]) -> str:
                kinds.append("phone")
                return _tag("phone", re.sub(r"\D", "", m.group(0)))
            text = pat.sub(phone, text)
    return text


def _walk(value: Any, kinds: list[str], pii: bool, depth: int) -> Any:
    if depth > 40:
        return "[REDACTED:too_deep]"
    if isinstance(value, str):
        return redact_text(value, kinds, pii=pii)
    if isinstance(value, Mapping):
        out: dict[Any, Any] = {}
        for k, v in value.items():
            if isinstance(k, str) and SENSITIVE_KEYS.match(k) and v not in (None, "", False):
                kinds.append("secret_field")
                out[k] = _tag("secret_field", str(v))
            else:
                out[k] = _walk(v, kinds, pii, depth + 1)
        return out
    if isinstance(value, (list, tuple)):
        return [_walk(v, kinds, pii, depth + 1) for v in value]
    if isinstance(value, bytes):
        return _tag("bytes", value.hex()[:64])
    return value


def redact(value: Any, *, pii: bool = True) -> Redacted:
    kinds: list[str] = []
    return Redacted(_walk(value, kinds, pii, 0), sorted(set(kinds)))
