"""Shared vocabulary: the three decisions and the six tool effect tags (arch §2.1, §7.4)."""

from __future__ import annotations

from enum import StrEnum


class Decision(StrEnum):
    allow = "allow"
    block = "block"
    ask = "ask"


class EffectTag(StrEnum):
    read = "read"
    write = "write"
    destructive = "destructive"
    external = "external"
    financial = "financial"
    execute = "execute"


# Only `read` tools may fail open when AgentShield cannot decide (arch §8.6).
FAIL_OPEN_TAGS: frozenset[EffectTag] = frozenset({EffectTag.read})
# A tool with no tag is treated as `external`, the safest non-blocking assumption.
DEFAULT_TAG = EffectTag.external


def fails_open(tag: EffectTag | None) -> bool:
    return (tag or DEFAULT_TAG) in FAIL_OPEN_TAGS
