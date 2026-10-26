"""Types shared by the stream and message rewriters."""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any] | None      # None when the model produced unparsable / non-object JSON
    raw_arguments: str = ""


@dataclass(frozen=True)
class Allow:
    pass


@dataclass(frozen=True)
class Replace:
    """Swap the tool call for this text (a block or an approval notice)."""

    text: str


ALLOW = Allow()
ToolJudgement = Allow | Replace
ToolJudge = Callable[[ToolCall], Awaitable[ToolJudgement]]


async def allow_all(_call: ToolCall) -> ToolJudgement:
    return ALLOW


def parse_arguments(raw: str) -> dict[str, Any] | None:
    if not raw.strip():
        return {}
    try:
        value = json.loads(raw)
    except ValueError:
        return None
    return value if isinstance(value, dict) else None
