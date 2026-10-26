"""Which parts of a model request are untrusted content (arch §7.2a): tool results, plus anything the
agent explicitly marks. System and user messages are trusted."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

Api = Literal["anthropic", "openai"]


@dataclass(frozen=True)
class UntrustedPart:
    message_index: int
    block_index: int | None       # None for OpenAI tool messages and string content
    source: str
    id: str
    text: str


def _flatten(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(b["text"] for b in content if isinstance(b, dict) and isinstance(b.get("text"), str))
    return ""


def extract_untrusted(api: Api, body: dict[str, Any]) -> list[UntrustedPart]:
    parts: list[UntrustedPart] = []
    messages = body.get("messages")
    if not isinstance(messages, list):
        return parts
    for mi, msg in enumerate(messages):
        if not isinstance(msg, dict):
            continue
        if api == "anthropic":
            content = msg.get("content")
            if msg.get("role") == "user" and isinstance(content, list):
                for bi, block in enumerate(content):
                    if isinstance(block, dict) and block.get("type") == "tool_result":
                        parts.append(UntrustedPart(mi, bi, "tool_result", str(block.get("tool_use_id", f"m{mi}b{bi}")),
                                                   _flatten(block.get("content"))))
        elif msg.get("role") == "tool":
            parts.append(UntrustedPart(mi, None, "tool_result", str(msg.get("tool_call_id", f"m{mi}")),
                                       _flatten(msg.get("content"))))
    return parts
