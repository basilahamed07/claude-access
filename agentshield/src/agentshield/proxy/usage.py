"""Token usage and stop reason from provider responses (used for audit events and budgets)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .sse import SseParser
from .upstream import Api


@dataclass
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0
    stop_reason: str | None = None
    tool_calls: int = 0
    text_chars: int = 0

    def as_payload(self) -> dict[str, Any]:
        return {"input_tokens": self.input_tokens, "output_tokens": self.output_tokens,
                "stop_reason": self.stop_reason, "tool_calls": self.tool_calls, "text_chars": self.text_chars}


def usage_from_message(api: Api, body: dict[str, Any]) -> Usage:
    u = Usage()
    usage = body.get("usage") or {}
    if api == "anthropic":
        u.input_tokens = int(usage.get("input_tokens") or 0)
        u.output_tokens = int(usage.get("output_tokens") or 0)
        u.stop_reason = body.get("stop_reason")
        for b in body.get("content") or []:
            if isinstance(b, dict):
                if b.get("type") == "tool_use":
                    u.tool_calls += 1
                elif b.get("type") == "text":
                    u.text_chars += len(str(b.get("text", "")))
    else:
        u.input_tokens = int(usage.get("prompt_tokens") or 0)
        u.output_tokens = int(usage.get("completion_tokens") or 0)
        for ch in body.get("choices") or []:
            if isinstance(ch, dict):
                u.stop_reason = ch.get("finish_reason") or u.stop_reason
                msg = ch.get("message") or {}
                u.tool_calls += len(msg.get("tool_calls") or [])
                u.text_chars += len(msg.get("content") or "") if isinstance(msg.get("content"), str) else 0
    return u


class StreamObserver:
    """Feed it the bytes the CLIENT receives; read the usage when the stream ends."""

    def __init__(self, api: Api) -> None:
        self.api = api
        self.parser = SseParser()
        self.usage = Usage()
        self._openai_tools: set[tuple[int, int]] = set()

    def feed(self, chunk: bytes) -> None:
        for ev in self.parser.feed(chunk):
            obj = ev.json()
            if not isinstance(obj, dict):
                continue
            u = self.usage
            if self.api == "anthropic":
                t = obj.get("type")
                if t == "message_start":
                    u.input_tokens = int((obj.get("message", {}).get("usage") or {}).get("input_tokens") or 0)
                elif t == "content_block_start" and (obj.get("content_block") or {}).get("type") == "tool_use":
                    u.tool_calls += 1
                elif t == "content_block_delta" and (obj.get("delta") or {}).get("type") == "text_delta":
                    u.text_chars += len(obj["delta"].get("text", ""))
                elif t == "message_delta":
                    u.stop_reason = (obj.get("delta") or {}).get("stop_reason") or u.stop_reason
                    u.output_tokens = int((obj.get("usage") or {}).get("output_tokens") or u.output_tokens)
            else:
                if obj.get("usage"):
                    u.input_tokens = int(obj["usage"].get("prompt_tokens") or 0)
                    u.output_tokens = int(obj["usage"].get("completion_tokens") or 0)
                for ch in obj.get("choices") or []:
                    d = ch.get("delta") or {}
                    u.text_chars += len(d.get("content") or "")
                    for t in d.get("tool_calls") or []:
                        self._openai_tools.add((int(ch.get("index", 0)), int(t.get("index", 0))))
                    u.tool_calls = len(self._openai_tools)
                    u.stop_reason = ch.get("finish_reason") or u.stop_reason
