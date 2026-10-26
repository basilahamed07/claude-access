"""Anthropic Messages stream/body rewriting.

`tool_use` blocks are buffered from `content_block_start` to `content_block_stop`, judged, and then
either replayed byte-for-byte or replaced by a text block at the same index. Text deltas pass through
immediately. Nothing of a tool call that has not been allowed is ever written to the client.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any

from .sse import SseEvent, SseParser, format_event
from .tools import Allow, Replace, ToolCall, ToolJudge, parse_arguments

TRUNCATED_ERROR = {"type": "error", "error": {
    "type": "api_error",
    "message": "The model stream ended inside a tool call; AgentShield dropped the incomplete call."}}


@dataclass
class _OpenTool:
    start: SseEvent
    id: str
    name: str
    parts: list[str] = field(default_factory=list)
    raws: list[SseEvent] = field(default_factory=list)


def text_block_events(index: int, text: str) -> list[bytes]:
    return [
        format_event("content_block_start", {"type": "content_block_start", "index": index,
                                             "content_block": {"type": "text", "text": ""}}),
        format_event("content_block_delta", {"type": "content_block_delta", "index": index,
                                             "delta": {"type": "text_delta", "text": text}}),
        format_event("content_block_stop", {"type": "content_block_stop", "index": index}),
    ]


class _State:
    def __init__(self, judge: ToolJudge) -> None:
        self.judge = judge
        self.open: dict[int, _OpenTool] = {}
        self.allowed = 0
        self.replaced = 0

    async def handle(self, ev: SseEvent) -> list[bytes]:
        obj = ev.json()
        if not isinstance(obj, dict):
            return [ev.raw]
        kind = obj.get("type")
        index = obj.get("index")
        if kind == "content_block_start":
            block = obj.get("content_block") or {}
            if isinstance(index, int) and block.get("type") == "tool_use":
                self.open[index] = _OpenTool(start=ev, id=str(block.get("id", "")), name=str(block.get("name", "")))
                return []
            return [ev.raw]
        if kind == "content_block_delta" and isinstance(index, int) and index in self.open:
            tool = self.open[index]
            delta = obj.get("delta") or {}
            if delta.get("type") == "input_json_delta":
                tool.parts.append(str(delta.get("partial_json", "")))
            tool.raws.append(ev)
            return []
        if kind == "content_block_stop" and isinstance(index, int) and index in self.open:
            return await self._finish(index, ev)
        if kind in {"message_delta", "message_stop"} and self.open:
            out = self._drop_open()
            return out + await self._tail(ev, obj)
        if kind == "message_delta":
            return await self._tail(ev, obj)
        return [ev.raw]

    async def _finish(self, index: int, stop: SseEvent) -> list[bytes]:
        tool = self.open.pop(index)
        raw_args = "".join(tool.parts)
        call = ToolCall(id=tool.id, name=tool.name, arguments=parse_arguments(raw_args), raw_arguments=raw_args)
        verdict = await self.judge(call)
        if isinstance(verdict, Allow):
            self.allowed += 1
            return [tool.start.raw, *(e.raw for e in tool.raws), stop.raw]
        assert isinstance(verdict, Replace)
        self.replaced += 1
        return text_block_events(index, verdict.text)

    def _drop_open(self) -> list[bytes]:
        self.open.clear()
        return [format_event("error", TRUNCATED_ERROR)]

    async def _tail(self, ev: SseEvent, obj: dict[str, Any]) -> list[bytes]:
        if obj.get("type") == "message_delta" and self.replaced and not self.allowed:
            delta = obj.get("delta") or {}
            if delta.get("stop_reason") == "tool_use":
                delta["stop_reason"] = "end_turn"
                obj["delta"] = delta
                return [format_event(ev.event, obj)]
        return [ev.raw]


async def rewrite_anthropic(stream: AsyncIterator[bytes], judge: ToolJudge) -> AsyncIterator[bytes]:
    parser, state = SseParser(), _State(judge)
    async for chunk in stream:
        for ev in parser.feed(chunk):
            for out in await state.handle(ev):
                yield out
    rest = parser.remainder()
    if state.open:
        yield format_event("error", TRUNCATED_ERROR)
    elif rest:
        yield rest


async def rewrite_anthropic_message(body: dict[str, Any], judge: ToolJudge) -> tuple[dict[str, Any], bool]:
    """Non-streaming equivalent. Returns (body, changed)."""
    content = body.get("content")
    if not isinstance(content, list):
        return body, False
    new_content: list[Any] = []
    allowed = replaced = 0
    for block in content:
        if isinstance(block, dict) and block.get("type") == "tool_use":
            args = block.get("input")
            call = ToolCall(id=str(block.get("id", "")), name=str(block.get("name", "")),
                            arguments=args if isinstance(args, dict) else None,
                            raw_arguments=json.dumps(args) if args is not None else "")
            verdict = await judge(call)
            if isinstance(verdict, Replace):
                replaced += 1
                new_content.append({"type": "text", "text": verdict.text})
                continue
            allowed += 1
        new_content.append(block)
    if not replaced:
        return body, False
    out = {**body, "content": new_content}
    if not allowed and out.get("stop_reason") == "tool_use":
        out["stop_reason"] = "end_turn"
    return out, True
