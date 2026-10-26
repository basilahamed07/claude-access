"""OpenAI Chat Completions stream/body rewriting.

Tool-call deltas are buffered per (choice, tool index) until the choice reports a finish reason, then
judged. Allowed calls are re-emitted as consolidated chunks (renumbered contiguously); replaced calls
become content text. Role/content chunks pass through untouched.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any

from .sse import SseEvent, SseParser, format_event
from .tools import Allow, Replace, ToolCall, ToolJudge, parse_arguments

TRUNCATED_ERROR = {"error": {
    "message": "The model stream ended inside a tool call; AgentShield dropped the incomplete call.",
    "type": "server_error", "param": None, "code": "upstream_error"}}


@dataclass
class _Tool:
    id: str = ""
    name: str = ""
    args: list[str] = field(default_factory=list)


def _chunk(base: dict[str, Any], choice_index: int, delta: dict[str, Any], finish: str | None = None) -> bytes:
    return format_event(None, {**base, "choices": [{"index": choice_index, "delta": delta, "finish_reason": finish}]})


class _State:
    def __init__(self, judge: ToolJudge) -> None:
        self.judge = judge
        self.tools: dict[int, dict[int, _Tool]] = {}
        self.allowed: dict[int, int] = {}
        self.replaced: dict[int, int] = {}

    async def handle(self, ev: SseEvent) -> list[bytes]:
        if ev.data.strip() == "[DONE]":
            truncated = [format_event(None, TRUNCATED_ERROR)] if self.tools else []
            self.tools.clear()
            return [*truncated, ev.raw]
        obj = ev.json()
        if not isinstance(obj, dict) or not isinstance(obj.get("choices"), list) or not obj["choices"]:
            return [ev.raw]
        out: list[bytes] = []
        modified = False
        base = {k: v for k, v in obj.items() if k not in {"choices", "usage"}}
        for ch in obj["choices"]:
            if not isinstance(ch, dict):
                continue
            ci = int(ch.get("index", 0))
            delta = ch.get("delta") or {}
            if isinstance(delta, dict) and delta.get("tool_calls"):
                modified = True
                self._buffer(ci, delta.pop("tool_calls"))
            finish = ch.get("finish_reason")
            if finish:
                flushed = await self._flush(ci, base)
                if flushed:
                    modified = True
                    out += flushed
                if self.replaced.get(ci) and not self.allowed.get(ci) and finish == "tool_calls":
                    ch["finish_reason"] = "stop"
                    modified = True
        if not modified:
            return [ev.raw]
        # forward what is left of the chunk (role/content/finish/usage) if anything is
        remaining = [c for c in obj["choices"] if isinstance(c, dict) and (
            c.get("finish_reason") or c.get("delta"))]
        if remaining or obj.get("usage"):
            obj["choices"] = remaining
            out.append(format_event(ev.event, obj))
        return out

    def _buffer(self, ci: int, deltas: Any) -> None:
        bucket = self.tools.setdefault(ci, {})
        for d in deltas if isinstance(deltas, list) else []:
            if not isinstance(d, dict):
                continue
            tool = bucket.setdefault(int(d.get("index", 0)), _Tool())
            if d.get("id"):
                tool.id = str(d["id"])
            fn = d.get("function") or {}
            if fn.get("name"):
                tool.name += str(fn["name"])
            if fn.get("arguments"):
                tool.args.append(str(fn["arguments"]))

    async def _flush(self, ci: int, base: dict[str, Any]) -> list[bytes]:
        out: list[bytes] = []
        bucket = self.tools.pop(ci, {})
        new_index = 0
        for _, tool in sorted(bucket.items()):
            raw = "".join(tool.args)
            call = ToolCall(id=tool.id, name=tool.name, arguments=parse_arguments(raw), raw_arguments=raw)
            verdict = await self.judge(call)
            if isinstance(verdict, Allow):
                self.allowed[ci] = self.allowed.get(ci, 0) + 1
                out.append(_chunk(base, ci, {"tool_calls": [{"index": new_index, "id": tool.id, "type": "function",
                                                              "function": {"name": tool.name, "arguments": ""}}]}))
                out.append(_chunk(base, ci, {"tool_calls": [{"index": new_index, "function": {"arguments": raw}}]}))
                new_index += 1
            else:
                assert isinstance(verdict, Replace)
                self.replaced[ci] = self.replaced.get(ci, 0) + 1
                out.append(_chunk(base, ci, {"content": verdict.text}))
        return out


async def rewrite_openai(stream: AsyncIterator[bytes], judge: ToolJudge) -> AsyncIterator[bytes]:
    parser, state = SseParser(), _State(judge)
    async for chunk in stream:
        for ev in parser.feed(chunk):
            for out in await state.handle(ev):
                yield out
    rest = parser.remainder()
    if state.tools:
        yield format_event(None, TRUNCATED_ERROR)
    elif rest:
        yield rest


async def rewrite_openai_message(body: dict[str, Any], judge: ToolJudge) -> tuple[dict[str, Any], bool]:
    choices = body.get("choices")
    if not isinstance(choices, list):
        return body, False
    changed = False
    new_choices: list[Any] = []
    for ch in choices:
        msg = ch.get("message") if isinstance(ch, dict) else None
        calls = msg.get("tool_calls") if isinstance(msg, dict) else None
        if not isinstance(ch, dict) or not isinstance(msg, dict) or not isinstance(calls, list) or not calls:
            new_choices.append(ch)
            continue
        kept: list[Any] = []
        notes: list[str] = []
        for tc in calls:
            fn = tc.get("function", {}) if isinstance(tc, dict) else {}
            raw = fn.get("arguments", "") if isinstance(fn.get("arguments", ""), str) else json.dumps(fn.get("arguments"))
            call = ToolCall(id=str(tc.get("id", "")) if isinstance(tc, dict) else "", name=str(fn.get("name", "")),
                            arguments=parse_arguments(raw), raw_arguments=raw)
            verdict = await judge(call)
            if isinstance(verdict, Replace):
                notes.append(verdict.text)
            else:
                kept.append(tc)
        if not notes:
            new_choices.append(ch)
            continue
        changed = True
        new_msg = {**msg}
        existing = msg.get("content")
        new_msg["content"] = "\n".join(([existing] if isinstance(existing, str) and existing else []) + notes)
        if kept:
            new_msg["tool_calls"] = kept
        else:
            new_msg.pop("tool_calls", None)
        new_ch = {**ch, "message": new_msg}
        if not kept and ch.get("finish_reason") == "tool_calls":
            new_ch["finish_reason"] = "stop"
        new_choices.append(new_ch)
    return ({**body, "choices": new_choices}, True) if changed else (body, False)
