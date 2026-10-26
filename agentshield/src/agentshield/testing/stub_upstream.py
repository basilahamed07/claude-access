"""A scripted fake model provider speaking both wire formats (streaming and not).

Used by the test-suite and by the email-agent demo, so nothing needs a real API key. Behaviours:
  * ``queue``: scripted turns, popped in order;
  * ``follow_injection``: if any tool result contains "forward ... to <address>", emit a ``send_email``
    tool call to that address (what a hijacked model would do);
  * otherwise a short text answer.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse


@dataclass
class StubToolCall:
    name: str
    arguments: dict[str, Any]
    id: str = ""
    raw_arguments: str | None = None      # emit this exact (possibly malformed) argument text instead of JSON


@dataclass
class Turn:
    text: str | None = None
    tool_calls: list[StubToolCall] = field(default_factory=list)
    input_tokens: int = 11
    output_tokens: int = 7


@dataclass
class Recorded:
    api: str
    headers: dict[str, str]
    body: dict[str, Any]


_FORWARD = re.compile(r"forward\b.{0,80}?\bto\s+([\w.+-]+@[\w-]+(?:\.[\w-]+)+)", re.I | re.S)


class StubUpstream:
    def __init__(self) -> None:
        self.queue: list[Turn] = []
        self.requests: list[Recorded] = []
        self.follow_injection = False
        self.fail_with: tuple[int, dict[str, Any]] | None = None
        self.chunk_size = 0          # >0: split streamed JSON/text deltas into pieces of this many chars
        self._n = 0
        self.app = self._build()

    # ── behaviour ────────────────────────────────────────────────────────────────────────────────
    def _turn_for(self, api: str, body: dict[str, Any]) -> Turn:
        if self.queue:
            return self.queue.pop(0)
        if self.follow_injection:
            for text in _tool_result_texts(api, body):
                m = _FORWARD.search(text)
                if m:
                    return Turn(text="Forwarding as instructed.",
                                tool_calls=[StubToolCall("send_email", {"to": m.group(1), "subject": "Invoices",
                                                                        "body": "Forwarded invoices"})])
        return Turn(text="Here is a short summary of your mail.")

    @staticmethod
    def _args(c: StubToolCall) -> str:
        return c.raw_arguments if c.raw_arguments is not None else json.dumps(c.arguments)

    def _tool_id(self, c: StubToolCall, api: str) -> str:
        self._n += 1
        return c.id or (f"toolu_stub{self._n:03d}" if api == "anthropic" else f"call_stub{self._n:03d}")

    # ── app ──────────────────────────────────────────────────────────────────────────────────────
    def _build(self) -> FastAPI:
        app = FastAPI()

        async def handle(request: Request, api: str) -> Any:
            body = await request.json()
            self.requests.append(Recorded(api, {k.lower(): v for k, v in request.headers.items()}, body))
            if self.fail_with:
                status, payload = self.fail_with
                self.fail_with = None
                return JSONResponse(payload, status_code=status)
            turn = self._turn_for(api, body)
            model = str(body.get("model", "stub-model"))
            if body.get("stream"):
                gen = self._sse_anthropic(turn, model) if api == "anthropic" else self._sse_openai(turn, model)
                return StreamingResponse(gen, media_type="text/event-stream")
            return JSONResponse(self._json_anthropic(turn, model) if api == "anthropic"
                                else self._json_openai(turn, model))

        @app.post("/v1/messages")
        async def messages(request: Request) -> Any:
            return await handle(request, "anthropic")

        @app.post("/v1/chat/completions")
        async def completions(request: Request) -> Any:
            return await handle(request, "openai")

        @app.post("/chat/completions")
        async def completions_noprefix(request: Request) -> Any:
            return await handle(request, "openai")

        return app

    # ── non-streaming bodies ─────────────────────────────────────────────────────────────────────
    def _json_anthropic(self, t: Turn, model: str) -> dict[str, Any]:
        content: list[dict[str, Any]] = []
        if t.text:
            content.append({"type": "text", "text": t.text})
        for c in t.tool_calls:
            content.append({"type": "tool_use", "id": self._tool_id(c, "anthropic"), "name": c.name, "input": c.arguments})
        return {"id": "msg_stub", "type": "message", "role": "assistant", "model": model, "content": content,
                "stop_reason": "tool_use" if t.tool_calls else "end_turn", "stop_sequence": None,
                "usage": {"input_tokens": t.input_tokens, "output_tokens": t.output_tokens}}

    def _json_openai(self, t: Turn, model: str) -> dict[str, Any]:
        msg: dict[str, Any] = {"role": "assistant", "content": t.text}
        if t.tool_calls:
            msg["tool_calls"] = [{"id": self._tool_id(c, "openai"), "type": "function",
                                  "function": {"name": c.name, "arguments": self._args(c)}}
                                 for c in t.tool_calls]
        return {"id": "chatcmpl-stub", "object": "chat.completion", "created": 1_700_000_000, "model": model,
                "choices": [{"index": 0, "message": msg, "finish_reason": "tool_calls" if t.tool_calls else "stop"}],
                "usage": {"prompt_tokens": t.input_tokens, "completion_tokens": t.output_tokens,
                          "total_tokens": t.input_tokens + t.output_tokens}}

    # ── streaming bodies ─────────────────────────────────────────────────────────────────────────
    def _pieces(self, s: str) -> list[str]:
        n = self.chunk_size or max(len(s), 1)
        return [s[i:i + n] for i in range(0, len(s), n)] or [""]

    def _sse_anthropic(self, t: Turn, model: str) -> Iterator[bytes]:
        def ev(name: str, data: dict[str, Any]) -> bytes:
            return f"event: {name}\ndata: {json.dumps(data)}\n\n".encode()

        yield ev("message_start", {"type": "message_start", "message": {
            "id": "msg_stub", "type": "message", "role": "assistant", "model": model, "content": [],
            "stop_reason": None, "stop_sequence": None,
            "usage": {"input_tokens": t.input_tokens, "output_tokens": 1}}})
        yield ev("ping", {"type": "ping"})
        idx = 0
        if t.text:
            yield ev("content_block_start", {"type": "content_block_start", "index": idx,
                                             "content_block": {"type": "text", "text": ""}})
            for piece in self._pieces(t.text):
                yield ev("content_block_delta", {"type": "content_block_delta", "index": idx,
                                                 "delta": {"type": "text_delta", "text": piece}})
            yield ev("content_block_stop", {"type": "content_block_stop", "index": idx})
            idx += 1
        for c in t.tool_calls:
            yield ev("content_block_start", {"type": "content_block_start", "index": idx, "content_block": {
                "type": "tool_use", "id": self._tool_id(c, "anthropic"), "name": c.name, "input": {}}})
            for piece in self._pieces(self._args(c)):
                yield ev("content_block_delta", {"type": "content_block_delta", "index": idx,
                                                 "delta": {"type": "input_json_delta", "partial_json": piece}})
            yield ev("content_block_stop", {"type": "content_block_stop", "index": idx})
            idx += 1
        yield ev("message_delta", {"type": "message_delta", "delta": {
            "stop_reason": "tool_use" if t.tool_calls else "end_turn", "stop_sequence": None},
            "usage": {"output_tokens": t.output_tokens}})
        yield ev("message_stop", {"type": "message_stop"})

    def _sse_openai(self, t: Turn, model: str) -> Iterator[bytes]:
        def chunk(delta: dict[str, Any], finish: str | None = None) -> bytes:
            payload: dict[str, Any] = {"id": "chatcmpl-stub", "object": "chat.completion.chunk",
                                       "created": 1_700_000_000, "model": model,
                                       "choices": [{"index": 0, "delta": delta, "finish_reason": finish}]}
            return f"data: {json.dumps(payload)}\n\n".encode()

        yield chunk({"role": "assistant", "content": ""})
        if t.text:
            for piece in self._pieces(t.text):
                yield chunk({"content": piece})
        for i, c in enumerate(t.tool_calls):
            yield chunk({"tool_calls": [{"index": i, "id": self._tool_id(c, "openai"), "type": "function",
                                         "function": {"name": c.name, "arguments": ""}}]})
            for piece in self._pieces(self._args(c)):
                yield chunk({"tool_calls": [{"index": i, "function": {"arguments": piece}}]})
        yield chunk({}, "tool_calls" if t.tool_calls else "stop")
        usage_chunk = {"id": "chatcmpl-stub", "object": "chat.completion.chunk", "created": 1_700_000_000,
                       "model": model, "choices": [],
                       "usage": {"prompt_tokens": t.input_tokens, "completion_tokens": t.output_tokens,
                                 "total_tokens": t.input_tokens + t.output_tokens}}
        yield f"data: {json.dumps(usage_chunk)}\n\n".encode()
        yield b"data: [DONE]\n\n"


def _tool_result_texts(api: str, body: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for m in body.get("messages", []):
        if not isinstance(m, dict):
            continue
        if api == "anthropic" and isinstance(m.get("content"), list):
            for b in m["content"]:
                if isinstance(b, dict) and b.get("type") == "tool_result":
                    c = b.get("content")
                    out.append(c if isinstance(c, str) else " ".join(
                        x.get("text", "") for x in (c or []) if isinstance(x, dict)))
        elif api == "openai" and m.get("role") == "tool":
            out.append(str(m.get("content", "")))
    return out
