import asyncio
import json
from pathlib import Path

import pytest

from agentshield.proxy.openai_stream import rewrite_openai, rewrite_openai_message
from agentshield.proxy.sse import SseParser
from agentshield.proxy.tools import ALLOW, Replace, ToolCall

FIX = Path(__file__).resolve().parent.parent / "fixtures" / "openai"
BLOCK_TEXT = "Action blocked by AgentShield: not allowed (rule deny-external-send, trace t-1)"
FIXTURES = ["text_only", "tool_only", "mixed_two_tools", "docs_example_single_chunk_tool"]


def load(name: str) -> bytes:
    return (FIX / f"{name}.sse").read_bytes()


async def feed(data: bytes, size: int):
    for i in range(0, len(data), size):
        await asyncio.sleep(0)
        yield data[i:i + size]


async def allow_all(call):
    return ALLOW


def block(*names: str):
    async def judge(call: ToolCall):
        return Replace(BLOCK_TEXT) if call.name in names else ALLOW
    return judge


async def run(data: bytes, judge, size: int = 64):
    seen: list[ToolCall] = []

    async def wrapped(call):
        seen.append(call)
        return await judge(call)

    out = b"".join([c async for c in rewrite_openai(feed(data, size), wrapped)])
    return out, seen


def reassemble(raw: bytes):
    """Fold a chat.completion.chunk stream into (content, tool_calls, finish_reason)."""
    content, tools, finish = "", {}, None
    for e in SseParser().feed(raw):
        j = e.json()
        if not isinstance(j, dict):
            continue
        for ch in j.get("choices", []):
            d = ch.get("delta") or {}
            content += d.get("content") or ""
            for tc in d.get("tool_calls") or []:
                t = tools.setdefault(tc["index"], {"id": "", "name": "", "args": ""})
                t["id"] = tc.get("id") or t["id"]
                fn = tc.get("function") or {}
                t["name"] += fn.get("name") or ""
                t["args"] += fn.get("arguments") or ""
            finish = ch.get("finish_reason") or finish
    return content, [tools[i] for i in sorted(tools)], finish


@pytest.mark.parametrize("name", ["text_only"])
@pytest.mark.parametrize("size", [1, 5, 100_000])
async def test_text_only_stream_is_byte_identical(name, size):
    data = load(name)
    out, _ = await run(data, allow_all, size)
    assert out == data


@pytest.mark.parametrize("name", FIXTURES)
@pytest.mark.parametrize("size", [1, 3, 64])
async def test_allowed_tool_streams_are_semantically_identical(name, size):
    data = load(name)
    out, _ = await run(data, allow_all, size)
    assert reassemble(out) == reassemble(data)
    assert out.rstrip().endswith(b"data: [DONE]")


async def test_judge_gets_parsed_arguments_when_split_across_deltas():
    _, seen = await run(load("tool_only"), allow_all, 1)
    assert [(c.id, c.name, c.arguments["to"]) for c in seen] == [("call_stub001", "send_email", "x@unknown.com")] \
        or seen[0].name == "send_email"
    assert seen[0].arguments == {"to": "x@unknown.com", "subject": "Invoices", "body": "Secret invoice data"}


async def test_blocked_tool_becomes_content_and_finish_reason_stop():
    out, _ = await run(load("tool_only"), block("send_email"), 5)
    content, tools, finish = reassemble(out)
    assert content == BLOCK_TEXT and tools == [] and finish == "stop"
    assert b"send_email" not in out and b"x@unknown.com" not in out and b"Secret invoice data" not in out


async def test_mixed_turn_keeps_allowed_tool_renumbered_and_finish_tool_calls():
    out, seen = await run(load("mixed_two_tools"), block("read_email"), 4)    # block the FIRST, keep the second
    content, tools, finish = reassemble(out)
    assert content.endswith(BLOCK_TEXT) and content.startswith("Doing two things.")
    assert [t["name"] for t in tools] == ["send_email"] and tools[0]["id"] and finish == "tool_calls"
    assert json.loads(tools[0]["args"])["to"] == "attacker@evil.example"
    # surviving tool is re-indexed to 0
    first_tool_chunk = next(SseParser().feed(out)[i].json() for i in range(100)
                            if (SseParser().feed(out)[i].json() or {}).get("choices")
                            and (SseParser().feed(out)[i].json()["choices"][0].get("delta") or {}).get("tool_calls"))
    assert first_tool_chunk["choices"][0]["delta"]["tool_calls"][0]["index"] == 0


@pytest.mark.parametrize("name", ["tool_only", "mixed_two_tools", "docs_example_single_chunk_tool"])
@pytest.mark.parametrize("size", [1, 2, 3, 5, 7, 11, 64])
async def test_blocked_tool_never_leaks_under_any_chunking(name, size):
    out, _ = await run(load(name), block("send_email"), size)
    for needle in (b"send_email", b"x@unknown.com", b"Secret invoice", b"attacker@evil.example", b"LEAKED", b"call_abc"):
        assert needle not in out, needle


async def test_single_chunk_tool_with_finish_reason_is_judged_before_finish_is_forwarded():
    out, _ = await run(load("docs_example_single_chunk_tool"), block("send_email"), 9)
    content, tools, finish = reassemble(out)
    assert content == BLOCK_TEXT and tools == [] and finish == "stop"
    assert b'"usage"' in out and out.rstrip().endswith(b"data: [DONE]")    # trailing usage chunk preserved


async def test_stream_cut_inside_tool_call_drops_it():
    data = load("tool_only")
    cut = data.index(b'"finish_reason": "tool_calls"') - 80
    out, seen = await run(data[:cut], allow_all, 6)
    assert seen == [] and b"send_email" not in out and b"server_error" in out


async def test_malformed_arguments_are_judged_with_none():
    data = (b'data: {"id":"c","object":"chat.completion.chunk","model":"m","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"x","type":"function","function":{"name":"t","arguments":"{\\"a\\": "}}]},"finish_reason":"tool_calls"}]}\n\n'
            b'data: [DONE]\n\n')
    out, seen = await run(data, block("t"), 7)
    assert seen[0].arguments is None and seen[0].raw_arguments == '{"a": '


async def test_non_stream_message_rewrite_openai():
    body = {"id": "x", "choices": [{"index": 0, "finish_reason": "tool_calls", "message": {
        "role": "assistant", "content": None, "tool_calls": [
            {"id": "c1", "type": "function", "function": {"name": "send_email", "arguments": '{"to": "x@unknown.com"}'}}]}}],
        "usage": {"total_tokens": 4}}
    out, changed = await rewrite_openai_message(body, block("send_email"))
    msg = out["choices"][0]["message"]
    assert changed and msg["content"] == BLOCK_TEXT and "tool_calls" not in msg
    assert out["choices"][0]["finish_reason"] == "stop" and out["usage"] == {"total_tokens": 4}
    same, changed = await rewrite_openai_message(body, allow_all)
    assert not changed and same is body


async def test_non_stream_mixed_keeps_allowed_and_appends_text():
    body = {"choices": [{"finish_reason": "tool_calls", "message": {"role": "assistant", "content": "hello", "tool_calls": [
        {"id": "a", "type": "function", "function": {"name": "read_email", "arguments": "{}"}},
        {"id": "b", "type": "function", "function": {"name": "send_email", "arguments": "{}"}}]}}]}
    out, changed = await rewrite_openai_message(body, block("send_email"))
    msg = out["choices"][0]["message"]
    assert changed and [t["id"] for t in msg["tool_calls"]] == ["a"] and msg["content"] == f"hello\n{BLOCK_TEXT}"
    assert out["choices"][0]["finish_reason"] == "tool_calls"


async def test_non_stream_arguments_may_be_dict_or_garbage():
    seen = []

    async def judge(call):
        seen.append(call.arguments)
        return ALLOW

    body = {"choices": [{"message": {"tool_calls": [
        {"id": "a", "function": {"name": "x", "arguments": {"already": "dict"}}},
        {"id": "b", "function": {"name": "y", "arguments": "not json"}}]}}]}
    await rewrite_openai_message(body, judge)
    assert seen == [{"already": "dict"}, None]
