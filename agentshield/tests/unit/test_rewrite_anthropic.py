import asyncio
import json
from pathlib import Path

import pytest

from agentshield.proxy.anthropic_stream import rewrite_anthropic, rewrite_anthropic_message
from agentshield.proxy.sse import SseParser
from agentshield.proxy.tools import ALLOW, Replace, ToolCall

FIX = Path(__file__).resolve().parent.parent / "fixtures" / "anthropic"
BLOCK_TEXT = "Action blocked by AgentShield: not allowed (rule deny-external-send, trace t-1)"
FIXTURES = ["text_only", "tool_only", "mixed_two_tools", "docs_example"]


def load(name: str) -> bytes:
    return (FIX / f"{name}.sse").read_bytes()


async def feed(data: bytes, size: int):
    for i in range(0, len(data), size):
        await asyncio.sleep(0)
        yield data[i:i + size]


async def run(data: bytes, judge, size: int = 64) -> tuple[bytes, list[ToolCall]]:
    seen: list[ToolCall] = []

    async def wrapped(call: ToolCall):
        seen.append(call)
        return await judge(call)

    out = b"".join([c async for c in rewrite_anthropic(feed(data, size), wrapped)])
    return out, seen


async def allow_all(call):
    return ALLOW


def block(*names: str):
    async def judge(call: ToolCall):
        return Replace(BLOCK_TEXT) if call.name in names else ALLOW
    return judge


def events(raw: bytes):
    return [e for e in SseParser().feed(raw)]


def content_blocks(raw: bytes):
    """Reassemble the final message content from the stream."""
    blocks: dict[int, dict] = {}
    stop = None
    for e in events(raw):
        j = e.json()
        if not isinstance(j, dict):
            continue
        if j["type"] == "content_block_start":
            blocks[j["index"]] = {**j["content_block"], "_json": ""}
        elif j["type"] == "content_block_delta":
            d = j["delta"]
            if d["type"] == "text_delta":
                blocks[j["index"]]["text"] += d["text"]
            elif d["type"] == "input_json_delta":
                blocks[j["index"]]["_json"] += d["partial_json"]
        elif j["type"] == "message_delta":
            stop = j["delta"]["stop_reason"]
    return [blocks[i] for i in sorted(blocks)], stop


@pytest.mark.parametrize("name", FIXTURES)
@pytest.mark.parametrize("size", [1, 3, 64, 100_000])
async def test_allowed_streams_are_byte_identical(name, size):
    data = load(name)
    out, _ = await run(data, allow_all, size)
    assert out == data


async def test_judge_gets_parsed_arguments_once_per_tool():
    out, seen = await run(load("docs_example"), allow_all, 7)
    assert [(c.name, c.arguments) for c in seen] == [("get_weather", {"location": "San Francisco, CA"})]
    assert seen[0].id == "toolu_01T1x1fJ34qAmk2tNTrN7Up6"


async def test_blocked_tool_is_replaced_by_text_and_stop_reason_becomes_end_turn():
    out, _ = await run(load("tool_only"), block("send_email"), 5)
    blocks, stop = content_blocks(out)
    assert [b["type"] for b in blocks] == ["text"] and blocks[0]["text"] == BLOCK_TEXT
    assert stop == "end_turn"
    assert b"send_email" not in out and b"x@unknown.com" not in out and b"Secret invoice data" not in out


async def test_mixed_turn_keeps_text_and_allowed_tool_and_stop_reason(  ):
    out, seen = await run(load("mixed_two_tools"), block("send_email"), 4)
    blocks, stop = content_blocks(out)
    assert [b["type"] for b in blocks] == ["text", "tool_use", "text"]
    assert blocks[0]["text"] == "Doing two things." and blocks[1]["name"] == "read_email"
    assert json.loads(blocks[1]["_json"]) == {"folder": "INBOX", "limit": 5}
    assert blocks[2]["text"] == BLOCK_TEXT
    assert stop == "tool_use"
    assert [c.name for c in seen] == ["read_email", "send_email"]
    assert b"LEAKED-PAYLOAD-123" not in out and b"attacker@evil.example" not in out


@pytest.mark.parametrize("name", ["tool_only", "mixed_two_tools", "docs_example"])
@pytest.mark.parametrize("size", [1, 2, 3, 5, 7, 11, 64])
async def test_blocked_tool_never_leaks_under_any_chunking(name, size):
    data = load(name)
    tool_names = {"tool_only": "send_email", "mixed_two_tools": "send_email", "docs_example": "get_weather"}[name]
    out, _ = await run(data, block(tool_names), size)
    secrets = {"tool_only": [b"send_email", b"x@unknown.com", b"Secret invoice data", b"Secret"],
               "mixed_two_tools": [b"send_email", b"attacker@evil.example", b"LEAKED-PAYLOAD-123", b"LEAKED"],
               "docs_example": [b"get_weather", b"location", b"input_json_delta", b"toolu_01T1x1fJ34qAmk2tNTrN7Up6"]}[name]
    for needle in secrets:
        assert needle not in out, needle
    if name != "mixed_two_tools":
        assert b"input_json_delta" not in out and b"tool_use" not in out.replace(b'"stop_reason":"tool_use"', b"")


async def test_input_json_delta_split_mid_token_is_reassembled():
    out, seen = await run(load("docs_example"), allow_all, 1)
    assert seen[0].arguments == {"location": "San Francisco, CA"}


async def test_text_is_forwarded_before_the_tool_block_completes():
    data = load("docs_example")
    cut = data.index(b"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":1")
    gate = asyncio.Event()

    async def source():
        yield data[:cut]
        await gate.wait()
        yield data[cut:]

    agen = rewrite_anthropic(source(), allow_all)
    first = await asyncio.wait_for(agen.__anext__(), timeout=2)     # would hang if text were held back
    assert first.startswith(b"event: message_start")
    gate.set()
    rest = b"".join([c async for c in agen])
    assert (first + rest) or True


async def test_malformed_tool_json_is_judged_with_none_arguments_and_raw_kept():
    data = (b'event: content_block_start\ndata: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"t","name":"x","input":{}}}\n\n'
            b'event: content_block_delta\ndata: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\\"a\\": "}}\n\n'
            b'event: content_block_stop\ndata: {"type":"content_block_stop","index":0}\n\n'
            b'event: message_delta\ndata: {"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":3}}\n\n')
    out, seen = await run(data, block("x"), 9)
    assert seen[0].arguments is None and seen[0].raw_arguments == '{"a": '
    assert b'"end_turn"' in out


async def test_empty_arguments_parse_to_empty_object():
    data = (b'event: content_block_start\ndata: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"t","name":"noargs","input":{}}}\n\n'
            b'event: content_block_stop\ndata: {"type":"content_block_stop","index":0}\n\n')
    _, seen = await run(data, allow_all, 5)
    assert seen[0].arguments == {}


async def test_stream_cut_inside_a_tool_call_drops_it_and_emits_error():
    data = load("tool_only")
    cut = data.index(b"event: content_block_stop")
    out, seen = await run(data[:cut], allow_all, 6)
    assert seen == [] and b"event: error" in out and b"send_email" not in out


async def test_usage_is_preserved_when_patching_message_delta():
    out, _ = await run(load("tool_only"), block("send_email"), 8)
    delta = next(e.json() for e in events(out) if e.event == "message_delta")
    assert delta["usage"]["output_tokens"] == 7 and delta["delta"]["stop_reason"] == "end_turn"


async def test_non_stream_message_rewrite():
    body = {"id": "m", "type": "message", "role": "assistant", "stop_reason": "tool_use", "usage": {"output_tokens": 3},
            "content": [{"type": "text", "text": "hi"},
                        {"type": "tool_use", "id": "t1", "name": "send_email", "input": {"to": "x@unknown.com"}}]}
    out, changed = await rewrite_anthropic_message(body, block("send_email"))
    assert changed and out["stop_reason"] == "end_turn"
    assert out["content"] == [{"type": "text", "text": "hi"}, {"type": "text", "text": BLOCK_TEXT}]
    same, changed = await rewrite_anthropic_message(body, allow_all)
    assert not changed and same is body


async def test_non_stream_mixed_keeps_stop_reason_tool_use():
    body = {"stop_reason": "tool_use", "content": [
        {"type": "tool_use", "id": "a", "name": "read_email", "input": {}},
        {"type": "tool_use", "id": "b", "name": "send_email", "input": {}}]}
    out, changed = await rewrite_anthropic_message(body, block("send_email"))
    assert changed and out["stop_reason"] == "tool_use" and out["content"][0]["name"] == "read_email"
