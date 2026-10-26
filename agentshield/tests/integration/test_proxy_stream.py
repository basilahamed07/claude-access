import json

import pytest

from agentshield.proxy.sse import SseParser
from agentshield.proxy.tools import ALLOW, Replace
from agentshield.testing.stub_upstream import StubToolCall, Turn

pytestmark = pytest.mark.integration

BLOCK = "Action blocked by AgentShield: test (rule r, trace t)"
OA = {"model": "gpt-4.1", "messages": [{"role": "user", "content": "go"}]}
AN = {"model": "claude-x", "max_tokens": 64, "messages": [{"role": "user", "content": "go"}]}
SEND = Turn(text="On it.", tool_calls=[StubToolCall("send_email", {"to": "x@unknown.com", "body": "Secret"})])


@pytest.fixture
def block_send(app):
    calls = []

    def factory(pc):
        async def judge(call):
            calls.append((pc.agent["slug"], pc.session.key, pc.api, call.name))
            return Replace(BLOCK) if call.name == "send_email" else ALLOW
        return judge

    state = app.state.s
    state.judge_factory = factory
    yield calls
    state.judge_factory = None


async def stream_text(client, url, body, headers):
    async with client.stream("POST", url, json={**body, "stream": True}, headers=headers) as r:
        data = b"".join([c async for c in r.aiter_bytes()])
    return r, data


@pytest.mark.parametrize("chunk", [0, 1, 3])
async def test_openai_stream_blocks_send_email_end_to_end(world, stub, block_send, chunk):
    stub.chunk_size = chunk
    stub.queue.append(SEND)
    r, data = await stream_text(world.api.client(), "/v1/chat/completions", OA, world.oa())
    assert r.status_code == 200
    assert b"send_email" not in data and b"x@unknown.com" not in data and b"Secret" not in data
    text = ""
    finish = None
    for e in SseParser().feed(data):
        j = e.json()
        for ch in (j or {}).get("choices", []) if isinstance(j, dict) else []:
            text += (ch.get("delta") or {}).get("content") or ""
            finish = ch.get("finish_reason") or finish
    assert text == "On it." + BLOCK and finish == "stop"
    assert block_send == [("oa-agent", block_send[0][1], "openai", "send_email")]


@pytest.mark.parametrize("chunk", [0, 1, 4])
async def test_anthropic_stream_blocks_send_email_end_to_end(world, stub, block_send, chunk):
    stub.chunk_size = chunk
    stub.queue.append(SEND)
    r, data = await stream_text(world.api.client(), "/v1/messages", AN, world.an())
    assert r.status_code == 200
    assert b"send_email" not in data and b"x@unknown.com" not in data and b"Secret" not in data
    events = [e.json() for e in SseParser().feed(data) if e.json()]
    stop = next(e for e in events if e["type"] == "message_delta")["delta"]["stop_reason"]
    texts = "".join(e["delta"]["text"] for e in events if e["type"] == "content_block_delta"
                    and e["delta"]["type"] == "text_delta")
    assert stop == "end_turn" and texts == "On it." + BLOCK


async def test_stream_with_allowed_tool_is_untouched_end_to_end(world, stub, block_send):
    stub.queue.append(Turn(tool_calls=[StubToolCall("read_email", {"folder": "INBOX"})]))
    r, data = await stream_text(world.api.client(), "/v1/messages", AN, world.an())
    assert b"read_email" in data and b'"stop_reason":"tool_use"' in data.replace(b'": "', b'":"')


async def test_non_stream_responses_are_rewritten_for_both_formats(world, stub, block_send):
    c = world.api.client()
    stub.queue.append(SEND)
    r = await c.post("/v1/chat/completions", json=OA, headers=world.oa())
    msg = r.json()["choices"][0]
    assert msg["message"]["content"] == "On it.\n" + BLOCK and "tool_calls" not in msg["message"]
    assert msg["finish_reason"] == "stop"
    stub.queue.append(SEND)
    r = await c.post("/v1/messages", json=AN, headers=world.an())
    body = r.json()
    assert [b["type"] for b in body["content"]] == ["text", "text"] and body["stop_reason"] == "end_turn"
    assert "send_email" not in r.text


async def test_judge_factory_receives_session_and_user_request(world, stub, app):
    seen = {}

    def factory(pc):
        seen.update(session=pc.session.key, user_request=pc.user_request, mode=pc.agent["mode"], trace=pc.trace_id)

        async def judge(call):
            return ALLOW
        return judge

    app.state.s.judge_factory = factory
    try:
        stub.queue.append(SEND)
        r = await world.api.client().post("/v1/chat/completions", json=OA,
                                          headers=world.oa(**{"X-AgentShield-Session": "s-77"}))
    finally:
        app.state.s.judge_factory = None
    assert seen["session"] == "s-77" and seen["user_request"] == "go" and seen["mode"] == "monitor"
    assert seen["trace"] == r.headers["x-agentshield-trace"]
    assert json.loads(r.content)["choices"][0]["message"]["tool_calls"]


async def test_upstream_error_during_stream_start_is_provider_shaped(world, stub, block_send):
    stub.fail_with = (500, {"oops": True})
    r, data = await stream_text(world.api.client(), "/v1/messages", AN, world.an())
    assert r.status_code == 502 and json.loads(data)["error"]["type"] == "api_error"
