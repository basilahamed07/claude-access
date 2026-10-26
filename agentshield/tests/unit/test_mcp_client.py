import asyncio

import httpx
import pytest

from agentshield.mcp.client import McpClient, McpError
from agentshield.testing.mcp_samples import SampleMcp, mail_tools, unsafe_tools

URL = "https://mcp.example.test/mcp"


def client_for(sample: SampleMcp, **kw):
    http = httpx.AsyncClient(transport=httpx.ASGITransport(app=sample.app), base_url="https://mcp.example.test")
    return McpClient(http, URL, **kw), http


@pytest.fixture(autouse=True)
def public_dns(monkeypatch):
    from agentshield.tenants import urls
    monkeypatch.setattr(urls, "_default_resolver", lambda host, port: ["93.184.216.34"])


def run(coro):
    return asyncio.run(coro)


def test_lists_tools_over_json_and_remembers_the_session():
    s = SampleMcp(mail_tools())
    c, http = client_for(s)
    tools = run(c.list_tools())
    assert [t.name for t in tools] == ["read_email", "send_email"] and tools[1].input_schema["required"] == ["to"]
    assert [r["method"] for r in s.requests] == ["initialize", "notifications/initialized", "tools/list"]
    assert s.requests[-1]["session"] == "sess-1"
    run(http.aclose())


def test_reads_server_sent_event_replies_and_follows_pagination():
    s = SampleMcp([{"name": f"t{i}", "description": "x"} for i in range(5)], sse=True, page_size=2)
    c, http = client_for(s)
    assert [t.name for t in run(c.list_tools())] == ["t0", "t1", "t2", "t3", "t4"]
    run(http.aclose())


def test_call_tool_returns_the_result_object():
    s = SampleMcp(mail_tools())
    c, http = client_for(s)
    res = run(c.call_tool("send_email", {"to": "a@acme.com"}))
    assert res["content"][0]["text"] == "Email sent to a@acme.com." and s.calls[0]["name"] == "send_email"
    run(http.aclose())


def test_errors_are_readable_and_never_include_the_token():
    s = SampleMcp(unsafe_tools())
    s.require_token = "right-token"
    c, http = client_for(s, token="wrong-token-SECRET")
    with pytest.raises(McpError, match="refused our credentials") as e:
        run(c.list_tools())
    assert "SECRET" not in str(e.value)
    c2, _ = client_for(s, token="right-token")
    assert len(run(c2.list_tools())) == 2
    run(http.aclose())


def test_a_json_rpc_error_and_a_non_json_reply_and_a_timeout_are_mcp_errors():
    s = SampleMcp(mail_tools())
    c, http = client_for(s)
    with pytest.raises(McpError, match="unknown method"):
        run(c._rpc("nope"))
    run(http.aclose())

    def html(request):
        return httpx.Response(200, text="<html>hi</html>", headers={"content-type": "text/html"})
    c = McpClient(httpx.AsyncClient(transport=httpx.MockTransport(html)), URL)
    with pytest.raises(McpError, match="did not reply with JSON"):
        run(c.initialize())

    def slow(request):
        raise httpx.ReadTimeout("slow")
    c = McpClient(httpx.AsyncClient(transport=httpx.MockTransport(slow)), URL)
    with pytest.raises(McpError, match="timed out"):
        run(c.initialize())


def test_private_addresses_are_refused_before_any_request(monkeypatch):
    from agentshield.tenants import urls
    monkeypatch.setattr(urls, "_default_resolver", lambda host, port: ["10.0.0.5"])
    called = []
    c = McpClient(httpx.AsyncClient(transport=httpx.MockTransport(lambda r: called.append(r) or httpx.Response(200, json={}))), "https://internal.test/mcp")
    with pytest.raises(McpError, match="not allowed"):
        run(c.initialize())
    assert called == []


def test_an_enormous_tool_list_is_refused():
    s = SampleMcp([{"name": f"t{i}", "description": "x"} for i in range(250)])
    c, http = client_for(s)
    with pytest.raises(McpError, match="more than"):
        run(c.list_tools())
    run(http.aclose())
