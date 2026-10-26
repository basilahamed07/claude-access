"""A small MCP client for Streamable HTTP servers: JSON-RPC over POST, replies as JSON or as a server-sent event."""

from __future__ import annotations

import json
from typing import Any

import httpx

from ..tenants.urls import UnsafeURL, avalidate_outbound_url
from .analysis import MAX_TOOLS, Tool

PROTOCOL = "2025-03-26"
MAX_REPLY = 2 * 1024 * 1024
MAX_PAGES = 10


class McpError(Exception):
    """The server could not be reached, replied badly, or returned a JSON-RPC error. Messages never include credentials."""


def _parse_reply(resp: httpx.Response, rpc_id: int) -> dict[str, Any]:
    if len(resp.content) > MAX_REPLY:
        raise McpError("the server's reply was too large")
    ctype = resp.headers.get("content-type", "")
    text = resp.text
    messages: list[Any] = []
    if "text/event-stream" in ctype:
        for block in text.split("\n\n"):
            data = "\n".join(line[5:].lstrip() for line in block.splitlines() if line.startswith("data:"))
            if data:
                try:
                    messages.append(json.loads(data))
                except ValueError:
                    continue
    else:
        try:
            body = json.loads(text)
        except ValueError as exc:
            raise McpError("the server did not reply with JSON") from exc
        messages = body if isinstance(body, list) else [body]
    for m in messages:
        if isinstance(m, dict) and m.get("id") == rpc_id:
            if "error" in m:
                err = m["error"] if isinstance(m["error"], dict) else {}
                raise McpError(f"the server returned an error: {str(err.get('message', 'unknown'))[:200]}")
            result = m.get("result")
            if not isinstance(result, dict):
                raise McpError("the server's reply had no result")
            return result
    raise McpError("the server did not answer the request")


class McpClient:
    def __init__(self, http: httpx.AsyncClient, url: str, *, token: str | None = None, allow_private: set[str] | None = None, timeout: float = 10.0) -> None:
        self.http, self.url, self.timeout = http, url, timeout
        self._token, self._allow_private = token, allow_private or set()
        self._session: str | None = None
        self._id = 0
        self._ready = False

    def _headers(self) -> dict[str, str]:
        h = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream", "MCP-Protocol-Version": PROTOCOL}
        if self._session:
            h["Mcp-Session-Id"] = self._session
        if self._token:
            h["Authorization"] = f"Bearer {self._token}"
        return h

    async def _post(self, payload: dict[str, Any]) -> httpx.Response:
        try:
            await avalidate_outbound_url(self.url, allow_private=self._allow_private)
        except UnsafeURL as exc:
            raise McpError(f"this server address is not allowed: {exc}") from None
        try:
            return await self.http.post(self.url, json=payload, headers=self._headers(), timeout=self.timeout)
        except httpx.TimeoutException:
            raise McpError("the server timed out") from None
        except httpx.HTTPError as exc:
            raise McpError(f"could not reach the server ({type(exc).__name__})") from None

    async def _rpc(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        self._id += 1
        resp = await self._post({"jsonrpc": "2.0", "id": self._id, "method": method, "params": params or {}})
        if resp.status_code in (401, 403):
            raise McpError("the server refused our credentials")
        if resp.status_code >= 400:
            raise McpError(f"the server answered HTTP {resp.status_code}")
        if sid := resp.headers.get("mcp-session-id"):
            self._session = sid
        return _parse_reply(resp, self._id)

    async def initialize(self) -> dict[str, Any]:
        info = await self._rpc("initialize", {"protocolVersion": PROTOCOL, "capabilities": {}, "clientInfo": {"name": "agentshield", "version": "0.1"}})
        await self._post({"jsonrpc": "2.0", "method": "notifications/initialized"})
        self._ready = True
        return info

    async def list_tools(self) -> list[Tool]:
        if not self._ready:
            await self.initialize()
        tools: list[Tool] = []
        cursor: str | None = None
        for _ in range(MAX_PAGES):
            res = await self._rpc("tools/list", {"cursor": cursor} if cursor else {})
            for raw in res.get("tools") or []:
                if isinstance(raw, dict) and raw.get("name"):
                    tools.append(Tool.from_mcp(raw))
            if len(tools) > MAX_TOOLS:
                raise McpError(f"the server lists more than {MAX_TOOLS} tools")
            cursor = res.get("nextCursor")
            if not cursor:
                return tools
        raise McpError("the server's tool list never ended")

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if not self._ready:
            await self.initialize()
        return await self._rpc("tools/call", {"name": name, "arguments": arguments})
