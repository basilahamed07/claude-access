"""Upstream adapters: forward a request to the tenant's provider and return/stream the answer.

Formats are not translated: an Anthropic-format request needs an `anthropic` upstream (which can be
an Anthropic-compatible gateway such as LiteLLM); an OpenAI-format request needs an `openai` or
`openai_compat` upstream.
"""

from __future__ import annotations

import time
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any, Literal

import httpx

from ..contracts.errors import ApiError
from ..observability import span
from ..tenants.urls import UnsafeURL, avalidate_outbound_url

Api = Literal["anthropic", "openai"]
ANTHROPIC_VERSION = "2023-06-01"
_PASS_HEADERS = ("anthropic-version", "anthropic-beta", "openai-organization", "openai-project")
_URL_OK_TTL = 60.0


@dataclass
class UpstreamConfig:
    id: str
    name: str
    kind: str
    base_url: str
    api_key: str | None
    model_map: dict[str, Any] = field(default_factory=dict)
    judge_model: str | None = None

    def resolve_model(self, alias: str) -> tuple[str, dict[str, Any] | None]:
        entry = self.model_map.get(alias)
        if isinstance(entry, dict) and entry.get("model"):
            return str(entry["model"]), entry
        return alias, None


def api_matches_kind(api: Api, kind: str) -> bool:
    return (api == "anthropic") == (kind == "anthropic")


def build_url(api: Api, base_url: str) -> str:
    base = base_url.rstrip("/")
    if api == "anthropic":
        return f"{base}/messages" if base.endswith("/v1") else f"{base}/v1/messages"
    return f"{base}/chat/completions"


def build_headers(api: Api, api_key: str | None, client_headers: dict[str, str]) -> dict[str, str]:
    headers = {"content-type": "application/json", "accept": client_headers.get("accept", "application/json")}
    if api == "anthropic":
        if api_key:
            headers["x-api-key"] = api_key
        headers["anthropic-version"] = client_headers.get("anthropic-version", ANTHROPIC_VERSION)
    elif api_key:
        headers["authorization"] = f"Bearer {api_key}"
    for name in _PASS_HEADERS:
        if name in client_headers and name not in headers:
            headers[name] = client_headers[name]
    return headers


class UpstreamClient:
    def __init__(self, http: httpx.AsyncClient, *, allow_private: set[str], max_bytes: int) -> None:
        self.http = http
        self.allow_private = allow_private
        self.max_bytes = max_bytes
        self._validated: dict[str, float] = {}

    async def _check_url(self, url: str) -> None:
        now = time.monotonic()
        if self._validated.get(url, 0) > now:
            return
        try:
            await avalidate_outbound_url(url, allow_private=self.allow_private)
        except UnsafeURL as exc:
            raise ApiError("upstream_error", "Upstream URL is not allowed") from exc
        self._validated[url] = now + _URL_OK_TTL

    async def complete(self, cfg: UpstreamConfig, api: Api, body: dict[str, Any],
                       client_headers: dict[str, str], api_key: str | None) -> httpx.Response:
        url = build_url(api, cfg.base_url)
        await self._check_url(url)
        try:
            with span("agentshield.upstream", **{"agentshield.upstream": cfg.name, "http.url": url}):
                resp = await self.http.post(url, json=body, headers=build_headers(api, api_key, client_headers))
        except httpx.TimeoutException as exc:
            raise ApiError("upstream_timeout", "The model provider timed out") from exc
        except httpx.HTTPError as exc:
            raise ApiError("upstream_error", "Could not reach the model provider") from exc
        if len(resp.content) > self.max_bytes:
            raise ApiError("upstream_error", "The model provider response was too large")
        return resp

    async def open_stream(self, cfg: UpstreamConfig, api: Api, body: dict[str, Any],
                          client_headers: dict[str, str], api_key: str | None) -> httpx.Response:
        """Return a response whose body has not been read yet (caller must `aclose()` it)."""
        url = build_url(api, cfg.base_url)
        await self._check_url(url)
        headers = build_headers(api, api_key, client_headers)
        headers["accept"] = "text/event-stream"
        req = self.http.build_request("POST", url, json=body, headers=headers)
        try:
            with span("agentshield.upstream.stream", **{"agentshield.upstream": cfg.name, "http.url": url}):
                return await self.http.send(req, stream=True)
        except httpx.TimeoutException as exc:
            raise ApiError("upstream_timeout", "The model provider timed out") from exc
        except httpx.HTTPError as exc:
            raise ApiError("upstream_error", "Could not reach the model provider") from exc

    async def iter_bytes(self, resp: httpx.Response) -> AsyncIterator[bytes]:
        total = 0
        try:
            async for chunk in resp.aiter_raw():
                total += len(chunk)
                if total > self.max_bytes:
                    break
                yield chunk
        finally:
            await resp.aclose()
