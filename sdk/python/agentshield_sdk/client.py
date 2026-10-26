"""AgentShield clients (sync and async).

Fail rule (arch §8.6), implemented in one place (`apply_fail_rule`): when AgentShield cannot decide, only `read` tools
run (with a logged warning); every other tool, and any tool without a tag, is blocked.
"""

from __future__ import annotations

import asyncio
import contextvars
import functools
import inspect
import json
import logging
import os
import time
import uuid
from collections.abc import Awaitable, Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, TypeVar

import httpx

from .errors import AgentShieldError, AuthError, Blocked, Unreachable
from .models import Approval, CheckResponse, EffectTag, ScanResult, UntrustedInput

log = logging.getLogger("agentshield_sdk")
T = TypeVar("T")
FAIL_OPEN: frozenset[str] = frozenset({"read"})
UNREACHABLE_RULE = "agentshield-unreachable"


@dataclass
class SessionContext:
    session_id: str
    user_request: str | None = None
    end_user: str | None = None
    untrusted: list[UntrustedInput] = field(default_factory=list)


_session: contextvars.ContextVar[SessionContext | None] = contextvars.ContextVar("agentshield_session", default=None)


@contextmanager
def session(session_id: str | None = None, *, user_request: str | None = None, end_user: str | None = None,
            untrusted_inputs: Sequence[UntrustedInput] = ()) -> Iterator[SessionContext]:
    """Group guarded calls into one session. Pass the user's request and anything untrusted the agent has read
    since its last decision, so the scanner and the scope check can use them."""
    ctx = SessionContext(session_id or f"sdk-{uuid.uuid4().hex[:16]}", user_request, end_user, list(untrusted_inputs))
    token = _session.set(ctx)
    try:
        yield ctx
    finally:
        _session.reset(token)


def apply_fail_rule(effect_tag: str | None, cause: Exception) -> None:
    """Return normally if the tool may run without a decision (read only); otherwise raise Blocked."""
    if (effect_tag or "external") in FAIL_OPEN:
        log.warning("AgentShield could not decide (%s); allowing read-only tool", type(cause).__name__)
        return
    raise Blocked("AgentShield could not be reached, so this action was not run", UNREACHABLE_RULE) from cause


def _not_approved(outcome: str, trace_id: str) -> Blocked:
    if outcome == "denied":
        return Blocked("A reviewer denied this action", "approval-denied", trace_id, "ask")
    if outcome == "expired":
        return Blocked("Nobody approved this action in time; it counts as denied", "approval-timeout", trace_id, "ask")
    return Blocked("No reviewer answered in time; the action was not run", "approval-timeout", trace_id, "ask")


def _arguments(fn: Callable[..., Any], args: tuple[Any, ...], kwargs: dict[str, Any]) -> dict[str, Any]:
    try:
        bound = inspect.signature(fn).bind(*args, **kwargs)
        bound.apply_defaults()
        raw = dict(bound.arguments)
    except TypeError:
        raw = {**{f"arg{i}": a for i, a in enumerate(args)}, **kwargs}
    out: dict[str, Any] = json.loads(json.dumps(raw, default=str))
    return out


def _problem_detail(resp: httpx.Response) -> str:
    try:
        return str(resp.json().get("detail") or resp.reason_phrase)
    except Exception:                                                 # noqa: BLE001
        return resp.reason_phrase


class _Base:
    def __init__(self, base_url: str, api_key: str, *, agent_id: str, tenant: str, timeout: float = 2.0) -> None:
        if not api_key:
            raise ValueError("api_key is required")
        self.base_url = base_url.rstrip("/")
        self.agent_id = agent_id
        self.tenant = tenant
        self.timeout = timeout
        self.__key = api_key

    def __repr__(self) -> str:
        return f"{type(self).__name__}(base_url={self.base_url!r}, agent_id={self.agent_id!r}, api_key='ask_***')"

    @property
    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.__key}", "Content-Type": "application/json"}

    def _check_body(self, tool: str, arguments: dict[str, Any], *, effect_tag: str | None, wait_seconds: int) -> dict[str, Any]:
        ctx = _session.get() or SessionContext(f"sdk-{uuid.uuid4().hex[:16]}")
        body: dict[str, Any] = {
            "agent_id": self.agent_id, "tenant": self.tenant, "session_id": ctx.session_id,
            "action": {"tool": tool, "arguments": arguments}, "wait_seconds": max(0, min(30, int(wait_seconds))),
            "context": {"user_request": ctx.user_request, "end_user": ctx.end_user,
                        "untrusted_inputs": [u.payload() for u in ctx.untrusted]},
        }
        if effect_tag:
            body["action"]["effect_tag"] = effect_tag
        return body

    @staticmethod
    def _parse(resp: httpx.Response, model: type[T]) -> T:
        if resp.status_code in (401, 403):
            raise AuthError(f"AgentShield rejected the credentials ({resp.status_code}): {_problem_detail(resp)}")
        if resp.status_code == 429 or resp.status_code >= 500:
            raise Unreachable(f"AgentShield answered {resp.status_code}")
        if resp.status_code >= 400:
            raise AgentShieldError(f"AgentShield rejected the request ({resp.status_code}): {_problem_detail(resp)}")
        try:
            return model(**resp.json())
        except Exception as exc:                                      # noqa: BLE001
            raise Unreachable("AgentShield sent a reply this SDK could not read") from exc

    @staticmethod
    def _denied(resp: CheckResponse, decision: str) -> Blocked:
        return Blocked(resp.reason, resp.rule_id, resp.trace_id, decision)


class AgentShield(_Base):
    """Synchronous client."""

    def __init__(self, base_url: str, api_key: str, *, agent_id: str, tenant: str, timeout: float = 2.0,
                 http: httpx.Client | None = None, sleep: Callable[[float], None] = time.sleep) -> None:
        super().__init__(base_url, api_key, agent_id=agent_id, tenant=tenant, timeout=timeout)
        self._http = http or httpx.Client(timeout=timeout)
        self._sleep = sleep

    @classmethod
    def from_env(cls, **kw: Any) -> AgentShield:
        return cls(os.environ["AGENTSHIELD_URL"], os.environ["AGENTSHIELD_API_KEY"], agent_id=os.environ["AGENTSHIELD_AGENT"],
                   tenant=os.environ["AGENTSHIELD_TENANT"], **kw)

    def close(self) -> None:
        self._http.close()

    def _send(self, method: str, path: str, *, body: dict[str, Any] | None = None, timeout: float | None = None) -> httpx.Response:
        try:
            return self._http.request(method, f"{self.base_url}{path}", headers=self._headers,
                                      content=json.dumps(body) if body is not None else None, timeout=timeout or self.timeout)
        except httpx.HTTPError as exc:
            raise Unreachable(f"could not reach AgentShield ({type(exc).__name__})") from None

    def check(self, tool: str, arguments: dict[str, Any] | None = None, *, effect_tag: EffectTag | None = None, wait_seconds: int = 0) -> CheckResponse:
        body = self._check_body(tool, arguments or {}, effect_tag=effect_tag, wait_seconds=wait_seconds)
        resp = self._send("POST", "/v1/check", body=body, timeout=self.timeout + wait_seconds)
        return self._parse(resp, CheckResponse)

    def scan(self, text: str, *, source: str, id: str = "content", session_id: str | None = None) -> ScanResult:
        ctx = _session.get()
        body: dict[str, Any] = {"source": source, "id": id, "text": text, "session_id": session_id or (ctx.session_id if ctx else None)}
        return self._parse(self._send("POST", "/v1/scan", body=body), ScanResult)

    def wait_for_approval(self, approval_id: str, timeout_s: float = 300, *, poll_s: float = 1.0) -> str:
        """Poll until a reviewer decides. Returns 'allow', 'denied', 'expired' or 'timeout'; only 'allow' lets the action run."""
        deadline = time.monotonic() + timeout_s
        while True:
            a = self._parse(self._send("GET", f"/v1/approvals/{approval_id}"), Approval)
            if a.status == "approved":
                return "allow"
            if a.status in {"denied", "expired"}:
                return "denied" if a.status == "denied" else "expired"
            if time.monotonic() >= deadline:
                return "timeout"
            self._sleep(min(poll_s, max(0.0, deadline - time.monotonic())))

    def authorize(self, tool: str, arguments: dict[str, Any], effect_tag: EffectTag | None, *, approval_timeout: float = 300) -> CheckResponse | None:
        """Decide whether a call may run. Returns the response when AgentShield decided, None when the fail rule let a read tool through."""
        try:
            resp = self.check(tool, arguments, effect_tag=effect_tag, wait_seconds=min(30, int(approval_timeout)))
            if resp.decision == "ask":
                if not resp.approval_id:
                    raise self._denied(resp, "ask")
                outcome = self.wait_for_approval(resp.approval_id, approval_timeout)
                if outcome != "allow":
                    raise _not_approved(outcome, resp.trace_id)
                return resp
        except Unreachable as exc:
            apply_fail_rule(effect_tag, exc)
            return None
        if resp.decision == "block":
            raise self._denied(resp, "block")
        return resp

    def guard(self, tool_name: str, effect_tag: EffectTag | None = None, *, approval_timeout: float = 300) -> Callable[[Callable[..., T]], Callable[..., T]]:
        def deco(fn: Callable[..., T]) -> Callable[..., T]:
            @functools.wraps(fn)
            def wrapper(*args: Any, **kwargs: Any) -> T:
                self.authorize(tool_name, _arguments(fn, args, kwargs), effect_tag, approval_timeout=approval_timeout)
                return fn(*args, **kwargs)
            return wrapper
        return deco


class AsyncAgentShield(_Base):
    """Asynchronous client with the same behaviour."""

    def __init__(self, base_url: str, api_key: str, *, agent_id: str, tenant: str, timeout: float = 2.0,
                 http: httpx.AsyncClient | None = None, sleep: Callable[[float], Awaitable[None]] = asyncio.sleep) -> None:
        super().__init__(base_url, api_key, agent_id=agent_id, tenant=tenant, timeout=timeout)
        self._http = http or httpx.AsyncClient(timeout=timeout)
        self._sleep = sleep

    async def aclose(self) -> None:
        await self._http.aclose()

    async def _send(self, method: str, path: str, *, body: dict[str, Any] | None = None, timeout: float | None = None) -> httpx.Response:
        try:
            return await self._http.request(method, f"{self.base_url}{path}", headers=self._headers,
                                            content=json.dumps(body) if body is not None else None, timeout=timeout or self.timeout)
        except httpx.HTTPError as exc:
            raise Unreachable(f"could not reach AgentShield ({type(exc).__name__})") from None

    async def check(self, tool: str, arguments: dict[str, Any] | None = None, *, effect_tag: EffectTag | None = None, wait_seconds: int = 0) -> CheckResponse:
        body = self._check_body(tool, arguments or {}, effect_tag=effect_tag, wait_seconds=wait_seconds)
        return self._parse(await self._send("POST", "/v1/check", body=body, timeout=self.timeout + wait_seconds), CheckResponse)

    async def scan(self, text: str, *, source: str, id: str = "content", session_id: str | None = None) -> ScanResult:
        ctx = _session.get()
        body: dict[str, Any] = {"source": source, "id": id, "text": text, "session_id": session_id or (ctx.session_id if ctx else None)}
        return self._parse(await self._send("POST", "/v1/scan", body=body), ScanResult)

    async def wait_for_approval(self, approval_id: str, timeout_s: float = 300, *, poll_s: float = 1.0) -> str:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout_s
        while True:
            a = self._parse(await self._send("GET", f"/v1/approvals/{approval_id}"), Approval)
            if a.status == "approved":
                return "allow"
            if a.status in {"denied", "expired"}:
                return a.status
            if loop.time() >= deadline:
                return "timeout"
            await self._sleep(min(poll_s, max(0.0, deadline - loop.time())))

    async def authorize(self, tool: str, arguments: dict[str, Any], effect_tag: EffectTag | None, *, approval_timeout: float = 300) -> CheckResponse | None:
        try:
            resp = await self.check(tool, arguments, effect_tag=effect_tag, wait_seconds=min(30, int(approval_timeout)))
            if resp.decision == "ask":
                if not resp.approval_id:
                    raise self._denied(resp, "ask")
                outcome = await self.wait_for_approval(resp.approval_id, approval_timeout)
                if outcome != "allow":
                    raise _not_approved(outcome, resp.trace_id)
                return resp
        except Unreachable as exc:
            apply_fail_rule(effect_tag, exc)
            return None
        if resp.decision == "block":
            raise self._denied(resp, "block")
        return resp

    def guard(self, tool_name: str, effect_tag: EffectTag | None = None, *, approval_timeout: float = 300) -> Callable[[Callable[..., Awaitable[T]]], Callable[..., Awaitable[T]]]:
        def deco(fn: Callable[..., Awaitable[T]]) -> Callable[..., Awaitable[T]]:
            if not inspect.iscoroutinefunction(fn):
                raise TypeError("AsyncAgentShield.guard needs an async function; use AgentShield.guard for sync tools")

            @functools.wraps(fn)
            async def wrapper(*args: Any, **kwargs: Any) -> T:
                await self.authorize(tool_name, _arguments(fn, args, kwargs), effect_tag, approval_timeout=approval_timeout)
                return await fn(*args, **kwargs)
            return wrapper
        return deco
