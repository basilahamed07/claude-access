"""An HTTP transport that checks the address it is about to connect to, at connect time.

`validate_outbound_url` looks at DNS before a request; an attacker who controls the name can answer with a public address then and a private
one a moment later (DNS rebinding). This transport resolves the host itself, refuses non-public addresses, and dials the address it checked, so
there is no second lookup to swap. The hostname is kept for the TLS handshake and certificate check.
"""

from __future__ import annotations

import asyncio
import ipaddress
from collections.abc import Iterable

import httpcore
import httpx

from .urls import Resolver, _default_resolver, _is_public

SocketOption = tuple[int, int, int] | tuple[int, int, bytes | bytearray] | tuple[int, int, None, int]


class SafeBackend(httpcore.AnyIOBackend):
    def __init__(self, allow_private: set[str] | None = None, resolver: Resolver | None = None) -> None:
        super().__init__()
        self.allow = {h.lower() for h in (allow_private or set())}
        self.resolver = resolver or _default_resolver

    async def connect_tcp(self, host: str, port: int, timeout: float | None = None, local_address: str | None = None,  # noqa: ASYNC109
                          socket_options: Iterable[SocketOption] | None = None) -> httpcore.AsyncNetworkStream:
        try:
            ipaddress.ip_address(host)
            addrs = [host]
        except ValueError:
            try:
                addrs = await asyncio.to_thread(self.resolver, host, port)
            except OSError as exc:
                raise httpcore.ConnectError(f"cannot resolve {host}") from exc
        if host.lower() not in self.allow:
            if not addrs or not all(_is_public(a) for a in addrs):
                raise httpcore.ConnectError("refusing to connect: the host resolves to a non-public address")
        last: Exception | None = None
        for addr in addrs:
            try:
                return await super().connect_tcp(addr, port, timeout=timeout, local_address=local_address, socket_options=socket_options)
            except httpcore.ConnectError as exc:
                last = exc
        raise last or httpcore.ConnectError("no address to connect to")


class SafeTransport(httpx.AsyncHTTPTransport):
    def __init__(self, *, allow_private: set[str] | None = None, resolver: Resolver | None = None, limits: httpx.Limits | None = None) -> None:
        lim = limits or httpx.Limits(max_connections=100, max_keepalive_connections=20, keepalive_expiry=30.0)
        super().__init__(limits=lim)
        old = self._pool
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=old._ssl_context, max_connections=lim.max_connections, max_keepalive_connections=lim.max_keepalive_connections,
            keepalive_expiry=lim.keepalive_expiry, http1=True, http2=False, network_backend=SafeBackend(allow_private, resolver))
