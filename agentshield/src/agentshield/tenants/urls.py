"""SSRF guard for every tenant-supplied URL (upstream base URLs, webhooks). api spec §A.6 API7.

https only (http only for hosts the operator explicitly allow-listed, e.g. a local vLLM), the host
is resolved and every address must be public, and the check is repeated at connect time so DNS
rebinding cannot swap in a private address after validation.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from collections.abc import Callable
from urllib.parse import urlsplit

Resolver = Callable[[str, int], list[str]]


class UnsafeURL(ValueError):
    pass


def _default_resolver(host: str, port: int) -> list[str]:
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return [str(i[4][0]) for i in infos]


_NAT64 = (ipaddress.ip_network("64:ff9b::/96"), ipaddress.ip_network("64:ff9b:1::/48"))


def _embedded_v4(ip: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    """The IPv4 address hidden inside an IPv6 one (mapped, NAT64, 6to4, Teredo), so it is checked as the IPv4 address it really is."""
    if ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    if ip.sixtofour is not None:
        return ip.sixtofour
    if ip.teredo is not None:
        return ip.teredo[1]
    if any(ip in net for net in _NAT64):
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return None


def _is_public(addr: str) -> bool:
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address = ipaddress.ip_address(addr.split("%")[0])
    if isinstance(ip, ipaddress.IPv6Address):
        v4 = _embedded_v4(ip)
        if v4 is not None and not _is_public(str(v4)):
            return False
    # An allow-list, not a deny-list: only globally routable addresses pass (this also excludes 100.64.0.0/10 carrier-grade NAT).
    if isinstance(ip, ipaddress.IPv6Address) and int(ip) >> 32 == 0 and int(ip) > 1:        # ::/96, an IPv4 address in IPv6 clothing
        return False
    # the older deny-list stays beside the allow-list, so a gap in one is covered by the other
    return ip.is_global and not (ip.is_private or ip.is_reserved or ip.is_multicast or ip.is_unspecified or ip.is_loopback or ip.is_link_local)


def validate_outbound_url(url: str, *, allow_private: set[str] | None = None,
                          resolver: Resolver | None = None) -> str:
    allow = {h.lower() for h in (allow_private or set())}
    parts = urlsplit(url.strip())
    host = (parts.hostname or "").lower()
    if parts.scheme not in {"https", "http"} or not host:
        raise UnsafeURL("URL must be http(s) with a host")
    if parts.username or parts.password:
        raise UnsafeURL("credentials in URLs are not allowed")
    allow_listed = host in allow
    if parts.scheme == "http" and not allow_listed:
        raise UnsafeURL("plain http is only allowed for allow-listed hosts")
    if allow_listed:
        return url
    port = parts.port or (443 if parts.scheme == "https" else 80)
    try:
        ipaddress.ip_address(host)
        addrs = [host]
    except ValueError:
        try:
            addrs = (resolver or _default_resolver)(host, port)
        except OSError as exc:
            raise UnsafeURL(f"cannot resolve host: {host}") from exc
    if not addrs:
        raise UnsafeURL("host does not resolve")
    for addr in addrs:
        if not _is_public(addr):
            raise UnsafeURL("URL resolves to a private, loopback or link-local address")
    return url


async def avalidate_outbound_url(url: str, *, allow_private: set[str] | None = None,
                                 resolver: Resolver | None = None) -> str:
    return await asyncio.to_thread(validate_outbound_url, url, allow_private=allow_private,
                                   resolver=resolver)
