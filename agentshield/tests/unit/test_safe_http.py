"""DNS rebinding: the address that was checked is the address that is dialled, and private ones are refused at connect time."""

import asyncio

import httpx
import pytest

from agentshield.tenants.safe_http import SafeTransport
from agentshield.tenants.urls import validate_outbound_url


@pytest.fixture
async def local_server():
    hits = []

    async def handle(reader, writer):
        hits.append(await reader.read(200))
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    yield server.sockets[0].getsockname()[1], hits
    server.close()
    await server.wait_closed()


async def get(transport, url):
    async with httpx.AsyncClient(transport=transport) as c:
        return await c.get(url)


async def test_a_host_that_resolves_to_a_private_address_is_never_connected_to(local_server):
    port, hits = local_server
    t = SafeTransport(resolver=lambda host, p: ["127.0.0.1"])
    with pytest.raises(httpx.ConnectError):
        await get(t, f"http://evil.example:{port}/")
    assert hits == []                                              # no connection was even opened


async def test_rebinding_between_the_check_and_the_connection_is_caught(local_server):
    """The pre-flight check sees a public address; the answer at connect time is private. The connect-time check wins."""
    port, hits = local_server
    answers = iter([["93.184.216.34"], ["127.0.0.1"]])
    pre = validate_outbound_url(f"https://rebind.example:{port}/", resolver=lambda h, p: next(answers))
    assert pre
    t = SafeTransport(resolver=lambda host, p: next(answers))
    with pytest.raises(httpx.ConnectError):
        await get(t, f"http://rebind.example:{port}/")
    assert hits == []


async def test_literal_private_addresses_and_metadata_endpoints_are_refused(local_server):
    port, hits = local_server
    t = SafeTransport()
    for url in (f"http://127.0.0.1:{port}/", "http://169.254.169.254/latest/meta-data/", "http://[::1]:9/", "http://10.0.0.1/"):
        with pytest.raises(httpx.ConnectError):
            await get(t, url)
    assert hits == []


async def test_allow_listed_hosts_may_be_private(local_server):
    port, hits = local_server
    t = SafeTransport(allow_private={"local-vllm"}, resolver=lambda host, p: ["127.0.0.1"])
    r = await get(t, f"http://local-vllm:{port}/v1")
    assert r.status_code == 200 and r.text == "ok" and len(hits) == 1
    t2 = SafeTransport(allow_private={"local-vllm"}, resolver=lambda host, p: ["127.0.0.1"])
    with pytest.raises(httpx.ConnectError):                        # allow-listing is per host name, not global
        await get(t2, f"http://other-name:{port}/")


async def test_the_dialled_address_is_the_checked_one_when_a_host_has_several(local_server):
    port, hits = local_server
    t = SafeTransport(resolver=lambda host, p: ["93.184.216.34", "10.0.0.5"])          # one public, one private: refuse the whole answer
    with pytest.raises(httpx.ConnectError):
        await get(t, f"http://mixed.example:{port}/")
    assert hits == []


async def test_unresolvable_hosts_are_a_connect_error_not_a_crash():
    def fail(host, port):
        raise OSError("nxdomain")
    with pytest.raises(httpx.ConnectError):
        await get(SafeTransport(resolver=fail), "http://nope.example/")
