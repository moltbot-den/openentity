"""Every corpus case through the real send path of each HTTP library, against a local server."""

import asyncio

import aiohttp
import httpx
import pytest
import requests
from conftest import MALFORMED, VALID, SCHEMAS

from langchain_openentity import OpenEntitySchemaViolation, RuthlessSchemaGuard

CASES = [(c, True) for c in MALFORMED] + [(c, False) for c in VALID]


@pytest.fixture
def guarded(server):
    g = RuthlessSchemaGuard(scope="all")
    for name, schema in SCHEMAS.items():
        g.register(f"GET {server}/s/{name}/*", schema)
    g.guard_http()
    yield g
    g.unguard_http()


def url(server, c):
    return f"{server}/s/{c['schema'] or 'free'}/{c['id']}"


def headers(c):
    return {"Accept": c["accept"]} if c["accept"] else {}


def expect(bad, call):
    if bad:
        with pytest.raises(OpenEntitySchemaViolation):
            call()
    else:
        call()


def test_httpx_sync_and_async(server, guarded):
    with httpx.Client() as cl:
        for c, bad in CASES:
            expect(bad, lambda: cl.get(url(server, c), headers=headers(c)))

    async def go():
        async with httpx.AsyncClient() as cl:
            for c, bad in CASES:
                try:
                    await cl.get(url(server, c), headers=headers(c))
                    assert not bad, c["id"]
                except OpenEntitySchemaViolation:
                    assert bad, c["id"]

    asyncio.run(go())


def test_httpx2(server, guarded):
    httpx2 = pytest.importorskip("httpx2")
    with httpx2.Client() as cl:
        for c, bad in CASES:
            expect(bad, lambda: cl.get(url(server, c), headers=headers(c)))


def test_requests(server, guarded):
    with requests.Session() as s:
        for c, bad in CASES:
            expect(bad, lambda: s.get(url(server, c), headers=headers(c)))


def test_aiohttp(server, guarded):
    async def go():
        async with aiohttp.ClientSession() as s:
            for c, bad in CASES:
                try:
                    async with s.get(url(server, c), headers=headers(c)) as r:
                        await r.read()
                    assert not bad, c["id"]
                except OpenEntitySchemaViolation:
                    assert bad, c["id"]

    asyncio.run(go())


def test_streaming_is_never_read(server, guarded):
    c = next(c for c in VALID if c["content_type"] == "text/event-stream")
    with httpx.Client() as cl, cl.stream("GET", url(server, c)) as r:
        assert r.status_code == 200
    html = next(c for c in MALFORMED if c["id"] == "m-html-0-ctjson")
    with httpx.Client() as cl, cl.stream("GET", url(server, html)) as r:
        assert r.status_code == 200  # stream=True responses are left alone


def test_uninstall_restores(server):
    g = RuthlessSchemaGuard(scope="all")
    off = g.guard_http()
    off()
    c = next(c for c in MALFORMED if c["id"] == "m-html-0-ctjson")
    assert httpx.get(url(server, c)).status_code == 200


def test_httpx2_client_with_a_rewriting_transport_like_open_swe(server, guarded):
    """Open-SWE's mcp_http_client wraps httpx2.AsyncHTTPTransport and sends a pinned-IP copy of each request.
    The guard sits above the transport, so it must still see the URL the caller used."""
    httpx2 = pytest.importorskip("httpx2")

    class Pinning(httpx2.AsyncBaseTransport):
        def __init__(self):
            self._inner = httpx2.AsyncHTTPTransport()

        async def handle_async_request(self, request):
            pinned = httpx2.Request(request.method, str(request.url).replace("localhost", "127.0.0.1"),
                                    headers=request.headers, stream=request.stream)
            return await self._inner.handle_async_request(pinned)

    case = next(c for c in MALFORMED if c["id"] == "m-html-0-schema")
    local = server.replace("127.0.0.1", "localhost")
    guarded.register(f"GET {local}/s/*/*", SCHEMAS["pull_list"])

    async def go():
        async with httpx2.AsyncClient(transport=Pinning()) as cl:
            with pytest.raises(OpenEntitySchemaViolation) as e:
                await cl.get(f"{local}/s/{case['schema']}/{case['id']}")
            assert "localhost" in e.value.tool

    asyncio.run(go())
