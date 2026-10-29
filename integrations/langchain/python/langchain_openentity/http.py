"""Patch the send path of httpx, httpx2 (Open-SWE uses it), requests and aiohttp, when installed.

Streaming responses (`stream=True`, SSE) are never read, so they are never checked.
"""

from __future__ import annotations

import functools
import importlib
from typing import Any, Callable


def _patch(obj: Any, name: str, make: Callable[[Callable], Callable], undo: list) -> None:
    orig = getattr(obj, name)
    setattr(obj, name, functools.wraps(orig)(make(orig)))
    undo.append(lambda: setattr(obj, name, orig))


def install(guard: Any) -> Callable[[], None]:
    undo: list[Callable[[], None]] = []

    def httpx_like(mod: Any) -> None:
        def sync(orig):
            def send(self, request, *a, **kw):
                resp = orig(self, request, *a, **kw)
                if not kw.get("stream"):
                    r = resp.request
                    guard._check(r.method, str(r.url), resp.status_code, resp.headers.get("content-type", ""),
                                 r.headers.get("accept", ""), lambda: resp.content)
                return resp
            return send

        def asyn(orig):
            async def send(self, request, *a, **kw):
                resp = await orig(self, request, *a, **kw)
                if not kw.get("stream"):
                    r = resp.request
                    guard._check(r.method, str(r.url), resp.status_code, resp.headers.get("content-type", ""),
                                 r.headers.get("accept", ""), lambda: resp.content)
                return resp
            return send

        _patch(mod.Client, "send", sync, undo)
        _patch(mod.AsyncClient, "send", asyn, undo)

    def requests_(mod: Any) -> None:
        def make(orig):
            def send(self, request, **kw):
                resp = orig(self, request, **kw)
                if not kw.get("stream"):
                    guard._check(request.method, resp.url, resp.status_code, resp.headers.get("content-type", ""),
                                 request.headers.get("Accept", ""), lambda: resp.content)
                return resp
            return send

        _patch(mod.Session, "send", make, undo)

    def aiohttp_(mod: Any) -> None:
        def make(orig):
            async def _request(self, method, str_or_url, **kw):
                resp = await orig(self, method, str_or_url, **kw)
                ct = resp.headers.get("content-type", "")
                try:  # headers may be a dict, a list of pairs or a CIMultiDict
                    accept = resp.request_info.headers.get("Accept", "")
                except Exception:  # noqa: BLE001
                    accept = ""
                if guard._wants(method, str(resp.url), resp.status, ct, accept):
                    body = await resp.read()
                    guard._check(method, str(resp.url), resp.status, ct, accept, lambda: body)
                return resp
            return _request

        _patch(mod.ClientSession, "_request", make, undo)

    for name, fn in (("httpx", httpx_like), ("httpx2", httpx_like), ("requests", requests_), ("aiohttp", aiohttp_)):
        try:
            fn(importlib.import_module(name))
        except ImportError:
            continue

    def uninstall() -> None:
        while undo:
            undo.pop()()

    return uninstall
