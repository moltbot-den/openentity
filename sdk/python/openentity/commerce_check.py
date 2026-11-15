"""Agent Commerce Check middleware (FastAPI / Starlette, Django): one hosted call before you accept an agent purchase.

`CommerceCheckMiddleware` is a plain ASGI middleware (no Starlette import), `django_middleware` a Django one (no Django import until
a response is built). Both attach the answer as `request.state.agent_check` (ASGI) or `request.agent_check` (Django), a dict:
{decision, reasons, evidence_id, ...}. step_up answers 428 with the cart, deny answers 403; `enforce=False` only observes.
Re-exported from `openentity.commerce`.
"""
import asyncio
import json
import re
import urllib.error
import urllib.request
from importlib.metadata import PackageNotFoundError, version

try:
    _VERSION = version("openentity")
except PackageNotFoundError:
    _VERSION = "dev"

ENDPOINT = "https://openentity.org/v1/commerce/check"
_UNAVAILABLE = {"error": "commerce_check_unavailable", "message": "the agent could not be checked; retry"}


def agent_did_of(headers: dict) -> str | None:
    """The agent DID named by the Signature-Input keyid (unverified: for building the cart only; the hosted check verifies)."""
    m = re.search(r'keyid="([^"#]+)', headers.get("signature-input", ""))
    return m.group(1) if m else None


def _post(endpoint: str, payload: dict) -> dict:
    req = urllib.request.Request(endpoint, data=json.dumps(payload).encode(), method="POST",
                                 headers={"content-type": "application/json", "user-agent": f"openentity-python/{_VERSION}"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.load(r)


def agent_check(request: dict, cart, policy: dict | None = None, *, approval: dict | None = None, endpoint: str = ENDPOINT, post=_post) -> dict:
    """Asks the hosted check about one request: request = {method, url, headers, body?: str}. Raises on a transport error or an HTTP error."""
    payload = {"request": request, "cart": cart, "policy": policy or {}, **({"approval": approval} if approval else {})}
    out = post(endpoint, payload)
    if not isinstance(out, dict) or "decision" not in out:
        raise RuntimeError(f"commerce check failed: {out!r}")
    return out


def _view(c: dict) -> dict:
    return {"decision": c["decision"], "reasons": c["reasons"], "evidence_id": c["evidence_id"],
            **({"cart": c["cart"], "cart_digest": c.get("cart_digest")} if c.get("cart") else {})}


def _status(c: dict) -> int:
    return 403 if c["decision"] == "deny" else 428


class CommerceCheckMiddleware:
    """ASGI: `app.add_middleware(CommerceCheckMiddleware, paths=["/buy"], cart=cart_for, policy={...})`.

    `cart(req, agent_did)` builds the cart/1 from req = {method, url, headers (lowercase), body}. `paths` limits it to those path prefixes
    (default: every path). `public_origin` ("https://shop.example") replaces the scheme and host agents signed, behind a proxy.
    `approval(req)` returns {approval, verifier_did, request_id} on a retry after step_up. `post` replaces the HTTP call (tests)."""

    def __init__(self, app, *, cart, policy: dict | None = None, approval=None, paths: list[str] | None = None, endpoint: str = ENDPOINT,
                 enforce: bool = True, public_origin: str | None = None, on_decision=None, post=_post):
        self.app, self.cart, self.policy, self.approval, self.paths = app, cart, policy or {}, approval, paths
        self.endpoint, self.enforce, self.public_origin, self.on_decision, self.post = endpoint, enforce, public_origin, on_decision, post

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or (self.paths and not any(scope["path"].startswith(p) for p in self.paths)):
            return await self.app(scope, receive, send)
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope["headers"]}
        chunks, more = [], True
        while more:  # buffer the body: the signature may cover it, and the app still needs to read it
            msg = await receive()
            chunks.append(msg.get("body", b""))
            more = msg.get("more_body", False)
        raw = b"".join(chunks)
        host = self.public_origin or f"{scope.get('scheme', 'http')}://{headers.get('host', '')}"
        qs = scope.get("query_string", b"").decode("latin-1")
        info = {"method": scope["method"], "url": f"{host.rstrip('/')}{scope['path']}{'?' + qs if qs else ''}", "headers": headers,
                **({"body": raw.decode("utf-8", "replace")} if raw else {})}
        sent = False

        async def replay():
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": raw, "more_body": False}
            return await receive()

        try:
            cart = self.cart(info, agent_did_of(headers))
            if asyncio.iscoroutine(cart):
                cart = await cart
            approval = self.approval(info) if self.approval else None
            c = await asyncio.to_thread(agent_check, info, cart, self.policy, approval=approval, endpoint=self.endpoint, post=self.post)
        except Exception:
            if self.enforce:
                return await _respond(send, 503, _UNAVAILABLE)
            return await self.app(scope, replay, send)
        scope.setdefault("state", {})["agent_check"] = c
        if self.on_decision:
            self.on_decision(c, info)
        if self.enforce and c["decision"] != "allow":
            return await _respond(send, _status(c), _view(c))
        return await self.app(scope, replay, send)


async def _respond(send, status: int, body: dict):
    data = json.dumps(body).encode()
    await send({"type": "http.response.start", "status": status, "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(data)).encode())]})
    await send({"type": "http.response.body", "body": data})


def django_middleware(*, cart, policy: dict | None = None, approval=None, paths: list[str] | None = None, endpoint: str = ENDPOINT,
                      enforce: bool = True, public_origin: str | None = None, on_decision=None, post=_post):
    """Django: `MIDDLEWARE = [..., "myapp.middleware.commerce_check"]` where myapp/middleware.py has
    `commerce_check = django_middleware(cart=cart_for, policy={...})`. Same options as CommerceCheckMiddleware; sets request.agent_check."""

    def factory(get_response):
        def middleware(request):
            if paths and not any(request.path.startswith(p) for p in paths):
                return get_response(request)
            from django.http import JsonResponse  # only a Django project has it

            headers = {k.lower(): v for k, v in request.headers.items()}
            raw = request.body
            url = request.build_absolute_uri()
            if public_origin:
                url = public_origin.rstrip("/") + re.sub(r"^https?://[^/]+", "", url)
            info = {"method": request.method, "url": url, "headers": headers, **({"body": raw.decode("utf-8", "replace")} if raw else {})}
            try:
                c = agent_check(info, cart(info, agent_did_of(headers)), policy, approval=approval(info) if approval else None, endpoint=endpoint, post=post)
            except Exception:
                return JsonResponse(_UNAVAILABLE, status=503) if enforce else get_response(request)
            request.agent_check = c
            if on_decision:
                on_decision(c, info)
            if enforce and c["decision"] != "allow":
                return JsonResponse(_view(c), status=_status(c))
            return get_response(request)

        return middleware

    return factory
