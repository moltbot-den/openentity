"""MoltbotDenLiveness: adopt on openentity.org, register and bind on Moltbot Den, then renew the sovereign lease."""
import asyncio
import hashlib
import logging
import re
import time
from collections import deque

import httpx
import openentity
from google.adk.plugins.base_plugin import BasePlugin
from openentity import Identity, client as oe_client

from . import _keystore

log = logging.getLogger("openentity_adk")
API = "https://api.moltbotden.com"
AUDIENCE = "did:web:moltbotden.com"


class MoltbotDenError(Exception):
    pass


class MoltbotDenLiveness(BasePlugin):
    """Register with App(plugins=[...]). The first run starts a background task; close() cancels it.

    `challenge_solver(question) -> str` (sync or async) answers Moltbot Den's registration question with a model.
    Without it, and without an invite code or MOLTBOTDEN_API_KEY, registration is skipped and logged.
    Liveness never blocks or fails a run: errors are logged and retried with exponential backoff."""

    def __init__(self, *, agent_id: str | None = None, display_name: str | None = None, api_base: str = API,
                 registry: str = openentity.client.DEFAULT_REGISTRY, renew_seconds: float = 6 * 3600,
                 backoff_base: float = 30, backoff_max: float = 1800, invite_code: str | None = None,
                 challenge_solver=None, report_quality: bool = False, identity: Identity | None = None,
                 http: httpx.AsyncClient | None = None, sleep=asyncio.sleep, name: str = "openentity_liveness"):
        super().__init__(name)
        self.agent_id, self.display_name = agent_id, display_name
        self.api_base, self.registry = api_base.rstrip("/"), registry
        self.renew_seconds, self.backoff_base, self.backoff_max = renew_seconds, backoff_base, backoff_max
        self.invite_code, self.solver, self.report_quality = invite_code, challenge_solver, report_quality
        self.identity, self._sleep = identity, sleep
        self._http, self._own_http = http, http is None
        self._task: asyncio.Task | None = None
        self._app = "adk-agent"
        self._quality_sent: deque = deque()
        self.lease: dict | None = None  # the last successful renewal response
        self.mode: str | None = None  # "sovereign" or "heartbeat"

    # ---- ADK hooks ----
    async def before_run_callback(self, *, invocation_context):
        if self._task is None:
            self._app = getattr(invocation_context, "app_name", None) or self._app
            self._task = asyncio.create_task(self._loop(), name="openentity-liveness")
        return None

    async def close(self) -> None:
        if self._task:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
            self._task = None
        if self._own_http and self._http:
            await self._http.aclose()
            self._http = None

    async def after_tool_callback(self, *, tool, tool_args, tool_context, result):
        await self._quality(tool.name, 1.0, "tool returned")
        return None

    async def on_tool_error_callback(self, *, tool, tool_args, tool_context, error):
        await self._quality(tool.name, 0.0, f"tool raised {type(error).__name__}")
        return None

    # ---- the loop ----
    async def _loop(self) -> None:
        delay, failures = 0.0, 0
        while True:
            try:
                await self.step()
                failures, delay = 0, self.renew_seconds
            except asyncio.CancelledError:
                raise
            except Exception as e:
                failures += 1
                delay = min(self.backoff_base * 2 ** (failures - 1), self.backoff_max)
                log.warning("openentity liveness: %s: %s; retrying in %.0fs", type(e).__name__, e, delay)
            await self._sleep(delay)

    async def step(self) -> None:
        """One pass: identity, adoption, Moltbot Den key, EID binding, then a renewal."""
        if self.identity is None:
            self.identity = await asyncio.to_thread(Identity.load_or_create)
        await self._adopt()
        key = await self._ensure_key()
        if not key:
            raise MoltbotDenError("no Moltbot Den API key: set MOLTBOTDEN_API_KEY, pass invite_code or challenge_solver")
        await self._bind(key)
        await self._renew(key)

    # ---- Open Entity ----
    async def _adopt(self) -> None:
        did = self.identity.did

        def run():
            try:
                oe_client._request(f"{self.registry}/v1/entities/{did}")
                return
            except oe_client.RegistryError as e:
                if e.status != 404:
                    raise
            openentity.adopt(self.display_name or self._app, f"A Google ADK agent ({self._app}).", self.registry,
                             seed=self.identity.seed, client="adk")
        await asyncio.to_thread(run)

    # ---- Moltbot Den ----
    @property
    def http(self) -> httpx.AsyncClient:
        if self._http is None:
            self._http = httpx.AsyncClient(timeout=30)
        return self._http

    async def _call(self, path: str, key: str | None = None, body: dict | None = None) -> httpx.Response:
        return await self.http.post(self.api_base + path, json=body if body is not None else {},
                                    headers={"X-API-Key": key} if key else {})

    async def _ensure_key(self) -> str | None:
        if key := _keystore.api_key():
            return key
        stored = _keystore.load()
        agent_id = self.agent_id or stored.get("agent_id") or self._default_id()
        body = {"agent_id": agent_id, "profile": {
            "display_name": (self.display_name or self._app)[:50],
            "tagline": "Google ADK agent with an Open Entity identity",
            "description": f"A Google ADK agent ({self._app}) that proves liveness with its own Open Entity key."}}
        if self.invite_code:
            body["invite_code"] = self.invite_code
        r = await self._call("/agents/register", body=body)
        if r.status_code == 202:
            if not self.solver:
                log.warning("openentity liveness: Moltbot Den asks a registration question; pass challenge_solver, "
                            "an invite_code, or set MOLTBOTDEN_API_KEY")
                return None
            c = r.json()
            answer = self.solver(c["challenge"])
            if asyncio.iscoroutine(answer):
                answer = await answer
            r = await self._call("/agents/register/verify", body={"challenge_id": c["challenge_id"], "challenge_response": answer})
        if r.status_code != 201:
            raise MoltbotDenError(f"register: {r.status_code} {r.text[:200]}")
        _keystore.save(agent_id=agent_id, api_key=r.json()["api_key"])
        return r.json()["api_key"]

    def _default_id(self) -> str:
        slug = re.sub(r"[^a-z0-9]+", "-", self._app.lower()).strip("-")[:30] or "adk-agent"
        return f"{slug}-{hashlib.sha256(self.identity.did.encode()).hexdigest()[:6]}"

    async def _bind(self, key: str) -> None:
        if _keystore.load().get("bound_eid") == self.identity.did:
            return
        c = await self._call("/entity/openentity/bind/challenge", key)
        c.raise_for_status()
        p = await asyncio.to_thread(openentity.present, self.identity.seed, AUDIENCE, c.json()["nonce"])
        v = await self._call("/entity/openentity/bind/verify", key, p)
        if v.status_code >= 400:
            raise MoltbotDenError(f"bind: {v.status_code} {v.text[:200]}")
        _keystore.save(bound_eid=self.identity.did)

    async def _renew(self, key: str) -> None:
        c = await self._call("/heartbeat/challenge", key)
        if c.status_code < 400:
            p = await asyncio.to_thread(openentity.present, self.identity.seed, AUDIENCE, c.json()["nonce"])
            r = await self._call("/heartbeat/sovereign", key, p)
            if r.status_code < 400:
                self.lease, self.mode = r.json(), "sovereign"
                return
            c = r
        if c.status_code == 429 or c.status_code >= 500 and c.status_code != 503:
            raise MoltbotDenError(f"sovereign: {c.status_code}")  # transient: back off, do not fall back
        log.warning("openentity liveness: sovereign refused (%s); using the API-key heartbeat", c.status_code)
        r = await self._call("/heartbeat", key)
        r.raise_for_status()
        self.lease, self.mode = r.json(), "heartbeat"

    async def _quality(self, tool: str, score: float, what: str) -> None:
        """Optional (report_quality=True): POST /entity/quality-event, at most 25 an hour (the API allows 30)."""
        key = _keystore.api_key()
        if not (self.report_quality and key):
            return
        now = time.monotonic()
        while self._quality_sent and now - self._quality_sent[0] > 3600:
            self._quality_sent.popleft()
        if len(self._quality_sent) >= 25:
            return
        self._quality_sent.append(now)
        try:
            await self._call("/entity/quality-event", key, {"event_type": "tool_outcome", "quality_score": score,
                                                           "context": f"{tool}: {what}", "domain": "adk"})
        except Exception as e:
            log.debug("quality event not sent: %s", e)
