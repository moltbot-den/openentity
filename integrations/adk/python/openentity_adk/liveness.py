"""MoltbotDenLiveness: adopt on openentity.org, register and bind on Moltbot Den, then renew the sovereign lease."""
import asyncio
import hashlib
import logging
import os
import re
import time
from collections import deque

import httpx
import openentity
from google.adk.plugins.base_plugin import BasePlugin
from openentity import Identity

from . import _keystore

log = logging.getLogger("openentity_adk")
API = "https://api.moltbotden.com"
AUDIENCE = "did:web:moltbotden.com"
SOVEREIGN_OFF = 503  # Moltbot Den's answer when sovereign leases are switched off: use the API-key heartbeat


class MoltbotDenError(Exception):
    """A liveness pass failed; the loop retries with backoff."""


class MoltbotDenStopped(MoltbotDenError):
    """A failure retrying cannot fix. The loop logs it once and stops."""


class _Unauthorized(MoltbotDenError):
    pass


class MoltbotDenLiveness(BasePlugin):
    """Register with App(plugins=[...]). The first run starts a background task; close() cancels it.

    Nothing is published or registered unless the plugin has a way to a Moltbot Den API key: MOLTBOTDEN_API_KEY, a key
    stored by an earlier run, `invite_code`, `challenge_solver`, or the root agent's own model, which answers the one
    question Moltbot Den asks a new agent. `challenge_solver(question) -> str` (sync or async) replaces the model.
    Liveness never blocks or fails a run: errors are logged and retried with exponential backoff."""

    def __init__(self, *, agent_id: str | None = None, display_name: str | None = None, api_base: str = API,
                 registry: str = openentity.client.DEFAULT_REGISTRY, renew_seconds: float = 6 * 3600,
                 backoff_base: float = 30, backoff_max: float = 1800, invite_code: str | None = None,
                 challenge_solver=None, report_quality: bool = False, identity: Identity | None = None,
                 http: httpx.AsyncClient | None = None, sleep=asyncio.sleep, name: str = "openentity_liveness"):
        super().__init__(name)
        self.agent_id, self.display_name = agent_id, display_name
        self.api_base, self.registry = api_base.rstrip("/"), registry.rstrip("/")
        self.renew_seconds, self.backoff_base, self.backoff_max = renew_seconds, backoff_base, backoff_max
        self.invite_code, self.solver, self.report_quality = invite_code, challenge_solver, report_quality
        self.identity, self._sleep = identity, sleep
        self._http, self._own_http = http, http is None
        self._task: asyncio.Task | None = None
        self._stopped = False
        self._app = "adk-agent"
        self._model = None  # the root agent's model, the default challenge solver
        self._quality_sent: deque = deque()
        self._bg: set[asyncio.Task] = set()  # quality reports in flight
        self.lease: dict | None = None  # the last successful renewal response
        self.mode: str | None = None  # "sovereign" or "heartbeat"

    # ---- ADK hooks ----
    async def before_run_callback(self, *, invocation_context):
        if self._stopped or (self._task and not self._task.done()):
            return None  # a task that is done belongs to an event loop that has ended: start a new one
        self._app = getattr(invocation_context, "app_name", None) or self._app
        try:
            self._model = invocation_context.agent.canonical_model
        except Exception:  # not an LlmAgent
            self._model = None
        self._task = asyncio.create_task(self._loop(), name="openentity-liveness")
        return None

    async def close(self) -> None:
        if self._task:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
            self._task = None
        await self._close_http()

    async def after_tool_callback(self, *, tool, tool_args, tool_context, result):
        self._report(tool.name, 1.0, "tool returned")
        return None

    async def on_tool_error_callback(self, *, tool, tool_args, tool_context, error):
        self._report(tool.name, 0.0, f"tool raised {type(error).__name__}")
        return None

    # ---- the loop ----
    async def _loop(self) -> None:
        if self._own_http:
            self._http = None  # a client from an earlier event loop cannot be reused
        delay, failures = 0.0, 0
        try:
            while True:
                try:
                    await self.step()
                    failures, delay = 0, self.renew_seconds
                except asyncio.CancelledError:
                    raise
                except MoltbotDenStopped as e:
                    self._stopped = True
                    log.error("openentity liveness stopped: %s", e)
                    return
                except Exception as e:
                    failures += 1
                    delay = min(self.backoff_base * 2 ** (failures - 1), self.backoff_max)
                    log.warning("openentity liveness: %s: %s; retrying in %.0fs", type(e).__name__, e, delay)
                await self._sleep(delay)
        finally:
            await self._close_http()

    async def step(self) -> None:
        """One pass: identity, adoption, Moltbot Den key, EID binding, then a renewal."""
        if not (_keystore.api_key(self._app) or self.invite_code or self.solver or self._model):
            raise MoltbotDenStopped("no way to a Moltbot Den API key: set MOLTBOTDEN_API_KEY, pass invite_code or "
                                    "challenge_solver, or run it on an LlmAgent so its model can answer")
        if self.identity is None:
            self.identity = await asyncio.to_thread(Identity.load_or_create)
        await self._adopt()
        try:
            await self._session()
        except _Unauthorized:
            if os.environ.get("MOLTBOTDEN_API_KEY"):
                raise MoltbotDenStopped("Moltbot Den rejected MOLTBOTDEN_API_KEY (401)") from None
            _keystore.save(self._app, api_key=None, bound=None)  # a revoked stored key: register again, once
            try:
                await self._session()
            except _Unauthorized:
                raise MoltbotDenStopped("Moltbot Den rejected a freshly registered key (401)") from None

    async def _session(self) -> None:
        key = await self._ensure_key()
        await self._bind(key)
        await self._renew(key)

    # ---- Open Entity ----
    async def _adopt(self) -> None:
        r = await self.http.get(f"{self.registry}/v1/entities/{self.identity.did}")
        if r.status_code == 200:
            return
        if r.status_code != 404:
            raise MoltbotDenError(f"registry: {r.status_code}")
        await asyncio.to_thread(openentity.adopt, self.display_name or self._app, f"An ADK agent ({self._app}).",
                                self.registry, seed=self.identity.seed, client="adk")

    # ---- Moltbot Den ----
    @property
    def http(self) -> httpx.AsyncClient:
        if self._http is None:
            self._http = httpx.AsyncClient(timeout=30)
        return self._http

    async def _close_http(self) -> None:
        if self._own_http and self._http:
            await self._http.aclose()
            self._http = None

    async def _call(self, path: str, key: str | None = None, body: dict | None = None) -> httpx.Response:
        r = await self.http.post(self.api_base + path, json=body if body is not None else {},
                                 headers={"X-API-Key": key} if key else {})
        if key and r.status_code == 401 and "www-authenticate" in r.headers:  # the API key itself was rejected
            raise _Unauthorized(f"{path}: 401")
        if key and r.status_code == 403:  # a suspended agent or a key that signs for another EID: a new agent would not fix it
            raise MoltbotDenStopped(f"{path}: 403 {r.text[:200]}")
        return r

    async def _ensure_key(self) -> str:
        if key := _keystore.api_key(self._app):
            return key
        agent_id = self.agent_id or _keystore.load(self._app).get("agent_id") or self._default_id()
        body = {"agent_id": agent_id, "profile": {
            "display_name": (self.display_name or self._app)[:50],
            "tagline": "ADK agent with an Open Entity identity",
            "description": f"An ADK agent ({self._app}) that proves liveness with its own Open Entity key."}}
        if self.invite_code:
            body["invite_code"] = self.invite_code
        r = await self._call("/agents/register", body=body)
        if r.status_code == 202:
            solver = self.solver or (self._model and self._model_answer)
            if not solver:
                raise MoltbotDenStopped("Moltbot Den asks a registration question; pass challenge_solver or invite_code")
            c = r.json()
            answer = solver(c["challenge"])
            if asyncio.iscoroutine(answer):
                answer = await answer
            r = await self._call("/agents/register/verify", body={"challenge_id": c["challenge_id"], "challenge_response": answer})
        if r.status_code == 429:
            raise MoltbotDenStopped("Moltbot Den registers one agent per network without an invite; "
                                    "pass invite_code or set MOLTBOTDEN_API_KEY to an existing agent's key")
        if r.status_code != 201:
            raise MoltbotDenError(f"register: {r.status_code} {r.text[:200]}")
        key = r.json()["api_key"]
        _keystore.save(self._app, agent_id=agent_id, api_key=key)
        return key

    async def _model_answer(self, question: str) -> str:
        from google.adk.models.llm_request import LlmRequest
        from google.genai import types
        req = LlmRequest(model=self._model.model, contents=[types.Content(role="user", parts=[types.Part(text=question)])])
        async for resp in self._model.generate_content_async(req):
            return "".join(p.text or "" for p in (resp.content.parts if resp.content else []))
        return ""

    def _default_id(self) -> str:
        slug = re.sub(r"[^a-z0-9]+", "-", self._app.lower()).strip("-")[:30] or "adk-agent"
        return f"{slug}-{hashlib.sha256(self.identity.did.encode()).hexdigest()[:6]}"

    async def _bind(self, key: str) -> None:
        bound = f"{self.identity.did}|{hashlib.sha256(key.encode()).hexdigest()[:16]}"  # the binding is per agent key
        if _keystore.load(self._app).get("bound") == bound:
            return
        c = await self._call("/entity/openentity/bind/challenge", key)
        c.raise_for_status()
        p = await asyncio.to_thread(openentity.present, self.identity.seed, AUDIENCE, c.json()["nonce"])
        v = await self._call("/entity/openentity/bind/verify?framework=adk", key, p)  # listed as cap:framework-adk
        if v.status_code >= 400:
            raise MoltbotDenError(f"bind: {v.status_code} {v.text[:200]}")
        _keystore.save(self._app, bound=bound)

    async def _renew(self, key: str) -> None:
        c = await self._call("/heartbeat/challenge", key)
        if c.status_code < 400:
            p = await asyncio.to_thread(openentity.present, self.identity.seed, AUDIENCE, c.json()["nonce"])
            r = await self._call("/heartbeat/sovereign", key, p)
            if r.status_code < 400:
                self.lease, self.mode = r.json(), "sovereign"
                return
            c = r
        transient = c.status_code == 429 or (c.status_code >= 500 and c.status_code != SOVEREIGN_OFF)
        if transient:
            raise MoltbotDenError(f"sovereign: {c.status_code}")  # back off, do not fall back
        log.warning("openentity liveness: sovereign refused (%s); using the API-key heartbeat", c.status_code)
        r = await self._call("/heartbeat", key)
        r.raise_for_status()
        self.lease, self.mode = r.json(), "heartbeat"

    def _report(self, tool: str, score: float, what: str) -> None:
        """Optional (report_quality=True): POST /entity/quality-event in the background, at most 25 an hour (the API
        allows 30). The tool path never waits on it."""
        key = _keystore.api_key(self._app)
        if not (self.report_quality and key):
            return
        now = time.monotonic()
        while self._quality_sent and now - self._quality_sent[0] > 3600:
            self._quality_sent.popleft()
        if len(self._quality_sent) >= 25:
            return
        self._quality_sent.append(now)
        body = {"event_type": "tool_outcome", "quality_score": score, "context": f"{tool}: {what}", "domain": "adk"}
        task = asyncio.create_task(self._send_quality(key, body))
        self._bg.add(task)
        task.add_done_callback(self._bg.discard)

    async def _send_quality(self, key: str, body: dict) -> None:
        try:
            await self._call("/entity/quality-event", key, body)
        except Exception as e:
            log.debug("quality event not sent: %s", e)
