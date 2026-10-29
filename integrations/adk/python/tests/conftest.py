import asyncio
import json

import httpx
import openentity
import pytest
from openentity import Identity

SEED = bytes(range(32))


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENENTITY_HOME", str(tmp_path))
    monkeypatch.setenv("OPENENTITY_KEYCHAIN", "off")
    monkeypatch.delenv("MOLTBOTDEN_API_KEY", raising=False)
    return tmp_path


@pytest.fixture
def ident():
    return Identity(SEED, "test")


class Den:
    """A fake Moltbot Den: records every call, answers from `routes` ({path: status or (status, json)})."""

    def __init__(self):
        self.calls, self.routes = [], {}
        self.entity_status = lambda: 404  # GET /v1/entities/{eid} on the registry; the registry fixture replaces it
        self.client = httpx.AsyncClient(transport=httpx.MockTransport(self.handle))

    def handle(self, req: httpx.Request) -> httpx.Response:
        if req.url.path.startswith("/v1/entities/"):
            return httpx.Response(self.entity_status(), json={})
        body = json.loads(req.content) if req.content else None
        self.calls.append((req.url.path, req.headers.get("x-api-key"), body))
        r = self.routes.get(req.url.path, (200, {}))
        status, data = r if isinstance(r, tuple) else (r, {})
        return httpx.Response(status, json=data)

    def paths(self):
        return [c[0] for c in self.calls]


@pytest.fixture
def den():
    d = Den()
    d.routes = {
        "/agents/register": (201, {"api_key": "mbd_key"}),
        "/entity/openentity/bind/challenge": (200, {"nonce": "nonce-bind-0123456789"}),
        "/entity/openentity/bind/verify": (200, {"success": True}),
        "/heartbeat/challenge": (200, {"nonce": "nonce-renew-0123456789"}),
        "/heartbeat/sovereign": (200, {"success": True, "lease_days": 7}),
        "/heartbeat": (200, {"success": True}),
    }
    return d


@pytest.fixture
def registry(monkeypatch, den):
    """Registry reads/writes: GET entity 404 until adopted. Returns the list of adopt() kwargs."""
    state = {"adopted": False, "adopts": []}
    den.entity_status = lambda: 200 if state["adopted"] else 404

    def adopt(name, description="", registry="", seed=None, client=None):
        state["adopts"].append({"name": name, "seed": seed, "client": client})
        state["adopted"] = True
        return {}

    monkeypatch.setattr(openentity, "adopt", adopt)
    return state


class Clock:
    """Replaces asyncio.sleep: records delays, returns instantly, parks forever after `limit` sleeps."""

    def __init__(self, limit=3):
        self.delays, self.limit = [], limit

    async def __call__(self, delay):
        self.delays.append(delay)
        await asyncio.sleep(0)
        if len(self.delays) >= self.limit:
            await asyncio.Event().wait()
