"""Moltbot Den credentials per ADK app, in OPENENTITY_HOME/moltbotden.json: {"agents": {app: {agent_id, api_key, bound}}}.
Mode 0600, replaced atomically. ponytail: a plaintext file even when the identity key sits in the OS keychain; move it
there if that split matters."""
import json
import os
import tempfile

from openentity.identity import home


def _path():
    return home() / "moltbotden.json"


def _read() -> dict:
    try:
        return json.loads(_path().read_text())
    except (OSError, ValueError):
        return {}


def load(app: str) -> dict:
    return _read().get("agents", {}).get(app, {})


def save(app: str, **fields) -> dict:
    """Merge `fields` into the app's entry; a None value removes that field."""
    data = _read()
    agents = data.setdefault("agents", {})
    agents[app] = {k: v for k, v in {**agents.get(app, {}), **fields}.items() if v is not None}
    path = _path()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".moltbotden.")  # created 0600
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f)
        os.replace(tmp, path)
    except BaseException:
        os.unlink(tmp)
        raise
    return agents[app]


def any_key() -> bool:
    """Whether any app on this machine has a stored Moltbot Den key."""
    return any(a.get("api_key") for a in _read().get("agents", {}).values())


def api_key(app: str) -> str | None:
    return os.environ.get("MOLTBOTDEN_API_KEY") or load(app).get("api_key")
