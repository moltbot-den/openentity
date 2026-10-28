"""The Moltbot Den API key and agent id, kept next to the Open Entity identity key (OPENENTITY_HOME, mode 0600).
ponytail: a file even when the identity key sits in the OS keychain; move it there if that split matters."""
import json
import os

from openentity import identity


def _path():
    return identity._file().parent / "moltbotden.json"


def load() -> dict:
    try:
        return json.loads(_path().read_text())
    except (OSError, ValueError):
        return {}


def save(**fields) -> dict:
    data = {**load(), **fields}
    path = _path()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(data, f)
    return data


def api_key() -> str | None:
    return os.environ.get("MOLTBOTDEN_API_KEY") or load().get("api_key")
