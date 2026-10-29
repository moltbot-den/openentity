import os
import stat

import pytest

from openentity import identity
from openentity.identity import Identity


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENENTITY_HOME", str(tmp_path))
    monkeypatch.setenv("OPENENTITY_KEYCHAIN", "off")
    return tmp_path


def test_file_fallback_is_0600_and_stable():
    a = Identity.load_or_create()
    f = identity._file()
    assert a.source == "file" and stat.S_IMODE(f.stat().st_mode) == 0o600 and stat.S_IMODE(f.parent.stat().st_mode) == 0o700
    b = Identity.load_or_create()
    assert (b.did, b.source) == (a.did, "file") and b.seed == a.seed


def test_keychain_wins_and_holds_the_only_copy(monkeypatch):
    store = {}

    def run(argv, stdin=None):
        if argv[0] == "security" and argv[1] == "find-generic-password":
            return store.get("k")
        if argv[0] == "security":
            store["k"] = argv[-1]
            return ""
        return None

    monkeypatch.delenv("OPENENTITY_KEYCHAIN")
    monkeypatch.setattr(identity, "_run", run)
    monkeypatch.setattr(identity.sys, "platform", "darwin")
    a = Identity.load_or_create()
    assert a.source == "keychain" and store["k"] == a.seed.hex() and not identity._file().exists()
    assert Identity.load_or_create().did == a.did


def test_keychain_failure_falls_back_to_file(monkeypatch):
    monkeypatch.delenv("OPENENTITY_KEYCHAIN")
    monkeypatch.setattr(identity, "_run", lambda argv, stdin=None: None)  # no `security`, no `secret-tool`
    assert Identity.load_or_create().source == "file"


def test_load_never_creates_a_key(home):
    """Read-only callers (a trust gate) must not mint an identity as a side effect."""
    assert Identity.load() is None
    assert not (home / "identity.key").exists()
    a = Identity.load_or_create()
    assert Identity.load().did == a.did


def test_home_follows_openentity_home(home):
    assert identity.home() == home
