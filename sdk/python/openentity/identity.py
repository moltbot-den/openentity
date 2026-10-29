"""Identity.load_or_create(): the entity's key from the OS keychain, else ~/.openentity/identity.key (mode 0600).
A fresh key goes to the keychain when one answers, otherwise to the file. Set OPENENTITY_KEYCHAIN=off to use the file only."""
import os
import pathlib
import subprocess
import sys

from . import core

SERVICE, ACCOUNT = "openentity", "identity"


def _run(argv: list[str], stdin: str | None = None) -> str | None:
    try:
        r = subprocess.run(argv, input=stdin, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    return r.stdout.strip() if r.returncode == 0 else None


def _keychain_get() -> str | None:
    if os.environ.get("OPENENTITY_KEYCHAIN") == "off":
        return None
    if sys.platform == "darwin":
        return _run(["security", "find-generic-password", "-s", SERVICE, "-a", ACCOUNT, "-w"])
    if sys.platform.startswith("linux"):
        return _run(["secret-tool", "lookup", "service", SERVICE, "account", ACCOUNT])


def _keychain_set(seed_hex: str) -> bool:
    if os.environ.get("OPENENTITY_KEYCHAIN") == "off":
        return False
    if sys.platform == "darwin":  # ponytail: the seed is briefly on argv, visible to this user's processes only
        return _run(["security", "add-generic-password", "-U", "-s", SERVICE, "-a", ACCOUNT, "-w", seed_hex]) is not None
    if sys.platform.startswith("linux"):
        return _run(["secret-tool", "store", "--label=Open Entity key", "service", SERVICE, "account", ACCOUNT], seed_hex) is not None
    return False


def home() -> pathlib.Path:
    """OPENENTITY_HOME, else ~/.openentity: where the key file and integrations' state live."""
    return pathlib.Path(os.environ.get("OPENENTITY_HOME", "~/.openentity")).expanduser()


def _file() -> pathlib.Path:
    return home() / "identity.key"


class Identity:
    def __init__(self, seed: bytes, source: str):
        self.kp, self.source = core.KeyPair(seed), source

    @property
    def did(self) -> str:
        return self.kp.did

    @property
    def seed(self) -> bytes:  # pass to adopt(), present(), record() and the other seed-keyed calls
        return self.kp.seed

    @classmethod
    def load(cls) -> "Identity | None":
        """The existing identity, or None. Never creates one."""
        for source, read in (("keychain", _keychain_get), ("file", lambda: _file().read_text().strip() if _file().exists() else None)):
            if h := read():
                return cls(bytes.fromhex(h), source)
        return None

    @classmethod
    def load_or_create(cls) -> "Identity":
        if found := cls.load():
            return found
        seed = os.urandom(32)
        if _keychain_set(seed.hex()):
            return cls(seed, "keychain")
        path = _file()
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:  # another process created it first
            return cls(bytes.fromhex(path.read_text().strip()), "file")
        with os.fdopen(fd, "w") as f:
            f.write(seed.hex())
        return cls(seed, "file")
