"""RFC 9421 HTTP message signatures, Open Entity profile: ed25519, keyid = the signer's did:key,
covered ("@method" "@target-uri" "content-digest"), Content-Digest per RFC 9530, label sig1."""
import base64
import hashlib
import os
import re
import time
from collections.abc import Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from . import core

SKEW = 5  # seconds of clock skew allowed on `created`


class HttpSigError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _digest(body: bytes) -> str:
    return f"sha-256=:{base64.b64encode(hashlib.sha256(body).digest()).decode()}:"


def _base(method: str, url: str, components: list[str], digest: str | None, params: str) -> bytes:
    lines = []
    for c in components:
        v = {"@method": method.upper(), "@target-uri": url, "content-digest": digest}[c]
        lines.append(f'"{c}": {v}')
    lines.append(f'"@signature-params": {params}')
    return "\n".join(lines).encode()


def _seed(key) -> bytes:
    for attr in ("seed", "kp"):  # Identity -> KeyPair -> seed
        if hasattr(key, attr):
            return _seed(getattr(key, attr))
    if isinstance(key, (bytes, bytearray)) and len(key) == 32:
        return bytes(key)
    raise ValueError("private_key must be an Identity, a KeyPair or a 32-byte Ed25519 seed")


def sign_request(method: str, url: str, body: bytes, private_key, did: str, *, created: int | None = None,
                 expires_in: int = 60, nonce: str | None = None) -> dict[str, str]:
    created = int(time.time()) if created is None else created
    nonce = nonce or _b64url(os.urandom(16))
    out = {}
    comps = ["@method", "@target-uri"]
    if body:
        out["Content-Digest"] = _digest(body)
        comps.append("content-digest")
    params = f'({" ".join(chr(34) + c + chr(34) for c in comps)});created={created};expires={created + expires_in};nonce="{nonce}";keyid="{did}";alg="ed25519"'
    sig = Ed25519PrivateKey.from_private_bytes(_seed(private_key)).sign(_base(method, url, comps, out.get("Content-Digest"), params))
    out["Signature-Input"] = f"sig1={params}"
    out["Signature"] = f"sig1=:{base64.b64encode(sig).decode()}:"
    return out


def verify_request(method: str, url: str, headers: Mapping[str, str], body: bytes, *, now: int | None = None,
                   max_age: int = 300) -> dict:
    h = {k.lower(): v for k, v in headers.items()}
    if "signature-input" not in h or "signature" not in h:
        raise HttpSigError("missing_headers")
    m = re.search(r"(?:^|,)\s*sig1=(\(([^)]*)\)((?:;[a-z]+=(?:\d+|\"[^\"]*\"))*))", h["signature-input"])
    s = re.search(r"(?:^|,)\s*sig1=:([A-Za-z0-9+/]+={0,2}):", h["signature"])
    if not m or not s:
        raise HttpSigError("missing_headers")
    params, comps = m.group(1), re.findall(r'"([^"]*)"', m.group(2))
    p = {k: (v[1:-1] if v.startswith('"') else int(v)) for k, v in re.findall(r";([a-z]+)=(\d+|\"[^\"]*\")", m.group(3))}
    if p.get("alg") != "ed25519":
        raise HttpSigError("unknown_alg")
    keyid = p.get("keyid", "")
    try:
        public = core.public_from_did_key(keyid)
        if core.did_key(public) != keyid:
            raise ValueError
    except Exception:
        raise HttpSigError("bad_keyid") from None
    if not (isinstance(p.get("created"), int) and isinstance(p.get("expires"), int)):
        raise HttpSigError("missing_headers")
    if len(p.get("nonce", "")) < 22:  # 16 bytes in base64url
        raise HttpSigError("missing_nonce")
    if comps[:2] != ["@method", "@target-uri"] or comps[2:] not in ([], ["content-digest"]):
        raise HttpSigError("missing_headers")
    digest = None
    if body or "content-digest" in comps:
        digest = h.get("content-digest")
        if "content-digest" not in comps or digest != _digest(body):
            raise HttpSigError("digest_mismatch")
    now = int(time.time()) if now is None else now
    if p["created"] > now + SKEW:
        raise HttpSigError("created_in_future")
    if now - p["created"] > max_age:
        raise HttpSigError("created_too_old")
    if p["expires"] < now:
        raise HttpSigError("expired")
    if p["expires"] - p["created"] > max_age:
        raise HttpSigError("lifetime_too_long")
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(base64.b64decode(s.group(1)), _base(method, url, comps, digest, params))
    except (InvalidSignature, ValueError):
        raise HttpSigError("bad_signature") from None
    return {"did": keyid, "keyid": keyid, "created": p["created"], "expires": p["expires"], "nonce": p["nonce"]}
