"""RFC 9421 HTTP message signatures, Open Entity profile: ed25519, keyid = the signer's did:key, or did:web:<host>#<key> for a
did:web signer the verifier allows (services such as the OpenEntity Account), covered ("@method" "@target-uri"
"content-digest"), Content-Digest per RFC 9530, label sig1."""
import base64
import hashlib
import json
import os
import re
import time
import urllib.request
from collections.abc import Mapping
from urllib.parse import unquote

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from . import core
from .errors import HttpSigError, InvalidInputError

SKEW = 5  # seconds of clock skew allowed on `created`
_DID_CACHE_S = 600  # the account service serves did.json with max-age=600
_DID_REFETCH_S = 30  # an unknown key refetches, at most this often per DID
_did_web_keys: dict[str, tuple[float, dict[str, bytes]]] = {}  # did -> (fetched at, Ed25519 keys by method id)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None  # did.json is served where the DID says, not elsewhere


def _did_json(url: str):
    req = urllib.request.Request(url, headers={"accept": "application/did+json, application/json"})
    with urllib.request.build_opener(_NoRedirect).open(req, timeout=5) as r:
        return json.load(r)


def _did_web_url(did: str) -> str:
    """The did.json URL of a did:web DID: /.well-known/did.json, or <path>/did.json for a DID with a path."""
    host, *path = [unquote(p) for p in did[len("did:web:"):].split(":")]
    return f"https://{host}/{'/'.join(path) if path else '.well-known'}/did.json"


def _ed25519_methods(did: str, doc) -> dict[str, bytes]:
    if not isinstance(doc, dict) or doc.get("id") != did:
        raise ValueError("the document names another DID")
    keys = {}
    for vm in doc.get("verificationMethod") or []:
        if not isinstance(vm, dict) or not isinstance(vm.get("id"), str):
            continue
        try:
            jwk = vm.get("publicKeyJwk") or {}
            if vm.get("type") == "Multikey":
                key = core.public_key_from_did_key("did:key:" + vm["publicKeyMultibase"])
            elif vm.get("type") == "JsonWebKey" and jwk.get("kty") == "OKP" and jwk.get("crv") == "Ed25519":
                key = base64.urlsafe_b64decode(jwk["x"] + "=" * (-len(jwk["x"]) % 4))
                if _b64url(key) != jwk["x"]:
                    continue
            else:
                continue
        except (KeyError, TypeError, ValueError):
            continue
        if len(key) == 32:
            keys[did + vm["id"] if vm["id"].startswith("#") else vm["id"]] = key
    return keys


def _did_web_key(keyid: str, fetch) -> bytes | None:
    did = keyid.split("#")[0]
    at, keys = _did_web_keys.get(did, (None, {}))
    age = float("inf") if at is None else time.monotonic() - at
    if age < _DID_CACHE_S and (keyid in keys or age < _DID_REFETCH_S):
        return keys.get(keyid)
    keys = _ed25519_methods(did, fetch(_did_web_url(did)))
    _did_web_keys[did] = (time.monotonic(), keys)
    return keys.get(keyid)


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _digest(body: bytes) -> str:
    return f"sha-256=:{base64.b64encode(hashlib.sha256(body).digest()).decode()}:"


def http_sig_base(method: str, url: str, components: list[str], digest: str | None, params: str) -> bytes:
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
    raise InvalidInputError("private_key must be an Identity, a KeyPair or an Ed25519 seed")


def sign_request(method: str, url: str, body: bytes, private_key, did: str, *, created: int | None = None,
                 expires_in: int = 60, nonce: str | None = None) -> dict[str, str]:
    """Sign a request. `private_key` is an Identity, a KeyPair or an Ed25519 seed. Returns Signature-Input, Signature and, for a non-empty body, Content-Digest."""
    created = int(time.time()) if created is None else created
    nonce = nonce or _b64url(os.urandom(16))
    out = {}
    comps = ["@method", "@target-uri"]
    if body:
        out["Content-Digest"] = _digest(body)
        comps.append("content-digest")
    params = f'({" ".join(chr(34) + c + chr(34) for c in comps)});created={created};expires={created + expires_in};nonce="{nonce}";keyid="{did}";alg="ed25519"'
    sig = Ed25519PrivateKey.from_private_bytes(_seed(private_key)).sign(http_sig_base(method, url, comps, out.get("Content-Digest"), params))
    out["Signature-Input"] = f"sig1={params}"
    out["Signature"] = f"sig1=:{base64.b64encode(sig).decode()}:"
    return out


def verify_request(method: str, url: str, headers: Mapping[str, str], body: bytes, *, now: int | None = None,
                   max_age: int = 300, allow_did_web=(), fetch=None) -> dict:
    """Verify a request signed by sign_request. Raises HttpSigError with `.code`. Nonce replay tracking is the caller's job.

    A did:key keyid verifies offline. A did:web:<host>#<key> keyid verifies only when its DID is in `allow_did_web`: the key
    comes from the DID's did.json (Ed25519 Multikey or JsonWebKey), cached for ten minutes and refetched when it names an
    unknown key. `fetch(url)` returns the parsed document; the default is HTTPS with a short timeout and no redirects."""
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
    did, public = keyid.split("#")[0], None
    if keyid.startswith("did:web:"):
        # Allowed DIDs only, so a request never makes the verifier fetch a URL of the sender's choosing.
        if not re.fullmatch(r"did:web:[^#]+#[^#]+", keyid) or did not in allow_did_web:
            raise HttpSigError("bad_keyid")
    else:
        try:
            public = core.public_key_from_did_key(keyid)
            if core.did_key_from_public_key(public) != keyid:
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
    if public is None:
        try:
            public = _did_web_key(keyid, fetch or _did_json)
        except Exception:
            public = None
        if public is None:
            raise HttpSigError("bad_keyid")
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(base64.b64decode(s.group(1)), http_sig_base(method, url, comps, digest, params))
    except (InvalidSignature, ValueError):
        raise HttpSigError("bad_signature") from None
    return {"did": did, "keyid": keyid, "created": p["created"], "expires": p["expires"], "nonce": p["nonce"]}
