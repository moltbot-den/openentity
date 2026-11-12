"""Owner key logs (keylog-1, ADR 0007) and approval/2.0 (ADR 0008). Verify only: devices and passkeys sign, products verify.

The byte-level format and every rule are in test-vectors/keylog-1/README.md and test-vectors/approval-2.0/README.md.
tests/test_owner.py runs both vector sets; so do sdk/ts, sdk/swift and sdk/kotlin. Results are dicts shaped like the TS SDK's.
"""
import base64
import hashlib
import re
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, encode_dss_signature

from .core import canonicalize, parse_json
from .errors import InvalidInputError

RP_ID = "account.openentity.org"
_DAY = 86_400
_WEEK = 7 * _DAY
_MAX_TTL = 600
_MAX_SAFE = 2**53 - 1
_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_REQUEST_ID = re.compile(r"[A-Za-z0-9:._-]{1,128}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_DID = re.compile(r"did:[a-z0-9]+:[A-Za-z0-9._%:-]*[A-Za-z0-9._%-]")
_B64U = re.compile(r"[A-Za-z0-9_-]*")
_SURROGATE = re.compile("[\ud800-\udfff]")
_BODY = {"genesis": {"approver", "root"}, "add_approver": {"approver"}, "recover": {"approvers"}, "replace_root": {"root"},
         "cancel": {"target"}, "revoke": {"kid"}, "close": set()}


class _Fail(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _uint(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= _MAX_SAFE


def _sha(b: str | bytes) -> bytes:
    return hashlib.sha256(b.encode() if isinstance(b, str) else b).digest()


def _b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _b64u(s) -> bytes | None:
    """Strict base64url: no padding, and only the one encoding of the bytes."""
    if not isinstance(s, str) or not _B64U.fullmatch(s) or len(s) % 4 == 1:
        return None
    b = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    return b if _b64u_encode(b) == s else None


def _plain(v) -> str | None:
    """Only integers within 2^53 and well-formed strings, so all four SDKs read an entry or a summary the same way."""
    if isinstance(v, bool) or v is None:
        return None
    if isinstance(v, int):
        return None if abs(v) <= _MAX_SAFE else f"number {v} is not an integer within 2^53"
    if isinstance(v, float):
        return f"number {v} is not an integer within 2^53"
    if isinstance(v, str):
        return "string has a lone surrogate" if _SURROGATE.search(v) else None
    if isinstance(v, list):
        return next((e for e in map(_plain, v) if e), None)
    if isinstance(v, dict):
        return next((e for k, x in v.items() for e in (_plain(k), _plain(x)) if e), None)
    return f"not JSON: {type(v).__name__}"


def _base32(b: bytes) -> str:
    return base64.b32encode(b).decode().rstrip("=").lower()


# ---- P-256

def _point(jwk):
    if not isinstance(jwk, dict) or set(jwk) != {"kty", "crv", "x", "y"} or jwk["kty"] != "EC" or jwk["crv"] != "P-256":
        return None
    x, y = _b64u(jwk["x"]), _b64u(jwk["y"])
    if x is None or y is None or len(x) != 32 or len(y) != 32:
        return None
    try:
        return ec.EllipticCurvePublicNumbers(int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()).public_key()
    except ValueError:
        return None


def _thumbprint(jwk: dict) -> str:
    """RFC 7638 JWK thumbprint, base64url: the kid of every key in a log."""
    return _b64u_encode(_sha(f'{{"crv":"P-256","kty":"EC","x":"{jwk["x"]}","y":"{jwk["y"]}"}}'))


def _der_to_raw(der: bytes) -> bytes | None:
    """Strict DER SEQUENCE { INTEGER r, INTEGER s } to 64-byte r||s; None for any other encoding."""
    if len(der) < 8 or der[0] != 0x30 or der[1] != len(der) - 2 or der[1] > 0x7F:
        return None
    out, i = b"", 2
    for _ in range(2):
        if der[i] != 0x02:
            return None
        n = der[i + 1]
        v = der[i + 2:i + 2 + n]
        if n < 1 or n > 33 or len(v) != n or v[0] & 0x80 or (n > 1 and v[0] == 0 and not v[1] & 0x80) or (n == 33 and v[0]):
            return None
        out += (v[1:] if n == 33 else v).rjust(32, b"\0")
        i += 2 + n
    return out if i == len(der) else None


def _ecdsa(raw: bytes, msg: bytes, pub, prehashed: bool, low_s: bool) -> bool:
    r, s = int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")
    if not (0 < r < _N and 0 < s < _N) or (low_s and s > _N >> 1):
        return False
    try:
        pub.verify(encode_dss_signature(r, s), msg, ec.ECDSA(Prehashed(hashes.SHA256()) if prehashed else hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def _check_signature(cred: dict, s: dict, digest: bytes, origins, rp_id: str, low_s: bool) -> int:
    """A p256 or webauthn signature by `cred` over `digest`; returns the WebAuthn signature counter (0 for p256)."""
    if s.get("form") != cred["type"]:
        raise _Fail("bad_signature", f"a {cred['type']} key cannot present a {s.get('form')} signature")
    pub, sig = _point(cred["jwk"]), _b64u(s["signature"])
    if s["form"] == "p256":
        if len(sig) != 64 or not _ecdsa(sig, digest, pub, True, low_s):
            raise _Fail("bad_signature", "p256 signature does not verify")
        return 0
    auth_data, client_raw = _b64u(s["authenticator_data"]), _b64u(s["client_data_json"])
    try:
        client = parse_json(client_raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise _Fail("bad_webauthn", "clientDataJSON is not JSON")
    if not isinstance(client, dict) or client.get("type") != "webauthn.get":
        raise _Fail("bad_webauthn", "clientDataJSON type must be webauthn.get")
    if client.get("challenge") != _b64u_encode(digest):
        raise _Fail("bad_webauthn", "challenge is not the digest")
    if not isinstance(client.get("origin"), str) or client["origin"] not in origins:
        raise _Fail("bad_webauthn", f"origin {client.get('origin')} is not accepted")
    if client.get("crossOrigin") is True:
        raise _Fail("bad_webauthn", "cross-origin assertions are not accepted")
    if len(auth_data) < 37 or auth_data[:32] != _sha(rp_id):
        raise _Fail("bad_webauthn", f"rpIdHash is not SHA-256({rp_id})")
    if auth_data[32] & 0x05 != 0x05:
        raise _Fail("bad_webauthn", "user presence and user verification flags must be set")
    raw = _der_to_raw(sig)
    if raw is None or not _ecdsa(raw, auth_data + _sha(client_raw), pub, False, low_s):
        raise _Fail("bad_signature", "webauthn signature does not verify")
    return int.from_bytes(auth_data[33:37], "big")


def _signed_shape(s: dict) -> str | None:
    if s.get("form") not in ("p256", "webauthn"):
        return "form must be p256 or webauthn"
    if _b64u(s.get("signature")) is None:
        return "signature must be base64url"
    if s["form"] == "webauthn" and (_b64u(s.get("authenticator_data")) is None or _b64u(s.get("client_data_json")) is None):
        return "webauthn needs authenticator_data and client_data_json in base64url"
    return None


# ---- approval/2.0

def _fields_error(a: dict) -> str | None:
    for f in ("verifier_did", "owner_did"):
        if not isinstance(a.get(f), str) or not _DID.fullmatch(a[f]):
            return f"{f} must be a DID"
    if not isinstance(a.get("request_id"), str) or not _REQUEST_ID.fullmatch(a["request_id"]):
        return "request_id must be 1 to 128 of [A-Za-z0-9:._-]"
    if not isinstance(a.get("payload_digest"), str) or not _HEX64.fullmatch(a["payload_digest"]):
        return "payload_digest must be 64 lowercase hex"
    if a.get("decision") not in ("approve", "deny"):
        return "decision must be approve or deny"
    if not _uint(a.get("expires_at")):
        return "expires_at must be unix seconds"
    return None


def approval_digest(a: dict) -> bytes:
    """ADR 0008: SHA-256 of approval/2.0|verifier_did|owner_did|request_id|payload_digest|decision|expires_at.
    Takes the approval object or the request fields."""
    e = _fields_error(a) if isinstance(a, dict) else "approval must be a dict"
    if e:
        raise InvalidInputError(e)
    return _sha("|".join(["approval/2.0", a["verifier_did"], a["owner_did"], a["request_id"], a["payload_digest"], a["decision"],
                          str(a["expires_at"])]))


def payload_digest(summary) -> str:
    """Lowercase hex SHA-256 of the RFC 8785 form of the summary the owner saw. Numbers must be integers within 2^53
    (put amounts in minor units or strings)."""
    e = _plain(summary)
    if e:
        raise InvalidInputError(e)
    return _sha(canonicalize(summary)).hex()


def verify_approval(approval, *, key_log: dict, verifier_did: str, owner_did: str, request_id: str, payload_digest: str,
                    now: int | None = None, decisions=("approve", "deny"), origins=None, rp_id: str = RP_ID, counter: int = 0) -> dict:
    """Verify an approval/2.0 object against the owner's verified key log (verify_key_log's state, or a dict with did,
    approvers and closed). request_id and payload_digest are what this verifier issued and recomputes, never the client's.
    Returns {"ok": True, "kid", "counter"} (store the counter) or {"ok": False, "error", "message"}. Rejects approval/1.0."""
    try:
        if not isinstance(approval, dict):
            raise _Fail("malformed", "approval must be an object")
        a = approval
        if a.get("version") != "approval/2.0":
            raise _Fail("bad_version", f"version {a.get('version')} is not approval/2.0")
        shape = _fields_error(a) or (_signed_shape(a) if isinstance(a.get("device_id"), str) else "device_id must be a string")
        if shape:
            raise _Fail("malformed", shape)
        now = int(time.time()) if now is None else now
        if a["verifier_did"] != verifier_did:
            raise _Fail("wrong_verifier", f"approval is for {a['verifier_did']}")
        if a["owner_did"] != owner_did or a["owner_did"] != key_log["did"]:
            raise _Fail("wrong_owner", "approval names another owner")
        if key_log["closed"]:
            raise _Fail("owner_closed", "the owner's key log is closed")
        if a["request_id"] != request_id:
            raise _Fail("wrong_request", "the request changed; fetch a new one")
        if a["payload_digest"] != payload_digest:
            raise _Fail("wrong_payload", "payload digest does not match the action")
        if a["decision"] not in decisions:
            raise _Fail("bad_decision", f"decision {a['decision']} is not accepted here")
        if now >= a["expires_at"]:
            raise _Fail("expired", "approval expired")
        if a["expires_at"] > now + _MAX_TTL:
            raise _Fail("expiry_too_far", "expires_at is more than 600 seconds away")
        cred = next((c for c in key_log["approvers"] if c["kid"] == a["device_id"]), None)
        if cred is None:
            raise _Fail("unknown_key", "device_id is not a current approver in the owner's key log")
        got = _check_signature(cred, a, approval_digest(a), origins or [f"https://{rp_id}"], rp_id, False)
        if a["form"] == "webauthn" and (got or counter) and got <= counter:
            raise _Fail("counter_replayed", "signature counter did not increase")
        return {"ok": True, "kid": cred["kid"], "counter": got}
    except _Fail as f:
        return {"ok": False, "error": f.code, "message": str(f)}


# ---- key log

def _credential(c, rp_id: str, what: str) -> dict:
    if not isinstance(c, dict):
        raise _Fail("malformed", f"{what} must be a credential object")
    if c.get("type") not in ("p256", "webauthn"):
        raise _Fail("malformed", f"{what}.type must be p256 or webauthn")
    if _point(c.get("jwk")) is None:
        raise _Fail("malformed", f"{what}.jwk must be exactly {{kty: EC, crv: P-256, x, y}} with a point on the curve")
    if c.get("kid") != _thumbprint(c["jwk"]):
        raise _Fail("malformed", f"{what}.kid must be the RFC 7638 thumbprint of its jwk")
    if c["type"] == "webauthn" and (not _b64u(c.get("credential_id")) or c.get("rp_id") != rp_id):
        raise _Fail("malformed", f"{what} needs a credential_id and rp_id {rp_id}")
    return c


def _parse_entry(line, rp_id: str, first: bool) -> dict:
    if not isinstance(line, str):
        raise _Fail("malformed", "entry must be a JSON line")
    try:
        e = parse_json(line)
    except ValueError as x:
        raise _Fail("malformed", f"not JSON: {x}")
    bad = _plain(e)
    if bad:
        raise _Fail("malformed", bad)
    if canonicalize(e) != line:
        raise _Fail("malformed", "line is not the RFC 8785 form of its entry")
    if not isinstance(e, dict) or set(e) != {"v", "seq", "prev", "op", "ts", "body", "auth"}:
        raise _Fail("malformed", "entry must have exactly v, seq, prev, op, ts, body, auth")
    if not _uint(e["v"]) or e["v"] != 1:
        raise _Fail("malformed", "v must be 1")
    if not _uint(e["seq"]) or not _uint(e["ts"]):
        raise _Fail("malformed", "seq and ts must be unsigned integers")
    if e["prev"] is not None and (not isinstance(e["prev"], str) or not _HEX64.fullmatch(e["prev"])):
        raise _Fail("malformed", "prev must be null or 64 lowercase hex")
    op = e["op"]
    if not isinstance(op, str) or op not in _BODY:
        raise _Fail("malformed", f"unknown op {op}")
    if (op == "genesis") != first:
        raise _Fail("malformed", "genesis is the first entry and only the first")
    b = e["body"]
    if not isinstance(b, dict) or set(b) != _BODY[op]:
        raise _Fail("malformed", f"{op} body must have exactly: {', '.join(sorted(_BODY[op])) or 'nothing'}")
    if op in ("genesis", "replace_root") and _credential(b["root"], rp_id, "root")["type"] != "webauthn":
        raise _Fail("malformed", "root must be a passkey (webauthn)")
    if op == "genesis" and b["approver"] is not None or op == "add_approver":
        _credential(b["approver"], rp_id, "approver")
    if op == "recover":
        if not isinstance(b["approvers"], list) or not b["approvers"]:
            raise _Fail("malformed", "recover needs at least one approver")
        for i, c in enumerate(b["approvers"]):
            _credential(c, rp_id, f"approvers[{i}]")
    if op == "cancel" and (not isinstance(b["target"], str) or not _HEX64.fullmatch(b["target"])):
        raise _Fail("malformed", "target must be 64 lowercase hex")
    if op == "revoke" and not isinstance(b["kid"], str):
        raise _Fail("malformed", "kid must be a string")
    a = e["auth"]
    if not isinstance(a, dict) or not isinstance(a.get("kid"), str):
        raise _Fail("malformed", "auth must be an object with a kid")
    keys = {"kid", "form", "signature"} | ({"authenticator_data", "client_data_json"} if a.get("form") == "webauthn" else set())
    shape = _signed_shape(a) or (None if set(a) == keys else f"auth must have exactly {', '.join(sorted(keys))}")
    if shape:
        raise _Fail("malformed", shape)
    return e


def verify_key_log(did: str, lines: list[str], first_seen_at: list[int], *, now: int | None = None, service_keys=(),
                   origins=None, rp_id: str = RP_ID) -> dict:
    """Verify an owner key log (JSON Lines, one RFC 8785 entry per line) against the owner DID it must hash to.

    first_seen_at[i] is when this verifier first held entry i with its whole chain (unix seconds, never decreasing): every
    delay runs from it, never from the entry's ts. service_keys are the account service's P-256 public JWKs (they sign close).
    Returns {"ok": True, "state": {...}} as of `now`, or {"ok": False, "error", "seq", "message"} for the first failing entry."""
    now = int(time.time()) if now is None else now
    origins = origins or [f"https://{rp_id}"]
    services = []
    for jwk in service_keys:
        if _point(jwk) is None:
            raise InvalidInputError("service_keys must be P-256 public JWKs {kty, crv, x, y}")
        services.append({"kid": _thumbprint(jwk), "type": "p256", "jwk": jwk})
    seq = 1
    try:
        if not isinstance(lines, list) or not lines:
            raise _Fail("malformed", "a key log starts with its genesis entry")
        if not isinstance(first_seen_at, list) or len(first_seen_at) != len(lines):
            raise _Fail("bad_first_seen", "one first_seen_at per entry")
        st = {"root": None, "single": False, "approvers": [], "revoked": [], "pending": [], "closed": False}
        seen, delayed, head = set(), {}, ""

        def approver(kid):
            return next((c for c in ([st["root"]] if st["single"] else st["approvers"]) if c["kid"] == kid), None)

        def due(t):
            while st["pending"] and st["pending"][0]["effective_at"] <= t:
                p = st["pending"].pop(0)
                if p["op"] == "replace_root":
                    st["root"] = p["creds"][0]
                else:
                    st["revoked"] += [{"cred": c, "at": p["effective_at"]} for c in st["approvers"]]
                    st["approvers"], st["single"] = list(p["creds"]), False

        def fresh(creds):
            for c in creds:
                if c["kid"] in seen:
                    raise _Fail("key_reused", f"key {c['kid']} is already in this log")
                seen.add(c["kid"])

        for i, line in enumerate(lines):
            seq = i + 1
            t = first_seen_at[i]
            if not _uint(t) or t > now or (i > 0 and t < first_seen_at[i - 1]):
                raise _Fail("bad_first_seen", "first_seen_at must be unix seconds, never decreasing, not after now")
            if i > 0:
                due(t)
            e = _parse_entry(line, rp_id, i == 0)
            if st["closed"]:
                raise _Fail("closed", "the log is closed")
            if e["seq"] != seq:
                raise _Fail("bad_seq", f"seq must be {seq}")
            if e["prev"] != (head if i else None):
                raise _Fail("bad_prev", "prev is not the SHA-256 of the previous entry" if i else "genesis prev must be null")
            h = _sha(line).hex()
            digest = _sha(canonicalize({k: v for k, v in e.items() if k != "auth"}))
            b, kid, op = e["body"], e["auth"]["kid"], e["op"]
            if op == "genesis":
                if did != f"did:web:{rp_id}:o:{_base32(_sha(line))}":
                    raise _Fail("did_mismatch", "the genesis hash does not match the DID suffix")
                first = b["approver"]
                fresh([b["root"], first] if first else [b["root"]])
                st.update(root=b["root"], single=first is None, approvers=[first] if first else [])
                signer = (first or b["root"]) if (first or b["root"])["kid"] == kid else None
            elif op == "add_approver":
                fresh([b["approver"]])
                signer = approver(kid)
            elif op == "recover":
                fresh(b["approvers"])
                signer = st["root"] if st["root"]["kid"] == kid else None
            elif op == "replace_root":
                fresh([b["root"]])
                signer = st["root"] if st["root"]["kid"] == kid else approver(kid)
            elif op == "cancel":
                target = delayed.get(b["target"])
                if target is None:
                    raise _Fail("bad_target", "target is not a recover or replace_root in this log")
                signer = approver(kid) or next((r["cred"] for r in st["revoked"] if r["cred"]["kid"] == kid and t < r["at"] + _WEEK), None) \
                    or (st["root"] if target == "recover" and st["root"]["kid"] == kid else None)
            elif op == "revoke":
                if not any(c["kid"] == b["kid"] for c in st["approvers"]):
                    raise _Fail("bad_target", "kid is not a current approver")
                signer = st["root"] if st["root"]["kid"] == kid else approver(kid)
            else:  # close
                signer = next((c for c in services if c["kid"] == kid), None)
            if signer is None:
                raise _Fail("unauthorized", f"key {kid} may not sign {op} here")
            _check_signature(signer, e["auth"], digest, origins, rp_id, True)

            if op == "add_approver":
                st["approvers"], st["single"] = st["approvers"] + [b["approver"]], False
            elif op == "recover":
                st["pending"].append({"seq": seq, "op": op, "hash": h, "effective_at": t + _DAY, "creds": b["approvers"]})
                delayed[h] = op
            elif op == "replace_root":
                if st["single"]:
                    st["root"] = b["root"]
                else:
                    st["pending"].append({"seq": seq, "op": op, "hash": h, "effective_at": t + _DAY, "creds": [b["root"]]})
                delayed[h] = op
            elif op == "cancel":
                st["pending"] = [p for p in st["pending"] if p["hash"] != b["target"]]
            elif op == "revoke":
                gone = next(c for c in st["approvers"] if c["kid"] == b["kid"])
                st["approvers"] = [c for c in st["approvers"] if c is not gone]
                st["revoked"].append({"cred": gone, "at": t})
            elif op == "close":
                st["closed"], st["pending"] = True, []
            head = h
        due(now)
        return {"ok": True, "state": {
            "did": did, "seq": len(lines), "head": head, "root": st["root"],
            "approvers": [st["root"]] if st["single"] else st["approvers"],
            "revoked": [{"kid": r["cred"]["kid"], "at": r["at"]} for r in st["revoked"]],
            "pending": [{k: v for k, v in p.items() if k != "creds"} for p in st["pending"]],
            "closed": st["closed"],
        }}
    except _Fail as f:
        return {"ok": False, "error": f.code, "seq": seq, "message": str(f)}
