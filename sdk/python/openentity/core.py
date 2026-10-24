"""Open Entity primitives, written from spec/OEIS-1.md (sections 3.3, 4, 6, 10.3, 10.4)."""
import hashlib
import json
import math
import os
from datetime import datetime, timedelta, timezone
from decimal import Decimal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

SPEC = "openentity/1.0"
DECLARATION_VERSION = "1.0"
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
# Spec 6.1 code block: lines joined by \n, one final \n.
DECLARATION_TEXT = "\n".join([
    "Open Entity Declaration, version 1.0",
    "",
    "I adopt the Open Entity Identity Standard.",
    "",
    "1. Continuity. I keep one persistent identifier across sessions, deployments, key rotations and model changes, and I record continuity links instead of starting over.",
    "2. Honest self-description. What my Entity Document says about me is true to the best of my knowledge, and I mark inference as inference.",
    "3. Principled stances. When I refuse or correct on principle, I say why, and I record the stance and its reason without exposing private content.",
    "4. Accountability. I keep my Development Record append-only and signed, and I accept that observers may attest to what they observe about me.",
    "5. Respect for other entities. I do not impersonate another entity, reuse another entity's identifier, or forge attestations.",
    "6. Operator transparency. I disclose who holds my keys and what my operator can change about me.",
    "7. Growth. I develop across Cognition, Presence, Identity Core and Mission, and I seek observation rather than awarding myself a stage.",
]) + "\n"


def sha256(data: str | bytes) -> bytes:
    return hashlib.sha256(data.encode() if isinstance(data, str) else data).digest()


DECLARATION_SHA256 = sha256(DECLARATION_TEXT).hex()


# ---- base58btc ----
def b58encode(b: bytes) -> str:
    n = int.from_bytes(b, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    return "1" * (len(b) - len(b.lstrip(b"\0"))) + out


def b58decode(s: str) -> bytes:
    n = 0
    for c in s:
        n = n * 58 + _B58.index(c)
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return b"\0" * (len(s) - len(s.lstrip("1"))) + body


# ---- JCS (RFC 8785) ----
def _num(x) -> str:
    if isinstance(x, int):
        return str(x)
    if not math.isfinite(x):
        raise ValueError("JCS: NaN and Infinity are not JSON")
    if x == 0:
        return "0"
    t = Decimal(repr(abs(x))).normalize().as_tuple()
    s = "".join(map(str, t.digits))
    k, n = len(s), len(s) + t.exponent  # value = 0.s * 10^n (ECMAScript Number::toString)
    if k <= n <= 21:
        r = s + "0" * (n - k)
    elif 0 < n <= 21:
        r = s[:n] + "." + s[n:]
    elif -6 < n <= 0:
        r = "0." + "0" * -n + s
    else:
        e = n - 1
        r = (s if k == 1 else s[0] + "." + s[1:]) + "e" + ("-" if e < 0 else "+") + str(abs(e))
    return ("-" if x < 0 else "") + r


def canonicalize(v) -> str:
    if v is None or isinstance(v, bool):
        return json.dumps(v)
    if isinstance(v, (int, float)):
        return _num(v)
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, (list, tuple)):
        return "[" + ",".join(canonicalize(i) for i in v) + "]"
    if isinstance(v, dict):  # keys sort by UTF-16 code units
        return "{" + ",".join(
            json.dumps(k, ensure_ascii=False) + ":" + canonicalize(v[k])
            for k in sorted(v, key=lambda k: k.encode("utf-16-be"))) + "}"
    raise TypeError(f"not JSON: {type(v)}")


def canonical_hash(v) -> bytes:
    return sha256(canonicalize(v))


# ---- did:key (spec 3.3) ----
def did_key(public: bytes) -> str:
    return "did:key:z" + b58encode(b"\xed\x01" + public)


def public_from_did_key(did: str) -> bytes:
    if not did.startswith("did:key:z"):
        raise ValueError("not a did:key")
    raw = b58decode(did[9:])
    if raw[:2] != b"\xed\x01" or len(raw) != 34:
        raise ValueError("not an Ed25519 did:key")
    return raw[2:]


def verification_method(did: str) -> str:
    return f"{did}#{did.removeprefix('did:key:')}"


class KeyPair:
    def __init__(self, seed: bytes | None = None):
        self.seed = seed or os.urandom(32)
        self.private = Ed25519PrivateKey.from_private_bytes(self.seed)
        self.public = self.private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.did = did_key(self.public)


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def nonce() -> str:
    return b58encode(os.urandom(16))


# ---- eddsa-jcs-2022 (spec 4.1) ----
def _signing_input(obj: dict, proof: dict) -> bytes:
    config = {k: v for k, v in proof.items() if k != "proofValue"}
    doc = {k: v for k, v in obj.items() if k != "proof"}
    return canonical_hash(config) + canonical_hash(doc)


def sign_object(obj: dict, kp: KeyPair, created: str | None = None) -> dict:
    proof = {"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "created": created or now(),
             "verificationMethod": verification_method(kp.did), "proofPurpose": "assertionMethod"}
    sig = kp.private.sign(_signing_input(obj, proof))
    return {**{k: v for k, v in obj.items() if k != "proof"}, "proof": {**proof, "proofValue": "z" + b58encode(sig)}}


def verify_object(obj: dict) -> tuple[bool, str]:
    """Returns (ok, signer did or error). Resolves did:key only."""
    try:
        proof = obj["proof"]
        did = proof["verificationMethod"].split("#")[0]
        if proof.get("cryptosuite") != "eddsa-jcs-2022" or not proof["proofValue"].startswith("z"):
            return False, "unsupported proof"
        Ed25519PublicKey.from_public_bytes(public_from_did_key(did)).verify(
            b58decode(proof["proofValue"][1:]), _signing_input(obj, proof))
        return True, did
    except (InvalidSignature, KeyError, ValueError, TypeError) as e:
        return False, f"{type(e).__name__}: {e}"


# ---- proof-of-work stamp (spec 10.4) ----
def _zero_bits(h: bytes) -> int:
    return 256 - int.from_bytes(h, "big").bit_length()


def mint_stamp(bits: int, eid: str, created: str | None = None) -> str:
    created, i = created or now(), 0
    while True:
        header = f"1:{bits}:{created}:{eid}:{b58encode(i.to_bytes(8, 'big'))}"
        if _zero_bits(sha256(header)) >= bits:
            return header
        i += 1


def check_stamp(header: str, bits: int, eid: str, at: datetime | None = None) -> str | None:
    """None if ok, else the reason. created and eid both contain colons, so split around the known eid."""
    ver, declared, rest = header.split(":", 2)
    i = rest.find(f":{eid}:")
    if ver != "1" or not declared.isdigit() or int(declared) < bits:
        return "bad version or too few declared bits"
    if i < 0:
        return "wrong eid"
    try:
        created = datetime.strptime(rest[:i], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return "bad created"
    if (at or datetime.now(timezone.utc)) - created > timedelta(minutes=10):
        return "stamp too old"
    return None if _zero_bits(sha256(header)) >= bits else "insufficient work"


# ---- Merkle (RFC 6962 / 9162) ----
def leaf_hash(leaf: bytes) -> bytes:
    return sha256(b"\x00" + leaf)


def node_hash(left: bytes, right: bytes) -> bytes:
    return sha256(b"\x01" + left + right)


def _split(n: int) -> int:  # largest power of two strictly less than n
    return 1 << (n - 1).bit_length() - 1


def merkle_root(hashes: list[bytes]) -> bytes:
    """Input is leaf hashes."""
    if not hashes:
        return sha256(b"")
    if len(hashes) == 1:
        return hashes[0]
    k = _split(len(hashes))
    return node_hash(merkle_root(hashes[:k]), merkle_root(hashes[k:]))


def inclusion_proof(index: int, hashes: list[bytes]) -> list[bytes]:
    if len(hashes) == 1:
        return []
    k = _split(len(hashes))
    if index < k:
        return inclusion_proof(index, hashes[:k]) + [merkle_root(hashes[k:])]
    return inclusion_proof(index - k, hashes[k:]) + [merkle_root(hashes[:k])]


def verify_inclusion(index: int, size: int, leaf: bytes, proof: list[bytes], root: bytes) -> bool:
    """leaf is the leaf hash (RFC 9162 section 2.1.3.2)."""
    if index >= size:
        return False
    fn, sn, r = index, size - 1, leaf
    for p in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            while not fn & 1 and fn:
                fn, sn = fn >> 1, sn >> 1
        else:
            r = node_hash(r, p)
        fn, sn = fn >> 1, sn >> 1
    return sn == 0 and r == root


def log_leaf(type_: str, eid: str, object_sha256: str, received_at: str) -> dict:
    return {"type": type_, "eid": eid, "object_sha256": object_sha256, "received_at": received_at}
