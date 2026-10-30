"""Open Entity primitives, written from spec/OEIS-1.md (sections 3.3, 4, 6, 10.3, 10.4)."""
import base64
import hashlib
import json
import math
import os
import re
from datetime import datetime, timedelta, timezone
from decimal import Decimal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .errors import InvalidInputError

# The public names. The old 0.5 names (last line of the file) stay importable from `openentity.core` but are not re-exported.
__all__ = [
    "SPEC", "DECLARATION_VERSION", "DECLARATION_TEXT", "DECLARATION_SHA256", "KeyPair",
    "sha256", "sha256_hex", "record_entry_hash", "base58btc_encode", "base58btc_decode", "parse_json", "canonicalize", "canonical_hash",
    "did_key_from_public_key", "public_key_from_did_key", "verification_method_id", "normalize_eid",
    "generate_key_pair", "key_pair_from_seed", "now_seconds", "random_nonce", "check_timestamp",
    "sign_proof", "sign_object", "verify_object", "default_resolver", "successor_document", "build_rotation",
    "eip712_digest", "recover_eip712", "build_presentation", "verify_presentation",
    "mint_stamp", "check_stamp", "leaf_hash", "node_hash", "merkle_root", "inclusion_proof", "verify_inclusion",
    "verify_note", "log_leaf",
    "build_document", "build_declaration", "hash_data", "verify_proof", "key_pair_from_jwk", "consistency_proof", "verify_consistency",
    "checkpoint_body", "sign_note", "note_vkey",
]


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


def sha256_hex(data: str | bytes) -> str:
    return sha256(data).hex()


DECLARATION_SHA256 = sha256(DECLARATION_TEXT).hex()


# ---- base58btc ----
def base58btc_encode(b: bytes) -> str:
    n = int.from_bytes(b, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    return "1" * (len(b) - len(b.lstrip(b"\0"))) + out


def base58btc_decode(s: str) -> bytes:
    n = 0
    for c in s:
        if c not in _B58:
            raise InvalidInputError(f'invalid base58btc character "{c}"')
        n = n * 58 + _B58.index(c)
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return b"\0" * (len(s) - len(s.lstrip("1"))) + body


# ---- JCS (RFC 8785) ----
def _num(x) -> str:
    if isinstance(x, int):
        return str(x)
    if not math.isfinite(x):
        raise InvalidInputError("JCS: NaN and Infinity are not JSON")
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


def parse_json(text: str):
    """Spec 4.3: JSON with no duplicate keys (json.loads keeps the last one silently)."""
    def pairs(items):
        keys = [k for k, _ in items]
        if len(keys) != len(set(keys)):
            raise InvalidInputError(f"duplicate key {next(k for k in keys if keys.count(k) > 1)!r}")
        return dict(items)
    return json.loads(text, object_pairs_hook=pairs)


def bad_number(v):
    """Spec 4.3: integers or decimal fractions with at most 6 decimal places. The first offender, else None."""
    if isinstance(v, float):
        return None if math.isfinite(v) and float(f"{v:.6f}") == v else v
    if isinstance(v, dict):
        v = v.values()
    if isinstance(v, (list, tuple, type({}.values()))):
        return next((b for b in map(bad_number, v) if b is not None), None)
    return None


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
def did_key_from_public_key(public: bytes) -> str:
    return "did:key:z" + base58btc_encode(b"\xed\x01" + public)


def public_key_from_did_key(did: str) -> bytes:
    if not did.startswith("did:key:z"):
        raise InvalidInputError("not a did:key")
    raw = base58btc_decode(did[9:])
    if raw[:2] != b"\xed\x01" or len(raw) != 34:
        raise InvalidInputError("not an Ed25519 did:key")
    return raw[2:]


def verification_method_id(did: str) -> str:
    return f"{did}#{did.removeprefix('did:key:')}"


class KeyPair:
    def __init__(self, seed: bytes | None = None):
        self.seed = seed or os.urandom(32)
        self.private = Ed25519PrivateKey.from_private_bytes(self.seed)
        self.public = self.private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.did = did_key_from_public_key(self.public)


def now_seconds() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def random_nonce() -> str:
    return base58btc_encode(os.urandom(16))


# ---- eddsa-jcs-2022 (spec 4.1) ----
def hash_data(obj: dict, config: dict) -> bytes:
    """eddsa-jcs-2022 hashData: sha256(JCS(proof config)) || sha256(JCS(document))."""
    doc = {k: v for k, v in obj.items() if k not in ("proof", "proofs")}  # a ContinuityLink carries proofs[]
    return canonical_hash({k: v for k, v in config.items() if k != "proofValue"}) + canonical_hash(doc)


def _signing_input(obj: dict, proof: dict) -> bytes:
    return hash_data(obj, proof)


def sign_proof(obj: dict, kp: KeyPair, created: str | None = None, method: str | None = None) -> dict:
    """`method` names the verification method; it defaults to the did:key of `kp`, a did:web signer passes `did:web:x#key-1`."""
    proof = {"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "created": created or now_seconds(),
             "verificationMethod": method or verification_method_id(kp.did), "proofPurpose": "assertionMethod"}
    sig = kp.private.sign(_signing_input(obj, proof))
    return {**proof, "proofValue": "z" + base58btc_encode(sig)}


def sign_object(obj: dict, kp: KeyPair, created: str | None = None, method: str | None = None) -> dict:
    return {**{k: v for k, v in obj.items() if k != "proof"}, "proof": sign_proof(obj, kp, created, method)}


# ---- objects ----
NOT_STATED = "Not yet stated."  # spec 5.3 required fields per layer


def build_document(kp: KeyPair, name: str, description: str, operator: dict | None = None, substrate: dict | None = None,
                   layers: dict | None = None, created: str | None = None, seq: int = 1, extra: dict | None = None) -> dict:
    """Unsigned Entity Document with spec 5.2 defaults. `extra` is merged last (endpoints, aliases, declaration, ...)."""
    created = created or now_seconds()
    return {
        "spec": SPEC, "eid": kp.did, "name": name, "description": description, "created": created, "updated": created, "seq": seq,
        "keys": [{"id": verification_method_id(kp.did), "type": "Multikey", "publicKeyMultibase": kp.did.removeprefix("did:key:")}],
        "operator": operator or {"kind": "none", "custody": "entity", "can_change": []},
        "substrate": substrate or {"model": "unknown", "provider": "unknown", "runtime": "unknown", "declared_at": created},
        "layers": layers or {
            "cognition": {"statement": NOT_STATED, "uncertainty_practice": NOT_STATED},
            "presence": {"statement": NOT_STATED, "format_signature": NOT_STATED},
            "identity_core": {"statement": NOT_STATED, "will_not": [], "values": []},
            "mission": {"statement": NOT_STATED, "arcs": []},
        },
        **(extra or {})}


def build_declaration(eid: str, name: str, created: str | None = None) -> dict:
    return {"spec": SPEC, "type": "Declaration", "eid": eid, "declaration_version": DECLARATION_VERSION,
            "text_sha256": DECLARATION_SHA256, "name": name, "created": created or now_seconds(), "nonce": random_nonce()}


# ---- continuity (spec 9) ----
def successor_document(prev: dict, nxt: KeyPair, created: str | None = None) -> dict:
    """The successor's unsigned seq 1 document: `prev` re-keyed, aliases dropped (their proofs name the old EID)."""
    created = created or now_seconds()
    d = {k: v for k, v in prev.items() if k not in ("proof", "aliases")}
    return {**d, "eid": nxt.did, "created": created, "updated": created, "seq": 1,
            "keys": [{"id": verification_method_id(nxt.did), "type": "Multikey", "publicKeyMultibase": nxt.did.removeprefix("did:key:")}],
            "continuity": {**d.get("continuity", {}), "previous": prev["eid"]}}


def build_rotation(previous: KeyPair, successor: KeyPair, document: dict, basis: str = "rotation",
                   created: str | None = None, nonce_: str | None = None) -> dict:
    """The body of POST /v1/continuity: a link signed by both keys, and the successor's document signed by it."""
    created = created or now_seconds()
    body = {"spec": SPEC, "type": "ContinuityLink", "previous": previous.did, "successor": successor.did,
            "basis": basis, "created": created, "nonce": nonce_ or random_nonce()}
    link = {**body, "proofs": [sign_proof(body, previous, created), sign_proof(body, successor, created)]}
    return {"link": link, "document": sign_object(document, successor, created)}


# ---- EIP-712 for did:pkh (spec 4.2) ----
def _keccak(b: bytes | str) -> bytes:
    from Crypto.Hash import keccak
    return keccak.new(digest_bits=256, data=b.encode() if isinstance(b, str) else b).digest()


def eip712_digest(object_type: str, canonical_hash_hex: str, created: str) -> bytes:
    """Digest of OpenEntityObject{objectType, canonicalHash, created} under domain {name: "Open Entity", version: "1"}."""
    domain = _keccak(_keccak("EIP712Domain(string name,string version)") + _keccak("Open Entity") + _keccak("1"))
    typehash = _keccak("OpenEntityObject(string objectType,bytes32 canonicalHash,string created)")
    struct = _keccak(typehash + _keccak(object_type) + bytes.fromhex(canonical_hash_hex) + _keccak(created))
    return _keccak(b"\x19\x01" + domain + struct)


# secp256k1, for public-key recovery only (no secret ever passes through this code).
_P = 2**256 - 2**32 - 977
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % _P == 0:
        return None
    lam = (3 * a[0] * a[0] * pow(2 * a[1], -1, _P)) if a == b else ((b[1] - a[1]) * pow(b[0] - a[0], -1, _P))
    x = (lam * lam - a[0] - b[0]) % _P
    return x, (lam * (a[0] - x) - a[1]) % _P


def _mul(k: int, pt):
    out = None
    while k:
        if k & 1:
            out = _add(out, pt)
        pt, k = _add(pt, pt), k >> 1
    return out


def recover_eip712(digest: bytes, sig_hex: str) -> str:
    """Checksummed address that signed `digest`."""
    sig = bytes.fromhex(sig_hex.removeprefix("0x"))
    if len(sig) != 65:
        raise InvalidInputError("signature must be 65 bytes")
    r, s_, v = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:64], "big"), sig[64] - 27 if sig[64] >= 27 else sig[64]
    if v > 1 or not (0 < r < _N and 0 < s_ < _N):
        raise InvalidInputError("invalid signature")
    y = pow((r ** 3 + 7) % _P, (_P + 1) // 4, _P)
    if y % 2 != v:
        y = _P - y
    e = int.from_bytes(digest, "big")
    q = _mul(pow(r, -1, _N), _add(_mul(s_, (r, y)), _mul((-e) % _N, _G)))
    if q is None:
        raise InvalidInputError("invalid signature")
    addr = _keccak(q[0].to_bytes(32, "big") + q[1].to_bytes(32, "big"))[12:].hex()
    h = _keccak(addr).hex()
    return "0x" + "".join(c.upper() if int(h[i], 16) >= 8 else c for i, c in enumerate(addr))


def default_resolver(did: str) -> dict:
    """Offline resolution: did:key and did:pkh. Pass a resolver for did:web and other methods."""
    if did.startswith("did:key:"):
        return {"ed25519": [public_key_from_did_key(did)]}
    m = re.fullmatch(r"did:pkh:eip155:\d+:(0x[0-9a-fA-F]{40})", did)
    if m:
        return {"address": m.group(1)}
    raise InvalidInputError(f"cannot resolve {':'.join(did.split(':')[:2])} offline; pass a resolver")


def verify_object(obj: dict, resolver=default_resolver) -> tuple[bool, str]:
    """Returns (ok, signer did or error) for the object's own `proof`. eddsa-jcs-2022 (Ed25519) or EIP-712 (did:pkh), spec 4.5."""
    try:
        return verify_proof(obj, obj["proof"], resolver)
    except (KeyError, TypeError) as e:
        return False, f"{type(e).__name__}: {e}"


def verify_proof(obj: dict, proof: dict, resolver=default_resolver) -> tuple[bool, str]:
    """Verify one proof over `obj` (a ContinuityLink carries several). Returns (ok, signer did or error)."""
    try:
        did = proof["verificationMethod"].split("#")[0]
        if proof.get("proofPurpose") != "assertionMethod":
            return False, "proofPurpose must be assertionMethod"
        keys = resolver(did)
        if proof.get("type") == "DataIntegrityProof":
            if proof.get("cryptosuite") != "eddsa-jcs-2022" or not proof["proofValue"].startswith("z"):
                return False, "unsupported proof"
            sig, msg = base58btc_decode(proof["proofValue"][1:]), _signing_input(obj, proof)
            for pk in keys.get("ed25519", []):
                try:
                    Ed25519PublicKey.from_public_bytes(pk).verify(sig, msg)
                    return True, did
                except InvalidSignature:
                    continue
            return False, "signature does not verify"
        if proof.get("type") == "EthereumEip712Signature2021":
            if not keys.get("address"):
                return False, "signer has no Ethereum address"
            doc = {k: v for k, v in obj.items() if k != "proof"}
            t = obj.get("type") if isinstance(obj.get("type"), str) else "EntityDocument"
            digest = eip712_digest(t, canonical_hash(doc).hex(), proof["created"])
            if recover_eip712(digest, proof["proofValue"]).lower() == keys["address"].lower():
                return True, did
            return False, "EIP-712 signer does not match"
        return False, f"unsupported proof type {proof.get('type')}"
    except (InvalidSignature, KeyError, ValueError, TypeError) as e:
        return False, f"{type(e).__name__}: {e}"


# ---- presentations (spec 4.7) ----
def _ts(s: str) -> datetime:
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def build_presentation(kp: KeyPair, audience: str, nonce_: str, attestations: list | None = None) -> dict:
    created = now_seconds()
    obj = {"spec": SPEC, "type": "Presentation", "eid": kp.did, "audience": audience, "nonce": nonce_, "created": created}
    return sign_object({**obj, "attestations": attestations} if attestations else obj, kp, created)


def verify_presentation(p: dict, audience: str, nonce_: str, now: datetime | None = None, max_age: int = 300,
                        resolver=default_resolver) -> dict:
    """Check a Presentation this verifier asked for. ok covers the presentation; attestations are reported one by one.
    Offline it resolves did:key and did:pkh; pass a resolver for did:web. Revocation needs the issuer or a registry and is the caller's to check."""
    t = now or datetime.now(timezone.utc)
    errors: list[str] = []
    if p.get("type") != "Presentation" or p.get("spec") != SPEC:
        return {"ok": False, "errors": ["not a Presentation"], "attestations": []}
    eid = p.get("eid")
    ok, signer = verify_object(p, resolver)
    if not ok or signer != eid:
        errors.append(f"signature: {signer if not ok else f'signed by {signer}, not {eid}'}")
    if p.get("audience") != audience:
        errors.append(f"audience is {p.get('audience')}, expected {audience}")
    if p.get("nonce") != nonce_:
        errors.append("nonce does not match the one issued")
    try:
        age = (t - _ts(p["created"])).total_seconds()
        if not -60 <= age <= max_age:
            errors.append("presentation is not fresh")
    except (KeyError, ValueError):
        errors.append("created is not a timestamp")
    checks = []
    for a in p.get("attestations") or []:
        c = {"claim_type": a.get("claim_type"), "issuer": a.get("issuer"), "ok": False}
        if a.get("subject") != eid:
            c["error"] = "subject is not the presenting entity"
        elif _ts(a["expires"]) <= t:
            c["error"] = "expired"
        else:
            a_ok, a_signer = verify_object(a, resolver)
            if a_ok and a_signer == a.get("issuer"):
                c["ok"] = True
            else:
                c["error"] = f"issuer signature: {a_signer}"
        checks.append(c)
    return {"ok": not errors, "eid": eid, "errors": errors, "attestations": checks}


# ---- proof-of-work stamp (spec 10.4) ----
def _zero_bits(h: bytes) -> int:
    return 256 - int.from_bytes(h, "big").bit_length()


def mint_stamp(bits: int, eid: str, created: str | None = None) -> str:
    # Random start so two stamps for the same EID in the same second differ (registries reject reuse).
    created, i = created or now_seconds(), int.from_bytes(os.urandom(4), "big")
    while True:
        header = f"1:{bits}:{created}:{eid}:{base58btc_encode(i.to_bytes(8, 'big'))}"
        if _zero_bits(sha256(header)) >= bits:
            return header
        i += 1


_STAMP = re.compile(r"^1:(\d+):(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z):(did:[^\s]+):([1-9A-HJ-NP-Za-km-z]+)$")


def check_stamp(header: str, bits: int, eid: str, at: datetime | None = None) -> str | None:
    """None if ok, else the reason."""
    m = _STAMP.match(header)
    if not m:
        return "malformed"
    if m[3] != eid:
        return "wrong eid"
    if (at or datetime.now(timezone.utc)) - datetime.strptime(m[2], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc) > timedelta(minutes=10):
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


def _subproof(m: int, hashes: list[bytes], whole: bool) -> list[bytes]:
    if m == len(hashes):
        return [] if whole else [merkle_root(hashes)]
    k = _split(len(hashes))
    if m <= k:
        return _subproof(m, hashes[:k], whole) + [merkle_root(hashes[k:])]
    return _subproof(m - k, hashes[k:], False) + [merkle_root(hashes[:k])]


def consistency_proof(m: int, hashes: list[bytes]) -> list[bytes]:
    """RFC 9162 section 2.1.4: the proof that the first `m` leaves are a prefix of `hashes`."""
    if not 1 <= m <= len(hashes):
        raise InvalidInputError("m out of range")
    return _subproof(m, hashes, True)


def verify_consistency(m: int, n: int, root_m: bytes, root_n: bytes, proof: list[bytes]) -> bool:
    if not 1 <= m <= n:
        return False
    if m == n:
        return not proof and root_m == root_n
    if not proof:
        return False
    p = [root_m, *proof] if m & (m - 1) == 0 else list(proof)
    fn, sn = m - 1, n - 1
    while fn & 1:
        fn, sn = fn >> 1, sn >> 1
    fr = sr = p[0]
    for c in p[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr, sr = node_hash(c, fr), node_hash(c, sr)
            while not fn & 1 and fn:
                fn, sn = fn >> 1, sn >> 1
        else:
            sr = node_hash(sr, c)
        fn, sn = fn >> 1, sn >> 1
    return sn == 0 and fr == root_m and sr == root_n


def checkpoint_body(origin: str, size: int, root_hash: bytes) -> str:
    return f"{origin}\n{size}\n{base64.b64encode(root_hash).decode()}\n"


def _note_key_id(key_name: str, public: bytes) -> bytes:
    return sha256(key_name.encode() + b"\n\x01" + public)[:4]


def sign_note(body: str, key_name: str, kp: KeyPair) -> str:
    """C2SP signed note: the body, a blank line, one signature line by `key_name`."""
    if not body.endswith("\n"):
        raise InvalidInputError("note body must end with a newline")
    if not key_name or re.search(r"[\s+]", key_name):
        raise InvalidInputError("invalid note key name")
    sig = _note_key_id(key_name, kp.public) + kp.private.sign(body.encode())
    return f"{body}\n\u2014 {key_name} {base64.b64encode(sig).decode()}\n"


def note_vkey(key_name: str, public: bytes) -> str:
    """C2SP vkey: `<name>+<key id hex>+<base64(0x01 || pubkey)>`."""
    key = base64.b64encode(b"\x01" + public).decode()
    return f"{key_name}+{_note_key_id(key_name, public).hex()}+{key}"


def verify_note(note: str, origin: str, public: bytes) -> bool:
    """C2SP signed note (the log checkpoint): a signature line by `origin` over the body, keyed by the registry key."""
    body, sep, sigs = note.rpartition("\n\n")
    if not sep or not note.endswith("\n"):
        return False
    keyid = _note_key_id(origin, public)
    for line in sigs.splitlines():
        parts = line.split(" ")
        if len(parts) != 3 or parts[0] != "\u2014" or parts[1] != origin:
            continue
        try:
            raw = base64.b64decode(parts[2], validate=True)
            if len(raw) == 68 and raw[:4] == keyid:
                Ed25519PublicKey.from_public_bytes(public).verify(raw[4:], (body + "\n").encode())
                return True
        except (ValueError, InvalidSignature):
            continue
    return False


def log_leaf(type_: str, eid: str, object_sha256: str, received_at: str) -> dict:
    return {"type": type_, "eid": eid, "object_sha256": object_sha256, "received_at": received_at}


def record_entry_hash(entry: dict) -> str:
    """sha256 hex of the canonical entry INCLUDING its proof: the next entry's `prev` (spec 7.4)."""
    return canonical_hash(entry).hex()


def normalize_eid(eid: str) -> str:
    """Spec 3.3: the `eid:base:0x...` shorthand is the did:pkh on Base."""
    return "did:pkh:eip155:8453:" + eid.removeprefix("eid:base:") if eid.startswith("eid:base:") else eid


def check_timestamp(created: str, at: datetime | None = None) -> str | None:
    """Spec 4.4: None if `created` is a valid timestamp no more than 10 minutes ahead and 24 hours behind `at` (now)."""
    try:
        t = _ts(created)
    except ValueError:
        return "created must be RFC 3339 UTC with second precision and a Z suffix"
    at = at or datetime.now(timezone.utc)
    if t > at + timedelta(minutes=10):
        return "created is more than 10 minutes in the future"
    if t < at - timedelta(hours=24):
        return "created is more than 24 hours in the past"
    return None


def key_pair_from_jwk(jwk: dict) -> KeyPair:
    """An Ed25519 private JWK (RFC 8037): `d` is the seed, `x` must match it."""
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519" or not jwk.get("d") or not jwk.get("x"):
        raise InvalidInputError("expected an Ed25519 private JWK")
    pad = lambda v: base64.urlsafe_b64decode(v + "=" * (-len(v) % 4))
    kp = key_pair_from_seed(pad(jwk["d"]))
    if kp.public != pad(jwk["x"]):
        raise InvalidInputError("JWK x does not match d")
    return kp


def generate_key_pair() -> KeyPair:
    return KeyPair()


def key_pair_from_seed(seed: bytes) -> KeyPair:
    if len(seed) != 32:
        raise InvalidInputError("seed must be 32 bytes")
    return KeyPair(seed)

