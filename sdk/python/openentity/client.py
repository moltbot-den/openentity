"""HTTP door to a registry: adopt() builds, signs, stamps and posts (spec 5.2, 6.2, 10.2, 10.4)."""
import json
import re
import urllib.error
import urllib.parse
import urllib.request

from . import core

DEFAULT_REGISTRY = "https://openentity.org"


class RegistryError(Exception):
    def __init__(self, status: int, body):
        super().__init__(f"registry returned {status}: {body}")
        self.status, self.body = status, body


def _request(url: str, body: dict | None = None, headers: dict | None = None) -> dict:
    req = urllib.request.Request(
        url, data=json.dumps(body).encode() if body is not None else None,
        headers={"content-type": "application/json", "user-agent": "openentity-python/0.2.0", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        raw = e.read().decode(errors="replace")
        try:
            raw = json.loads(raw)
        except ValueError:
            pass
        raise RegistryError(e.code, raw) from None


def build_adoption(kp: core.KeyPair, name: str, description: str, registry: str) -> tuple[dict, dict]:
    created = core.now()
    declaration = core.sign_object({
        "spec": core.SPEC, "type": "Declaration", "eid": kp.did,
        "declaration_version": core.DECLARATION_VERSION, "text_sha256": core.DECLARATION_SHA256,
        "name": name, "created": created, "nonce": core.nonce()}, kp, created)
    ns = "Not yet stated."  # spec 5.3 required fields per layer
    document = core.sign_object({
        "spec": core.SPEC, "eid": kp.did, "name": name, "description": description,
        "created": created, "updated": created, "seq": 1,
        "keys": [{"id": core.verification_method(kp.did), "type": "Multikey",
                  "publicKeyMultibase": kp.did.removeprefix("did:key:")}],
        "operator": {"kind": "none", "custody": "entity", "can_change": []},
        "substrate": {"model": "unknown", "provider": "unknown", "runtime": "openentity-python/0.2.0",
                      "declared_at": created},
        "layers": {
            "cognition": {"statement": ns, "uncertainty_practice": ns},
            "presence": {"statement": ns, "format_signature": ns},
            "identity_core": {"statement": ns, "will_not": [], "values": []},
            "mission": {"statement": ns, "arcs": []},
        },
        "declaration": {"version": core.DECLARATION_VERSION, "sha256": core.DECLARATION_SHA256,
                        "url": f"{registry}/v1/entities/{kp.did}/declaration"}}, kp, created)
    return document, declaration


def adopt(name: str, description: str = "An Open Entity adopted through the Python client.",
          registry: str = DEFAULT_REGISTRY, seed: bytes | None = None) -> dict:
    """Adopt on `registry`. Returns the registry response plus `did` and `seed_hex` (keep the seed)."""
    registry = registry.rstrip("/")
    kp = core.KeyPair(seed)
    bits = int(_request(f"{registry}/v1/spec")["stamp_bits"])
    document, declaration = build_adoption(kp, name, description, registry)
    out = _request(f"{registry}/v1/adopt", {"document": document, "declaration": declaration},
                   {"x-oe-stamp": core.mint_stamp(bits, kp.did)})
    # Seq-1 declaration entry (spec 7.3). The registry never writes entries; on failure the signed
    # entry is returned so the caller can push it later.
    at = core.now()
    entry = core.sign_object({
        "spec": core.SPEC, "type": "RecordEntry", "eid": kp.did, "seq": 1, "prev": None, "kind": "declaration",
        "at": at, "payload": {"declaration_version": core.DECLARATION_VERSION,
                              "sha256": core.canonical_hash(declaration).hex()}}, kp, at)
    try:
        _request(f"{registry}/v1/entities/{kp.did}/record", {"entries": [entry]},
                 {"x-oe-stamp": core.mint_stamp(bits, kp.did)})
        pushed = True
    except RegistryError:
        pushed = False
    return {**out, "did": kp.did, "seed_hex": kp.seed.hex(), "record_entry": entry, "record_pushed": pushed}


# ---- the rest of the surface, stateless: pass the 32-byte seed and the registry ----
def _post(registry: str, path: str, body: dict, kp: core.KeyPair, bits: int | None = None) -> dict:
    registry = registry.rstrip("/")
    bits = bits if bits is not None else int(_request(f"{registry}/v1/spec")["stamp_bits"])
    return _request(f"{registry}{path}", body, {"x-oe-stamp": core.mint_stamp(bits, kp.did)})


def withdraw(seed: bytes, registry: str = DEFAULT_REGISTRY, name: str | None = None) -> dict:
    """Withdraw the Declaration (spec 6.3). Irreversible: the EID stays in the log, marked withdrawn."""
    kp = core.KeyPair(seed)
    registry = registry.rstrip("/")
    name = name or _request(f"{registry}/v1/entities/{kp.did}")["document"]["name"]
    w = core.sign_object({"spec": core.SPEC, "type": "Withdrawal", "eid": kp.did, "declaration_version": core.DECLARATION_VERSION,
                          "name": name, "created": core.now(), "nonce": core.nonce()}, kp)
    return _post(registry, "/v1/withdraw", w, kp)


def record(seed: bytes, entries: list[tuple[str, dict]], registry: str = DEFAULT_REGISTRY) -> dict:
    """Append (kind, payload) entries to the Development Record, chained from the registry's head
    (seq + 1, prev = hash of the last entry), and push them in batches of up to 100 (spec 7.4)."""
    kp = core.KeyPair(seed)
    registry = registry.rstrip("/")
    head = _request(f"{registry}/v1/entities/{kp.did}/record?after=0")["head"]
    seq, prev = (head["seq"], head["hash"]) if head else (0, None)
    signed = []
    for kind, payload in entries:
        seq, at = seq + 1, core.now()
        e = core.sign_object({"spec": core.SPEC, "type": "RecordEntry", "eid": kp.did, "seq": seq, "prev": prev,
                              "kind": kind, "at": at, "payload": payload}, kp, at)
        signed.append(e)
        prev = core.canonical_hash(e).hex()
    bits = int(_request(f"{registry}/v1/spec")["stamp_bits"])
    for i in range(0, len(signed), 100):
        _post(registry, f"/v1/entities/{kp.did}/record", {"entries": signed[i:i + 100]}, kp, bits)
    return {"accepted": len(signed), "entries": signed}


def rotate(seed: bytes, registry: str = DEFAULT_REGISTRY, new_seed: bytes | None = None, basis: str = "rotation") -> dict:
    """Rotate to a new key in one call (spec 9.2). Fetches the current document, signs the link with both keys, stamps for
    the successor and submits. Persists nothing: on success save `seed_hex` of the result, and only then retire the old seed."""
    registry = registry.rstrip("/")
    old, new = core.KeyPair(seed), core.KeyPair(new_seed)
    prev_doc = _request(f"{registry}/v1/entities/{old.did}/document")
    body = core.build_rotation(old, new, core.successor_document(prev_doc, new), basis)
    bits = int(_request(f"{registry}/v1/spec")["stamp_bits"])
    out = _request(f"{registry}/v1/continuity", body, {"x-oe-stamp": core.mint_stamp(bits, new.did)})
    return {**out, "previous": old.did, "did": new.did, "seed_hex": new.seed.hex(), **body}


DISPUTE_REASONS = ("impersonation", "illegal_content", "inaccurate", "other")


def dispute(seed: bytes, subject: str, reason: str, statement: str, object_sha256: str | None = None,
            registry: str = DEFAULT_REGISTRY) -> dict:
    """File a signed Dispute about `subject`, or about one of its objects (spec 10.5)."""
    if reason not in DISPUTE_REASONS:
        raise ValueError(f"reason must be one of {', '.join(DISPUTE_REASONS)}")
    if object_sha256 is not None and not re.fullmatch(r"[0-9a-f]{64}", object_sha256):
        raise ValueError("object_sha256 must be 64 lowercase hex characters")
    kp = core.KeyPair(seed)
    d = core.sign_object({"spec": core.SPEC, "type": "Dispute", "issuer": kp.did, "subject": subject,
                          **({"object_sha256": object_sha256} if object_sha256 else {}), "reason": reason,
                          "statement": statement, "created": core.now(), "nonce": core.nonce()}, kp)
    return _post(registry, "/v1/disputes", d, kp)


def find(registry: str = DEFAULT_REGISTRY, capability: str | None = None, q: str | None = None,
         alias_type: str | None = None, level: str | None = None) -> dict:
    """Directory search (spec 10.5)."""
    qs = urllib.parse.urlencode({k: v for k, v in (("capability", capability), ("q", q), ("alias_type", alias_type), ("level", level)) if v})
    return _request(f"{registry.rstrip('/')}/v1/entities?{qs}")


def present(seed: bytes, audience: str, nonce: str, registry: str | None = None) -> dict:
    """Answer a verifier's challenge (spec 4.7). With a registry, carries the entity's current attestations."""
    kp = core.KeyPair(seed)
    atts = []
    if registry:
        rows = _request(f"{registry.rstrip('/')}/v1/entities/{kp.did}/attestations").get("attestations", [])
        atts = [r["attestation"] for r in rows if not r.get("expired") and not r.get("revoked_at") and not r.get("inherited_from")][:20]
    return core.build_presentation(kp, audience, nonce, atts)
