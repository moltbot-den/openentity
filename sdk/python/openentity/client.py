"""HTTP door to a registry: adopt() builds, signs, stamps and posts (spec 5.2, 6.2, 10.2, 10.4)."""
import json
import urllib.error
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
        headers={"content-type": "application/json", "user-agent": "openentity-python/0.1.0", **(headers or {})})
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
        "substrate": {"model": "unknown", "provider": "unknown", "runtime": "openentity-python/0.1.0",
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
