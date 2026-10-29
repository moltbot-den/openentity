"""Issuer helpers (ADR 0003): sign attestations and revocations, build a did:web issuer's two well-known files.

`issuer` defaults to the signer's did:key. A did:web issuer passes its DID; the proof then names `<issuer>#<key_id>`,
the key `did_document` publishes. Registry submission stays with `client` (POST /v1/attestations, stamped, spec 10.4)."""
import re
from datetime import datetime, timedelta, timezone

from . import core
from .errors import InvalidInputError

MAX_TTL = timedelta(days=365)  # spec 8.4


def _ts(t: datetime) -> str:
    return t.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _method(kp: core.KeyPair, issuer: str | None, key_id: str) -> str | None:
    return f"{issuer}#{key_id}" if issuer and issuer != kp.did else None


def sign_attestation(kp: core.KeyPair, subject: str, claim_type: str, claim: dict, *, issuer: str | None = None,
                key_id: str = "key-1", evidence: dict | None = None, confidence: float | None = None,
                ttl: timedelta = timedelta(days=90), now: datetime | None = None) -> dict:
    """A signed Attestation (spec 8.2). `ttl` is capped at one year."""
    if not timedelta(0) < ttl <= MAX_TTL:
        raise InvalidInputError("ttl must be positive and at most 1 year")
    t = now or datetime.now(timezone.utc)
    created = _ts(t)
    obj = {"spec": core.SPEC, "type": "Attestation", "issuer": issuer or kp.did, "subject": subject,
           "claim_type": claim_type, "claim": claim, **({"evidence": evidence} if evidence else {}),
           **({"confidence": confidence} if confidence is not None else {}), "created": created, "expires": _ts(t + ttl)}
    return core.sign_object(obj, kp, created, _method(kp, issuer, key_id))


def sign_revocation(kp: core.KeyPair, attested: dict | str, *, issuer: str | None = None, key_id: str = "key-1",
               reason: str | None = None, now: datetime | None = None) -> dict:
    """A signed Revocation naming the attestation (the object, or its SHA-256 hex) (spec 8.4)."""
    sha = core.canonical_hash(attested).hex() if isinstance(attested, dict) else attested
    created = _ts(now or datetime.now(timezone.utc))
    obj = {"spec": core.SPEC, "type": "Revocation", "issuer": issuer or kp.did, "attestation_sha256": sha,
           **({"reason": reason} if reason else {}), "created": created}
    return core.sign_object(obj, kp, created, _method(kp, issuer, key_id))


def build_did_document(did: str, public: bytes, key_id: str = "key-1") -> dict:
    """The body of `https://<domain>/.well-known/did.json` for a did:web issuer."""
    vm = f"{did}#{key_id}"
    return {"@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"], "id": did,
            "verificationMethod": [{"id": vm, "type": "Multikey", "controller": did,
                                    "publicKeyMultibase": core.did_key_from_public_key(public).removeprefix("did:key:")}],
            "assertionMethod": [vm], "authentication": [vm]}


def build_openentity_json(did: str, public: bytes, name: str, description: str, *, key_id: str = "key-1",
                    operator: dict | None = None, extensions: dict | None = None) -> dict:
    """The unsigned body of `https://<domain>/.well-known/openentity.json`: the domain alias proof (spec 3.4) and,
    under `extensions["openentity:observer"]`, an observer's methodology (spec 8.4)."""
    return {"spec": core.SPEC, "eid": did, "name": name, "description": description,
            "keys": [{"id": f"{did}#{key_id}", "type": "Multikey",
                      "publicKeyMultibase": core.did_key_from_public_key(public).removeprefix("did:key:")}],
            "operator": operator or {"kind": "organization", "name": name, "custody": "operator", "can_change": []},
            **({"extensions": extensions} if extensions else {})}


A2A_EXTENSION_URI = "https://openentity.org/spec/1.0"


def a2a_extension(eid: str, document_url: str) -> dict:
    """The spec 11.2 A2A AgentExtension block."""
    return {"uri": A2A_EXTENSION_URI, "description": "Open Entity identity (OEIS-1) of this agent", "required": False, "params": {"eid": eid, "document": document_url}}


def agent_card(doc: dict, url: str, document_url: str, version: str = "1.0.0") -> dict:
    """A full A2A AgentCard for an Entity Document: each capability slug becomes a skill. `url` is the agent's A2A endpoint."""
    skills = []
    for slug in doc.get("capabilities") or []:
        ns, name = slug.split(":", 1) if ":" in slug else ("", slug)
        skills.append({"id": slug, "name": re.sub(r"[-.]", " ", name), "description": f"Self-declared capability: {slug}", "tags": [ns, name] if ns else [name]})
    return {"name": doc["name"], "description": doc["description"], "url": url, "version": version,
            "capabilities": {"streaming": False, "pushNotifications": False, "extensions": [a2a_extension(doc["eid"], document_url)]},
            "defaultInputModes": ["text/plain"], "defaultOutputModes": ["text/plain"], "skills": skills}


# Deprecated 0.5 names, kept until 1.0.
attestation, revocation, did_document, openentity_json = sign_attestation, sign_revocation, build_did_document, build_openentity_json
