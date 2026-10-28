"""trust(eid): one TrustReport from registry reads only (ADR 0002). Every attestation and revocation is verified
locally against its issuer's key; any failure returns an untrusted report (fail closed). Cached for 5 minutes."""
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import unquote

from . import client, core

MOLTBOTDEN, CLAWGRC = "did:web:moltbotden.com", "did:web:api.clawgrc.com"
SMA = ("did:web:securemyagent.ai", "did:pkh:eip155:8453:0x62fef02E2859726EC1c0B534853Ad2cdd5FdDE1a")
TIER, POSTURE, VIOLATION = "trust_tier", "custom:securemyagent:security_posture", "custom:clawgrc:violation"
ACCEPT = {TIER: (MOLTBOTDEN, CLAWGRC), POSTURE: SMA, VIOLATION: (CLAWGRC,)}  # claim_type -> issuers read; others are ignored
CACHE_SECONDS = 300
_cache: dict = {}


@dataclass(frozen=True)
class TrustReport:
    eid: str
    ok: bool  # False: a read failed or a signature did not verify. Treat the entity as untrusted.
    error: str | None = None
    level: str | None = None  # registry level, "L0" to "L3"
    withdrawn: bool = False
    trust_tier: dict = field(default_factory=dict)  # issuer DID -> newest live tier (0 to 4)
    security_posture: dict | None = None  # claim of the newest live custom:securemyagent:security_posture
    violations: list = field(default_factory=list)  # live custom:clawgrc:violation: issuer, severity, policy, observed_at, sha256
    revocations: list = field(default_factory=list)  # verified revocations of the accepted attestations


def did_web_resolver(fetch=client._request):
    """did:web through /.well-known/did.json (or <path>/did.json); everything else offline."""
    def resolve(did: str) -> dict:
        if not did.startswith("did:web:"):
            return core.default_resolver(did)
        host, *path = [unquote(p) for p in did[8:].split(":")]
        doc = fetch(f"https://{host}/{'/'.join(path) if path else '.well-known'}/did.json")
        if doc.get("id") != did:
            raise ValueError(f"{did} document names {doc.get('id')}")
        keys = []
        for vm in doc.get("verificationMethod", []):
            try:
                keys.append(core.public_from_did_key("did:key:" + vm["publicKeyMultibase"]))
            except (KeyError, ValueError):
                continue  # not an Ed25519 Multikey
        return {"ed25519": keys}
    return resolve


def trust(eid: str, registry: str = client.DEFAULT_REGISTRY, *, now: datetime | None = None, fetch=client._request,
          resolver=None) -> TrustReport:
    key = (registry, eid)
    hit = _cache.get(key)
    if hit and time.monotonic() - hit[0] < CACHE_SECONDS:
        return hit[1]
    try:
        report = _read(eid, registry.rstrip("/"), now or datetime.now(timezone.utc), fetch, resolver or did_web_resolver(fetch))
    except Exception as e:  # fail closed on anything: network, registry, schema, signature
        return TrustReport(eid, False, f"{type(e).__name__}: {e}")
    _cache[key] = (time.monotonic(), report)
    return report


def _read(eid, base, now, fetch, resolver) -> TrustReport:
    if not eid.startswith("did:"):
        raise ValueError("eid must be a DID")
    ent = fetch(f"{base}/v1/entities/{eid}")
    if ent["eid"] != eid:
        raise ValueError(f"registry answered for {ent['eid']}")
    rows = fetch(f"{base}/v1/entities/{eid}/attestations")["attestations"]
    tiers, posture, violations, revocations = {}, None, [], []
    for r in sorted(rows, key=lambda r: r["attestation"]["created"], reverse=True):
        a, ct = r["attestation"], r["attestation"].get("claim_type")
        if a.get("issuer", "").lower() not in {i.lower() for i in ACCEPT.get(ct, ())}:
            continue
        if r.get("inherited_from") and ct != VIOLATION:
            continue  # a rotation does not carry positive claims; a strike follows the entity
        sha, ended = r["sha256"], core._ts(a["expires"]) <= now
        if a["subject"] != (r.get("inherited_from") or eid) or core.canonical_hash(a).hex() != sha:
            raise ValueError(f"attestation {sha} does not match what the registry served")
        ok, signer = core.verify_object(a, resolver)
        if not ok or signer != a["issuer"]:
            raise ValueError(f"attestation {sha}: {signer}")
        rv = r.get("revocation")
        if rv:
            ok, signer = core.verify_object(rv, resolver)
            if not ok or signer != a["issuer"] or rv["attestation_sha256"] != sha:
                raise ValueError(f"revocation of {sha}: {signer}")
            revocations.append({"sha256": sha, "claim_type": ct, "issuer": a["issuer"], "reason": rv.get("reason"), "at": rv["created"]})
        elif r.get("revoked_at"):
            raise ValueError(f"registry reports a revocation of {sha} it does not carry")
        if ended or rv:
            continue
        c = a["claim"]
        if ct == TIER:
            tiers.setdefault(a["issuer"], c["tier"])
        elif ct == POSTURE:
            posture = posture or c
        else:
            violations.append({"issuer": a["issuer"], "severity": c["severity"], "policy": c["policy"], "observed_at": c["observed_at"], "sha256": sha})
    return TrustReport(eid, True, None, ent["level"], bool(ent.get("withdrawn")), tiers, posture, violations, revocations)
