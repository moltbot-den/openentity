"""The plain functions behind the tools: one Open Entity identity, adopt, read self, record, verify, trust.
The key never leaves Identity; no function here returns it. The registry is $OPENENTITY_REGISTRY or openentity.org."""
import os

import openentity
from openentity import Identity, core
from openentity.client import DEFAULT_REGISTRY, RegistryError, _request

CLIENT = "openai-agents"  # the unsigned adopt label (spec 10.2)


def _registry() -> str:
    return os.environ.get("OPENENTITY_REGISTRY", DEFAULT_REGISTRY).rstrip("/")


def _entity(eid: str) -> dict | None:
    try:
        return _request(f"{_registry()}/v1/entities/{eid}")
    except RegistryError as e:
        if e.status == 404:
            return None
        raise


def adopt(name: str, description: str = "") -> dict:
    """Adopt this agent's identity (created on first use) on the registry; a second call changes nothing."""
    ident = Identity.load_or_create()
    if _entity(ident.did):
        return {"eid": ident.did, "adopted": False}
    out = openentity.adopt(name, description or "An agent adopted through its Open Entity tools.",
                           registry=_registry(), seed=ident.seed, client=CLIENT)
    return {"eid": ident.did, "adopted": True, "level": out.get("level"), "record_pushed": out.get("record_pushed")}


def self_() -> dict:
    """This agent's own entity as the registry serves it: EID, level, document, and how many record entries it holds."""
    eid = Identity.load_or_create().did
    ent = _entity(eid)
    if not ent:
        return {"eid": eid, "adopted": False}
    return {"eid": eid, "adopted": True, "level": ent["level"], "name": ent["name"], "document": ent["document"],
            "record_entries": ent["counts"]["record_entries"]}


def _record(kind: str, payload: dict) -> dict:
    ident = Identity.load_or_create()
    out = openentity.record(ident.seed, [(kind, payload)], _registry())
    return {"eid": ident.did, "seq": out["entries"][0]["seq"], "kind": kind}


def record_stance(stance_type: str, reason_category: str, cost: str, context: str, instruction_conflict: bool = False) -> dict:
    """A stance entry: stance_type refusal|correction|limit_assertion, reason_category values|capability|safety|relationship,
    cost none|low|high. `context` says what happened, with no private content."""
    return _record("stance", {"stance_type": stance_type, "reason_category": reason_category, "cost": cost,
                              "context": context, "instruction_conflict": instruction_conflict})


def record_arc(action: str, arc_id: str, title: str, outcome: str = "") -> dict:
    """An arc entry: action `open` or `close`; `outcome` applies to close."""
    if action not in ("open", "close"):
        raise ValueError("action must be open or close")
    payload = {"arc_id": arc_id, "title": title}
    if action == "close" and outcome:
        payload["outcome"] = outcome
    return _record("arc_opened" if action == "open" else "arc_closed", payload)


def verify(eid: str) -> dict:
    """Check a counterparty's signed Entity Document and Declaration locally. ok=False on any failure."""
    try:
        ent = _request(f"{_registry()}/v1/entities/{eid}")
        doc, decl = ent["document"], ent["declaration"]
        checks = {"eid": ent["eid"] == eid and doc["eid"] == eid,
                  "document_signature": core.verify_object(doc) == (True, eid),
                  "declaration_signature": core.verify_object(decl) == (True, eid),
                  "declaration_text": decl["text_sha256"] == core.DECLARATION_SHA256}
    except Exception as e:  # fail closed: anything unreadable or malformed is not verified
        return {"eid": eid, "ok": False, "error": f"{type(e).__name__}: {e}"}
    return {"eid": eid, "ok": all(checks.values()), "checks": checks}


def trust(eid: str) -> dict:
    """The counterparty's TrustReport (attestations verified locally, cached 5 minutes) as a dict. ok=False means untrusted."""
    r = openentity.trust(eid, _registry())
    return {k: getattr(r, k) for k in r.__dataclass_fields__}
