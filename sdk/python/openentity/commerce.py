"""OEIS Commerce Profile (spec/commerce-profile.md): mandate/1, cart/1, receipt/1 and the one-call checkout check.

Verify and sign only: owners sign mandates on their devices, products verify. tests/test_commerce.py runs
test-vectors/{mandate-1,cart-1,receipt-1,checkout-1}; sdk/ts runs the same files. Results are dicts shaped like the TS SDK's.
"""
import re
import time
from urllib.parse import unquote

from .core import canonicalize, default_resolver, sign_proof, verify_proof, verification_method_id
from .errors import InvalidInputError
from .httpsig import verify_request
from .owner import (_DAY, _DID, _HEX64, RP_ID, _check_signature, _Fail, _plain, _sha, _signed_shape, _uint, payload_digest,
                    verify_approval)

_MAX_TTL = 90 * _DAY
_MD_ID = re.compile(r"md_[a-z2-7]{26}")
_RC_ID = re.compile(r"rc_[a-z2-7]{26}")
_CCY = re.compile(r"[A-Z]{3}")
_REQ = re.compile(r"[A-Za-z0-9:._-]{1,128}")
RAILS = ("card", "x402", "mpp", "credits", "usdc")
_PERIODS = ("P1D", "P7D", "P1M")
_BANDS = ("poor", "fair", "good", "strong")
_CART_KEYS = {"profile", "merchant", "agent_did", "lines", "total", "currency", "rail", "mandate_id"}
_LINE_KEYS = {"sku", "title", "qty", "unit"}
_MANDATE_KEYS = {"version", "mandate_id", "issuer_did", "agent_did", "issued_at", "expires_at", "limits", "scope", "step_up_over", "status", "signature"}
_RECEIPT_KEYS = {"version", "receipt_id", "kind", "refers_to", "merchant_did", "agent_did", "mandate_id", "mandate_hash", "cart_digest",
                 "approval_request_id", "total", "currency", "rail", "settlement_ref", "created_at"}


def _strs(v) -> bool:
    return isinstance(v, list) and all(isinstance(x, str) and 0 < len(x) <= 253 for x in v)


def _str(v, pat) -> bool:
    return isinstance(v, str) and pat.fullmatch(v) is not None


# ---- cart/1

def cart_error(c) -> str | None:
    """None when `c` is a well-formed cart/1 summary, else why not."""
    if not isinstance(c, dict) or set(c) != _CART_KEYS:
        return "cart/1 has exactly: " + ", ".join(sorted(_CART_KEYS))
    if c["profile"] != "cart/1":
        return "profile must be cart/1"
    if not _str(c["merchant"], _DID):
        return "merchant must be a DID"
    if not _str(c["agent_did"], _DID):
        return "agent_did must be a DID"
    if not _str(c["currency"], _CCY):
        return "currency must be 3 uppercase letters"
    if c["rail"] not in RAILS:
        return "rail must be one of " + ", ".join(RAILS)
    if c["mandate_id"] is not None and not _str(c["mandate_id"], _MD_ID):
        return "mandate_id must be md_<26 base32> or null"
    if not isinstance(c["lines"], list) or not 1 <= len(c["lines"]) <= 100:
        return "lines must hold 1 to 100 lines"
    total = 0
    for line in c["lines"]:
        if not isinstance(line, dict):
            return "a line must be an object"
        keys = _LINE_KEYS | ({"category"} if "category" in line else set())
        if set(line) != keys:
            return "a line has exactly: " + ", ".join(sorted(keys))
        if not isinstance(line["sku"], str) or not line["sku"] or not isinstance(line["title"], str) or not isinstance(line.get("category", ""), str):
            return "sku, title and category must be strings"
        if not _uint(line["qty"]) or not line["qty"] or not _uint(line["unit"]):
            return "qty must be a positive integer and unit an integer in minor units"
        total += line["qty"] * line["unit"]
    if not _uint(c["total"]) or c["total"] != total:
        return "total must equal the sum of qty * unit"
    return _plain(c)


def cart_digest(cart) -> str:
    """Lowercase hex payload digest of a cart/1 summary: the payload_digest of the approval/2.0 that approves this purchase."""
    e = cart_error(cart)
    if e:
        raise InvalidInputError(e)
    return payload_digest(cart)


# ---- mandate/1

def _mandate_error(m: dict) -> str | None:
    if not _MANDATE_KEYS <= set(m) or set(m) - _MANDATE_KEYS - {"ap2"}:
        return "mandate/1 has " + ", ".join(sorted(_MANDATE_KEYS)) + " and optionally ap2"
    if not _str(m["mandate_id"], _MD_ID):
        return "mandate_id must be md_<26 base32>"
    if not _str(m["issuer_did"], _DID) or not _str(m["agent_did"], _DID):
        return "issuer_did and agent_did must be DIDs"
    if not _uint(m["issued_at"]) or not _uint(m["expires_at"]) or m["expires_at"] <= m["issued_at"]:
        return "issued_at and expires_at must be unix seconds, expires after issued"
    if m["expires_at"] - m["issued_at"] > _MAX_TTL:
        return "a mandate lasts at most 90 days"
    lim = m["limits"]
    if not isinstance(lim, dict) or set(lim) != {"currency", "per_tx_max", "period", "period_max", "total_max"}:
        return "limits must be {currency, per_tx_max, period, period_max, total_max}"
    if not _str(lim["currency"], _CCY) or lim["period"] not in _PERIODS:
        return "limits.currency must be 3 uppercase letters and period one of " + ", ".join(_PERIODS)
    if not all(_uint(lim[k]) for k in ("per_tx_max", "period_max", "total_max")):
        return "limits amounts must be integers in minor units"
    s = m["scope"]
    if not isinstance(s, dict) or set(s) - {"merchants", "categories", "rails"} or not {"merchants", "rails"} <= set(s):
        return "scope must be {merchants, categories?, rails}"
    if not _strs(s["merchants"]) or ("categories" in s and not _strs(s["categories"])):
        return "scope.merchants and scope.categories must be arrays of strings"
    if not isinstance(s["rails"], list) or not s["rails"] or any(r not in RAILS for r in s["rails"]):
        return "scope.rails must be a non-empty subset of " + ", ".join(RAILS)
    if not _uint(m["step_up_over"]):
        return "step_up_over must be an integer in minor units"
    if not isinstance(m["status"], str) or not re.fullmatch(r"https://\S+", m["status"]):
        return "status must be an https URL"
    if "ap2" in m and not (isinstance(m["ap2"], dict) and set(m["ap2"]) == {"checkout_mandate_hash"}
                           and (m["ap2"]["checkout_mandate_hash"] is None or isinstance(m["ap2"]["checkout_mandate_hash"], str))):
        return "ap2 must be {checkout_mandate_hash: string | null}"
    sig = m["signature"]
    if not isinstance(sig, dict) or not isinstance(sig.get("device_id"), str):
        return "signature must hold device_id, form, signature"
    keys = {"device_id", "form", "signature"} | ({"authenticator_data", "client_data_json"} if sig.get("form") == "webauthn" else set())
    return _signed_shape(sig) or (_plain(m) if set(sig) == keys else "signature must have exactly " + ", ".join(sorted(keys)))


def mandate_digest(m: dict) -> bytes:
    """SHA-256 of `mandate/1|*|` + the RFC 8785 form of the mandate without its signature. `*` is the verifier scope: any merchant may rely on it."""
    if not isinstance(m, dict):
        raise InvalidInputError("mandate must be an object")
    return _sha("mandate/1|*|" + canonicalize({k: v for k, v in m.items() if k != "signature"}))


def verify_mandate(mandate, *, key_log: dict, agent_did: str | None = None, now: int | None = None, status: dict | None = None,
                   origins=None, rp_id: str = RP_ID) -> dict:
    """Verify a mandate/1 against the issuer's key log (verify_key_log's state, or a dict with did, approvers and closed).
    `status` is the answer of the mandate's status URL, fetched by the caller; without it a mandate is accepted only when it
    expires within a day. Returns {"ok": True, "kid", "mandate_id", "limits", "scope", "step_up_over", ...} or {"ok": False, "error", "message"}."""
    try:
        if not isinstance(mandate, dict):
            raise _Fail("malformed", "mandate must be an object")
        m = mandate
        if m.get("version") != "mandate/1":
            raise _Fail("bad_version", f"version {m.get('version')} is not mandate/1")
        bad = _mandate_error(m)
        if bad:
            raise _Fail("malformed", bad)
        now = int(time.time()) if now is None else now
        if m["issuer_did"] != key_log["did"]:
            raise _Fail("wrong_owner", "the mandate names another owner")
        if key_log["closed"]:
            raise _Fail("owner_closed", "the owner's key log is closed")
        if agent_did is not None and m["agent_did"] != agent_did:
            raise _Fail("wrong_agent", "the mandate is for another agent")
        if now < m["issued_at"]:
            raise _Fail("not_yet_valid", "the mandate is issued in the future")
        if now >= m["expires_at"]:
            raise _Fail("expired", "the mandate expired")
        cred = next((c for c in key_log["approvers"] if c["kid"] == m["signature"]["device_id"]), None)
        if cred is None:
            raise _Fail("unknown_key", "device_id is not a current approver in the owner's key log")
        _check_signature(cred, m["signature"], mandate_digest(m), [f"https://{rp_id}"] if origins is None else origins, rp_id, False)
        if status is not None:
            # A status answer that is not exactly what section 2.2 says is no answer: it never lets a mandate through.
            if (not isinstance(status, dict) or status.get("status") not in ("active", "revoked", "exhausted")
                    or status.get("mandate_id", m["mandate_id"]) != m["mandate_id"]
                    or any(k in status and not _uint(status[k]) for k in ("period_spent", "total_spent"))):
                raise _Fail("status_required", "the status answer is malformed or for another mandate")
            if status["status"] == "revoked":
                raise _Fail("revoked", "the owner revoked the mandate")
            if status["status"] == "exhausted":
                raise _Fail("exhausted", "the mandate is spent")
        elif m["expires_at"] - now > _DAY:
            raise _Fail("status_required", "a mandate with more than a day left needs a fresh status answer")
        out = {"ok": True, "kid": cred["kid"], "mandate_id": m["mandate_id"], "limits": m["limits"], "scope": m["scope"], "step_up_over": m["step_up_over"]}
        for k in ("period_spent", "total_spent"):
            if status and status.get(k) is not None:
                out[k] = status[k]
        return out
    except _Fail as f:
        return {"ok": False, "error": f.code, "message": str(f)}


_HOST = re.compile(r"[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:\d+)?")


def _did_host(did: str) -> str | None:
    """The host of a did:web DID, lowercase, without port; None for other methods and for anything that is not a plain hostname (%2F, %23, %3F, a bad escape)."""
    if not did.startswith("did:web:"):
        return None
    try:
        d = unquote(did[8:].split(":")[0], errors="strict").lower()
    except UnicodeDecodeError:
        return None
    return d.split(":")[0] if _HOST.fullmatch(d) else None


def _merchant_allowed(patterns: list, merchant: str) -> bool:
    if not patterns:
        return True
    host = _did_host(merchant)
    for p in patterns:
        if p == merchant:
            return True
        if p.startswith("did:") or host is None:
            continue
        d = p.lower()
        if host.endswith(d[1:]) if d.startswith("*.") else host == d:
            return True
    return False


def mandate_covers(mandate: dict, cart, spent: dict | None = None) -> dict:
    """Whether a verified mandate allows this cart. `step_up_required` means the cart fits but is above step_up_over: the owner
    must approve this exact cart (approval/2.0 over cart_digest). `spent` is {period_spent, total_spent} from the status answer."""
    def no(reason, detail):
        return {"ok": False, "step_up_required": False, "reason": reason, "detail": detail}
    bad = cart_error(cart)
    if bad:
        return no("bad_cart", bad)
    c, lim, s, spent = cart, mandate["limits"], mandate["scope"], spent or {}
    if c["agent_did"] != mandate["agent_did"]:
        return no("wrong_agent", "the cart is for another agent")
    if c["mandate_id"] is not None and c["mandate_id"] != mandate["mandate_id"]:
        return no("wrong_mandate", "the cart names another mandate")
    if c["currency"] != lim["currency"]:
        return no("wrong_currency", f"the mandate is in {lim['currency']}")
    if c["rail"] not in s["rails"]:
        return no("out_of_scope", f"rail {c['rail']} is not in scope")
    if not _merchant_allowed(s["merchants"], c["merchant"]):
        return no("out_of_scope", f"merchant {c['merchant']} is not in scope")
    if s.get("categories") and any(x.get("category") not in s["categories"] for x in c["lines"]):
        return no("out_of_scope", "a line is outside the categories")
    if not all(spent.get(k) is None or _uint(spent[k]) for k in ("period_spent", "total_spent")):
        return no("over_limit", "spent must be unsigned integers")
    if c["total"] > lim["per_tx_max"]:
        return no("over_limit", "per_tx_max")
    if (spent.get("period_spent") or 0) + c["total"] > lim["period_max"]:
        return no("over_limit", "period_max")
    if (spent.get("total_spent") or 0) + c["total"] > lim["total_max"]:
        return no("over_limit", "total_max")
    return {"ok": True, "step_up_required": c["total"] > mandate["step_up_over"]}


# ---- receipt/1

def receipt_error(r) -> str | None:
    """None when `r` is a well-formed receipt/1 (proofs aside), else why not."""
    if not isinstance(r, dict):
        return "receipt must be an object"
    if set(r) - _RECEIPT_KEYS - {"proofs"} or not _RECEIPT_KEYS <= set(r):
        return "receipt/1 has exactly: " + ", ".join(sorted(_RECEIPT_KEYS)) + ", proofs"
    if r["version"] != "receipt/1":
        return "version must be receipt/1"
    if not _str(r["receipt_id"], _RC_ID):
        return "receipt_id must be rc_<26 base32>"
    if r["kind"] not in ("purchase", "refund", "chargeback"):
        return "kind must be purchase, refund or chargeback"
    if (r["refers_to"] is not None) if r["kind"] == "purchase" else not _str(r["refers_to"], _RC_ID):
        return "refers_to is null for a purchase and the purchase's receipt_id for a refund or chargeback"
    if not _str(r["merchant_did"], _DID) or not _str(r["agent_did"], _DID):
        return "merchant_did and agent_did must be DIDs"
    if r["merchant_did"] == r["agent_did"]:
        return "merchant_did and agent_did must differ"
    if r["mandate_id"] is not None and not _str(r["mandate_id"], _MD_ID):
        return "mandate_id must be md_<26 base32> or null"
    if r["mandate_hash"] is not None and not _str(r["mandate_hash"], _HEX64):
        return "mandate_hash must be 64 lowercase hex or null"
    if (r["mandate_id"] is None) != (r["mandate_hash"] is None):
        return "mandate_id and mandate_hash go together"
    if not _str(r["cart_digest"], _HEX64):
        return "cart_digest must be 64 lowercase hex"
    if r["approval_request_id"] is not None and not _str(r["approval_request_id"], _REQ):
        return "approval_request_id must be a request id or null"
    if not _uint(r["total"]) or not _uint(r["created_at"]):
        return "total and created_at must be unsigned integers"
    if not _str(r["currency"], _CCY):
        return "currency must be 3 uppercase letters"
    if r["rail"] not in RAILS:
        return "rail must be one of " + ", ".join(RAILS)
    if not isinstance(r["settlement_ref"], str) or not 1 <= len(r["settlement_ref"]) <= 256:
        return "settlement_ref must be 1 to 256 characters"
    if "proofs" in r and not isinstance(r["proofs"], list):
        return "proofs must be an array"
    return _plain(r)


def sign_receipt(receipt: dict, kp, by: str, created: str | None = None, method: str | None = None) -> dict:
    """Add `by`'s eddsa-jcs-2022 proof ("merchant" or "agent"). Both parties sign the same bytes (the receipt without proofs), so
    the buyer countersigns without seeing the merchant's proof. A did:web merchant passes its own verification `method`."""
    e = receipt_error(receipt)
    if e:
        raise InvalidInputError(e)
    if by not in ("merchant", "agent"):
        raise InvalidInputError("by must be merchant or agent")
    if (method or verification_method_id(kp.did)).split("#")[0] != receipt[f"{by}_did"]:
        raise InvalidInputError(f"{by}_did is not the signing key's DID")
    if any(p.get("by") == by for p in receipt.get("proofs", [])):
        raise InvalidInputError(f"already signed by {by}")
    return {**receipt, "proofs": [*receipt.get("proofs", []), {"by": by, **sign_proof(receipt, kp, created, method)}]}


def verify_receipt(receipt, *, resolver=default_resolver, require=("merchant",)) -> dict:
    """Verify the proofs on a receipt. `require` lists who must have signed; any proof present must verify, and its signer must be
    the receipt's merchant_did or agent_did named by `by`. Returns {"ok": True, "signed_by"} or {"ok": False, "error", "message"}."""
    e = receipt_error(receipt)
    if e:
        return {"ok": False, "error": "malformed", "message": e}
    signed = []
    for p in receipt.get("proofs", []):
        if not isinstance(p, dict) or p.get("by") not in ("merchant", "agent") or p["by"] in signed:
            return {"ok": False, "error": "malformed", "message": "each proof names a distinct by: merchant or agent"}
        by, proof = p["by"], {k: v for k, v in p.items() if k != "by"}
        if not isinstance(proof.get("verificationMethod"), str) or proof["verificationMethod"].split("#")[0] != receipt[f"{by}_did"]:
            return {"ok": False, "error": "wrong_signer", "message": f"the {by} proof is not by {by}_did"}
        ok, why = verify_proof(receipt, proof, resolver)
        if not ok:
            return {"ok": False, "error": "bad_proof", "message": f"{by}: {why}"}
        signed.append(by)
    for need in require:
        if need not in signed:
            return {"ok": False, "error": "missing_proof", "message": f"no {need} proof"}
    return {"ok": True, "signed_by": signed}


def verify_receipt_chain(purchase, later) -> dict:
    """Structural check that refunds and chargebacks are consistent with their purchase: each refers_to the purchase, same parties,
    currency and rail, no repeated receipt_id, and their sum at most the purchase total. Proofs are verify_receipt's job; run both."""
    def bad(error, message):
        return {"ok": False, "error": error, "message": message}
    e = next((x for x in map(receipt_error, [purchase, *later]) if x), None)
    if e:
        return bad("malformed", e)
    if purchase["kind"] != "purchase":
        return bad("not_purchase", "the first receipt must be a purchase")
    ids, refunded = {purchase["receipt_id"]}, 0
    for x in later:
        if x["kind"] == "purchase" or x["refers_to"] != purchase["receipt_id"]:
            return bad("mismatch", "each later receipt must be a refund or chargeback of this purchase")
        if x["receipt_id"] in ids:
            return bad("mismatch", "receipt_id repeats")
        ids.add(x["receipt_id"])
        if any(x[k] != purchase[k] for k in ("merchant_did", "agent_did", "currency", "rail")):
            return bad("mismatch", "parties, currency and rail must equal the purchase's")
        refunded += x["total"]
    if refunded > purchase["total"]:
        return bad("over_refund", "refunds and chargebacks exceed the purchase total")
    return {"ok": True, "refunded": refunded}


# ---- the checkout check

def verify_agent_for_checkout(*, cart, merchant_policy: dict, agent_did: str | None = None, request: dict | None = None,
                              agent: dict | None = None, mandate=None, key_log: dict | None = None, status: dict | None = None,
                              approval: dict | None = None, now: int | None = None, origins=None) -> dict:
    """The one-call check behind Agent Commerce Check: agent, owner, mandate, cart and merchant policy in, "allow", "step_up" or
    "deny" with reasons out. Deny is final (bad signature, wrong agent, dead mandate, policy unmet); step_up means an owner approval
    of this exact cart would allow. `request` ({method, url, headers, body}) is verified here; or pass `agent_did` when the caller
    already did. `agent` is what the registry says (level, owner_did, security_band, security_issuer), never the request's claim.
    `approval` is {approval, verifier_did, request_id, counter?}: the owner's approval/2.0 of this cart, with the merchant's own ids."""
    now = int(time.time()) if now is None else now
    evidence: dict = {}

    def deny(*reasons):
        return {"decision": "deny", "reasons": list(reasons), "evidence": evidence}
    if cart_error(cart):
        return deny("bad_cart")
    pol, facts = merchant_policy or {}, agent or {}
    if request is not None:
        try:
            agent_did = verify_request(request["method"], request["url"], request["headers"], request.get("body", b""), now=now,
                                       max_age=request.get("max_age", 300))["did"]
            evidence["request"] = "verified"
        except Exception:  # HttpSigError and anything a hostile header can raise: either way the request is unverified
            return deny("request_unverified")
    if not agent_did:
        return deny("request_unverified")
    evidence["agent_did"] = agent_did
    if cart["agent_did"] != agent_did:
        return deny("agent_mismatch")

    reasons = []
    if pol.get("min_level") is not None and not (facts.get("level") is not None and facts["level"] >= pol["min_level"]):
        reasons.append("level_too_low")
    if pol.get("min_security_band") is not None:
        need = _BANDS.index(pol["min_security_band"]) if pol["min_security_band"] in _BANDS else len(_BANDS)
        got = _BANDS.index(facts["security_band"]) if facts.get("security_band") in _BANDS else -1
        if got < 0 or got < need:
            reasons.append("security_band_too_low")
        elif pol.get("accept_issuers") and facts.get("security_issuer") not in pol["accept_issuers"]:
            reasons.append("issuer_not_accepted")

    owner, covered = facts.get("owner_did"), None
    if mandate is not None:
        if not key_log:
            return deny("no_key_log")
        v = verify_mandate(mandate, key_log=key_log, agent_did=agent_did, now=now, status=status, origins=origins)
        if not v["ok"]:
            return deny(f"mandate_{v['error']}")
        owner = mandate["issuer_did"]
        evidence["mandate_id"] = v["mandate_id"]
        evidence["mandate_hash"] = mandate_digest(mandate).hex()
        covered = mandate_covers(mandate, cart, status)
        if not covered["ok"] and covered["reason"] not in ("over_limit", "out_of_scope"):
            return deny(f"mandate_{covered['reason']}")
    elif pol.get("require_mandate"):
        reasons.append("mandate_required")
    if pol.get("require_owner") and not owner:
        reasons.append("owner_unknown")
    if reasons:
        return deny(*reasons)

    if covered and covered["ok"] and not covered["step_up_required"]:
        return {"decision": "allow", "reasons": ["mandate_covers_cart"], "evidence": evidence}
    why = "no_mandate" if not covered else f"mandate_{covered['reason']}" if not covered["ok"] else "step_up_over"
    if approval and key_log and owner:
        a = verify_approval(approval["approval"], key_log=key_log, verifier_did=approval["verifier_did"], owner_did=owner,
                            request_id=approval["request_id"], payload_digest=cart_digest(cart), decisions=("approve",), now=now,
                            origins=origins, counter=approval.get("counter", 0))
        if a["ok"]:
            evidence["approval_request_id"] = approval["request_id"]
            evidence["approval_kid"], evidence["approval_counter"] = a["kid"], a["counter"]
            return {"decision": "allow", "reasons": ["owner_approved_cart", why], "evidence": evidence}
        evidence["approval_error"] = a["error"]
    return {"decision": "step_up", "reasons": [why], "evidence": evidence}
