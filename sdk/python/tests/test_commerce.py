"""OEIS Commerce Profile vectors (mandate-1, cart-1, receipt-1, checkout-1): the same files sdk/ts runs."""
import json
import pathlib

import pytest

import openentity as oe
from openentity.errors import InvalidInputError

DIR = pathlib.Path(__file__).parents[3] / "test-vectors"
load = lambda p: json.loads((DIR / p).read_text())
STATES = load("approval-2.0/vectors.json")["key_states"]
MANDATES = load("mandate-1/vectors.json")
CARTS = load("cart-1/vectors.json")
RECEIPTS = load("receipt-1/vectors.json")
PKH = load("receipt-1/pkh.json")
CHECKOUT = load("checkout-1/vectors.json")


@pytest.mark.parametrize("c", MANDATES["cases"], ids=lambda c: c["name"])
def test_mandate(c):
    x = c["context"]
    r = oe.verify_mandate(c["mandate"], key_log=STATES[x["key_state"]], agent_did=x.get("agent_did"), now=x["now"], status=x.get("status"))
    if r["ok"]:
        got = {k: r[k] for k in ("ok", "mandate_id", "limits", "scope", "step_up_over", "period_spent", "total_spent") if k in r}
        if "kid" in c["expect"]:
            got["kid"] = r["kid"]
    else:
        got = {"ok": False, "error": r["error"]}
    assert got == c["expect"], r.get("message")


def test_mandate_digests_and_replay():
    pool = {}
    for m in [*CARTS["mandates"].values(), *(c["mandate"] for c in MANDATES["cases"])]:
        pool.setdefault(m["mandate_id"], m)  # the tampered case reuses an id: the first is the real one
    for d in MANDATES["digests"]:
        assert oe.mandate_digest(pool[d["mandate_id"]]).hex() == d["digest"]
    r = MANDATES["replay"]["mandate_signature_as_approval"]
    c = r["context"]
    got = oe.verify_approval(r["approval"], key_log=STATES[c["key_state"]], verifier_did=c["verifier_did"], owner_did=c["owner_did"],
                             request_id=c["request_id"], payload_digest=c["payload_digest"], now=c["now"])
    assert got["ok"] is False and got["error"] == r["expect"]["error"]


def test_cart_digests():
    for c in CARTS["carts"]:
        assert oe.canonicalize(c["cart"]) == c["canonical"]
        assert oe.cart_digest(c["cart"]) == c["digest"]
    for c in CARTS["invalid"]:
        with pytest.raises(InvalidInputError):
            oe.cart_digest(c["cart"])


@pytest.mark.parametrize("c", CARTS["covers"], ids=lambda c: c["name"])
def test_covers(c):
    r = oe.mandate_covers(CARTS["mandates"][c["mandate"]], c["cart"], c.get("spent"))
    assert {k: r[k] for k in ("ok", "step_up_required", "reason") if k in r} == c["expect"]


@pytest.mark.parametrize("c", RECEIPTS["cases"], ids=lambda c: c["name"])
def test_receipt(c):
    r = oe.verify_receipt(c["receipt"], require=c.get("require", ["merchant"]))
    assert ({"ok": True, "signed_by": r["signed_by"]} if r["ok"] else {"ok": False, "error": r["error"]}) == c["expect"], r.get("message")


def test_sign_receipt_guards():
    k = oe.key_pair_from_seed(bytes(i + 77 for i in range(32)))
    base = RECEIPTS["cases"][0]["receipt"]
    bare = {x: v for x, v in base.items() if x != "proofs"}
    with pytest.raises(InvalidInputError):
        oe.sign_receipt(bare, k, "merchant")
    agent = oe.key_pair_from_seed(bytes(i + 1 for i in range(32)))
    with pytest.raises(InvalidInputError, match="already signed"):
        oe.sign_receipt(base, agent, "agent")
    # The Python signer reproduces the committed proof byte for byte (Ed25519 is deterministic).
    merchant = oe.key_pair_from_seed(bytes(i + 0x21 for i in range(32)))
    again = oe.sign_receipt(bare, merchant, "merchant", created="2026-11-07T00:02:00Z")
    assert again["proofs"][0] == base["proofs"][0]


@pytest.mark.parametrize("c", PKH["cases"], ids=lambda c: c["name"])
def test_receipt_with_a_pkh_party(c):
    r = oe.verify_receipt(c["receipt"], require=c["require"])
    assert ({"ok": True, "signed_by": r["signed_by"]} if r["ok"] else {"ok": False, "error": r["error"]}) == c["expect"], r.get("message")


def test_pkh_receipt_signing_helpers():
    s = PKH["signing"]
    for r in (s["unsigned"], s["merchant_signed"]):
        assert "0x" + oe.receipt_eip712_digest(r, s["created"]).hex() == s["digest"]
    assert oe.add_receipt_eip712_proof(s["merchant_signed"], "agent", s["signature"], s["created"]) == s["countersigned"]
    other = next(c for c in PKH["cases"] if c["name"] == "other-wallet")["receipt"]["proofs"][-1]["proofValue"]
    for args, why in (((s["merchant_signed"], "agent", other), "not by agent_did"), ((s["countersigned"], "agent", s["signature"]), "already signed"),
                      ((s["unsigned"], "merchant", s["signature"]), "not a did:pkh"), ((s["merchant_signed"], "agent", "0x1234"), "not by agent_did")):
        with pytest.raises(InvalidInputError, match=why):
            oe.add_receipt_eip712_proof(*args, s["created"])


@pytest.mark.parametrize("c", CHECKOUT["cases"], ids=lambda c: c["name"])
def test_checkout(c):
    i = c["input"]
    a = i.get("approval")
    r = oe.verify_agent_for_checkout(
        agent_did=i.get("agent_did"), cart=i["cart"], merchant_policy=i["merchant_policy"], agent=i.get("agent"), mandate=i.get("mandate"),
        key_log=STATES[i["key_state"]], status=i.get("status"), now=i["now"], approval=a)
    got = {"decision": r["decision"], "reasons": r["reasons"]}
    if "approval_error" in r["evidence"]:
        got["approval_error"] = r["evidence"]["approval_error"]
    if "approval_counter" in c["expect"]:
        got["approval_counter"] = r["evidence"]["approval_counter"]
    assert got == c["expect"]


def test_checkout_verifies_the_signed_request():
    k = oe.key_pair_from_seed(bytes(i + 77 for i in range(32)))
    cart = {**CHECKOUT["cases"][0]["input"]["cart"], "agent_did": k.did, "mandate_id": None}
    url, now = "https://shop.example/checkout", 1_800_000_000
    headers = oe.sign_request("POST", url, b"", k, k.did, created=now)
    ok = oe.verify_agent_for_checkout(cart=cart, merchant_policy={}, request={"method": "POST", "url": url, "headers": headers}, now=now)
    assert (ok["decision"], ok["reasons"], ok["evidence"]["request"]) == ("step_up", ["no_mandate"], "verified")
    bad = oe.verify_agent_for_checkout(cart=cart, merchant_policy={}, request={"method": "POST", "url": "https://evil.example/", "headers": headers}, now=now)
    assert bad["reasons"] == ["request_unverified"]
    other = {**cart, "agent_did": CHECKOUT["cases"][0]["input"]["agent_did"]}
    assert oe.verify_agent_for_checkout(cart=other, merchant_policy={}, request={"method": "POST", "url": url, "headers": headers}, now=now)["reasons"] == ["agent_mismatch"]


# ---- adversarial review fixes (same cases as the TS "adversarial review fixes" block)

def test_wildcard_merchant_matches_only_a_plain_hostname():
    m, cart = CARTS["mandates"]["M"], CARTS["covers"][0]["cart"]
    at = lambda merchant: oe.mandate_covers(m, {**cart, "merchant": merchant})
    assert at("did:web:shop.moltbotden.com")["ok"] and at("did:web:shop.moltbotden.com%3A8443")["ok"]
    for evil in ("did:web:evil.com%2F.moltbotden.com", "did:web:evil.com%23.moltbotden.com", "did:web:evil.com%3F.moltbotden.com",
                 "did:web:evil.com%40.moltbotden.com", "did:web:%zz.moltbotden.com", "did:web:%ff.moltbotden.com"):
        assert at(evil)["reason"] == "out_of_scope", evil


def test_spent_that_is_not_an_unsigned_integer_never_fits():
    m, cart = CARTS["mandates"]["M"], CARTS["covers"][0]["cart"]
    for bad in (float("nan"), "abc", -1000, 1.5, True):
        assert oe.mandate_covers(m, cart, {"period_spent": bad})["reason"] == "over_limit", bad


def test_a_malformed_or_foreign_status_answer_is_no_answer():
    c = MANDATES["cases"][0]
    x = c["context"]
    run = lambda status: oe.verify_mandate(c["mandate"], key_log=STATES[x["key_state"]], agent_did=x.get("agent_did"), now=x["now"], status=status)
    for bad in ({}, {"status": "bogus"}, {"status": "active", "mandate_id": "md_aaaaaaaaaaaaaaaaaaaaaaaaaa"}, {"status": "active", "total_spent": "abc"},
                {"status": "active", "period_spent": -1}, "active"):
        assert run(bad)["error"] == "status_required", bad
    assert run({"status": "active", "mandate_id": c["mandate"]["mandate_id"]})["ok"]


def test_receipt_parties_differ_and_refunds_stay_inside_the_purchase():
    p = RECEIPTS["cases"][0]["receipt"]
    assert "differ" in oe.receipt_error({**p, "merchant_did": p["agent_did"]})
    refund = lambda rid, total, **kw: {**{k: v for k, v in p.items() if k != "proofs"}, "kind": "refund", "receipt_id": rid, "refers_to": p["receipt_id"], "total": total, **kw}
    r1, r2 = refund("rc_" + "a" * 26, 600), refund("rc_" + "b" * 26, 400)
    assert oe.verify_receipt_chain(p, [r1, r2]) == {"ok": True, "refunded": 1000}
    assert oe.verify_receipt_chain(p, [r1, {**r2, "total": 401}])["error"] == "over_refund"
    assert oe.verify_receipt_chain(p, [r1, r1])["error"] == "mismatch"
    assert oe.verify_receipt_chain(p, [{**r1, "currency": "EUR"}])["error"] == "mismatch"
    assert oe.verify_receipt_chain(p, [{**r1, "refers_to": "rc_" + "c" * 26}])["error"] == "mismatch"
    assert oe.verify_receipt_chain(r1, [])["error"] == "not_purchase"


def test_an_allow_by_approval_hands_back_the_key_and_counter():
    i = next(c for c in CHECKOUT["cases"] if c["name"] == "allow-step-up-approved")["input"]
    r = oe.verify_agent_for_checkout(agent_did=i.get("agent_did"), cart=i["cart"], merchant_policy=i["merchant_policy"], agent=i.get("agent"), mandate=i.get("mandate"),
                                     key_log=STATES[i["key_state"]], status=i.get("status"), now=i["now"], approval={**i["approval"], "counter": 0})
    assert (r["evidence"]["approval_kid"], r["evidence"]["approval_counter"]) == (i["approval"]["approval"]["device_id"], 0)


QUORUM = load("quorum-1/vectors.json")


@pytest.mark.parametrize("c", QUORUM["cases"], ids=lambda c: c["name"])
def test_quorum(c):
    x = c["context"]
    r = oe.verify_quorum(c["approvals"], key_log=STATES[x["key_state"]], verifier_did=x["verifier_did"], owner_did=x["owner_did"],
                         request_id=x["request_id"], payload_digest=x["payload_digest"], now=x["now"], m=x["m"], of=x["of"])
    got = {"ok": True, "kids": r["kids"]} if r["ok"] else {"ok": False, "error": r["error"]}
    assert got == c["expect"], r.get("message")


def test_checkout_with_org_quorum():
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    import base64
    c = next(x for x in CHECKOUT["cases"] if x["name"] == "step-up-over-threshold")["input"]
    keys = [ec.generate_private_key(ec.SECP256R1()) for _ in range(2)]
    b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()

    def cred(i, k):
        n = k.public_key().public_numbers()
        return {"kid": f"org-device-{i}", "type": "p256", "jwk": {"kty": "EC", "crv": "P-256", "x": b64(n.x.to_bytes(32, "big")), "y": b64(n.y.to_bytes(32, "big"))}}

    creds = [cred(i, k) for i, k in enumerate(keys)]
    base = STATES[c["key_state"]]
    key_log = {**base, "approvers": [*base["approvers"], *creds]}

    def signed(i, **over):
        a = {"version": "approval/2.0", "verifier_did": "did:web:shop.example", "owner_did": base["did"], "request_id": "req_q1",
             "payload_digest": oe.cart_digest(c["cart"]), "decision": "approve", "expires_at": c["now"] + 300, **over}
        r, s = utils.decode_dss_signature(keys[i].sign(oe.approval_digest(a), ec.ECDSA(utils.Prehashed(hashes.SHA256()))))
        return {**a, "device_id": creds[i]["kid"], "form": "p256", "signature": b64(r.to_bytes(32, "big") + s.to_bytes(32, "big"))}

    def run(approvals, **over):
        q = {"approvals": approvals, "m": 2, "of": [x["kid"] for x in creds], "verifier_did": "did:web:shop.example", "request_id": "req_q1", **over}
        return oe.verify_agent_for_checkout(agent_did=c["agent_did"], cart=c["cart"], merchant_policy=c["merchant_policy"], agent=c.get("agent"),
                                            mandate=c["mandate"], key_log=key_log, status=c["status"], quorum=q, now=c["now"])

    ok = run([signed(0), signed(1)])
    assert ok["decision"] == "allow" and ok["evidence"]["approval_kids"] == [x["kid"] for x in creds]
    for bundle, over in ([[signed(0)], {}], [[signed(0), signed(0)], {}], [[signed(0), signed(1, payload_digest="0" * 64)], {}], [[signed(0), signed(1)], {"request_id": "req_other"}]):
        r = run(bundle, **over)
        assert r["decision"] == "step_up" and r["evidence"]["approval_error"]
