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
