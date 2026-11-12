"""Owner key log (keylog-1), approval/2.0 and pair-sas/1 vectors, written by the TS generator and checked here independently."""
import hashlib
import json
import pathlib

import pytest

import openentity
from openentity.pair import PAIR_SAS_WORDS

VEC = pathlib.Path(__file__).parents[3] / "test-vectors"
A = json.loads((VEC / "approval-2.0" / "vectors.json").read_text())
KEYLOG = sorted(p for p in (VEC / "keylog-1").glob("*.json") if p.name != "keys.json")


def test_every_keylog_rule_has_a_vector():
    assert len(KEYLOG) >= 50


@pytest.mark.parametrize("path", KEYLOG, ids=lambda p: p.stem)
def test_keylog(path):
    v = json.loads(path.read_text())
    r = openentity.verify_key_log(v["did"], v["log"], v["first_seen_at"], now=v["now"], origins=v["origins"], service_keys=v["service_keys"])
    if r["ok"]:
        s = r["state"]
        got = {"ok": True, "state": {**s, "root": s["root"]["kid"], "approvers": [c["kid"] for c in s["approvers"]]}}
    else:
        got = {"ok": False, "error": r["error"], "seq": r["seq"]}
    assert got == v["expect"], r.get("message")


def test_keylog_did_is_base32_of_the_genesis_line():
    import base64
    v = json.loads((VEC / "keylog-1" / "genesis-device.json").read_text())
    suffix = base64.b32encode(hashlib.sha256(v["log"][0].encode()).digest()).decode().rstrip("=").lower()
    assert v["did"] == f"did:web:account.openentity.org:o:{suffix}"


def test_keylog_input_errors():
    v = json.loads((VEC / "keylog-1" / "genesis-device.json").read_text())
    assert openentity.verify_key_log(v["did"], v["log"], [], now=v["now"])["error"] == "bad_first_seen"
    with pytest.raises(openentity.InvalidInputError):
        openentity.verify_key_log(v["did"], v["log"], v["first_seen_at"], service_keys=[{"kty": "EC", "crv": "P-256", "x": "AA", "y": "AA"}])
    # A boolean is not the integer 1 (Python's True == 1 must not leak through).
    e = json.loads(v["log"][0])
    e["v"] = True
    line = openentity.canonicalize(e)
    assert openentity.verify_key_log(v["did"], [line], v["first_seen_at"], now=v["now"])["error"] == "malformed"


def test_digests_for_both_decisions():
    assert [d["fields"]["decision"] for d in A["digests"]] == ["approve", "deny"]
    for d in A["digests"]:
        f = d["fields"]
        assert d["preimage"] == "|".join(["approval/2.0", f["verifier_did"], f["owner_did"], f["request_id"], f["payload_digest"],
                                          f["decision"], str(f["expires_at"])])
        assert hashlib.sha256(d["preimage"].encode()).hexdigest() == d["digest"]
        assert openentity.approval_digest(f).hex() == d["digest"]
    for bad in ({"request_id": "a|b"}, {"request_id": "a\n"}, {"owner_did": "did:web:x|y"}, {"expires_at": True}, {"payload_digest": "AB" * 32}):
        with pytest.raises(openentity.InvalidInputError):
            openentity.approval_digest({**A["digests"][0]["fields"], **bad})


def test_payload_digests():
    for p in A["payloads"]:
        assert openentity.canonicalize(p["summary"]) == p["canonical"]
        assert openentity.payload_digest(p["summary"]) == p["digest"]
    for p in A["payloads_invalid"]:
        with pytest.raises(openentity.InvalidInputError):
            openentity.payload_digest(p["summary"])


@pytest.mark.parametrize("c", A["cases"], ids=lambda c: c["name"])
def test_approval(c):
    x = c["context"]
    r = openentity.verify_approval(c["approval"], key_log=A["key_states"][x["key_state"]], verifier_did=x["verifier_did"],
                                   owner_did=x["owner_did"], request_id=x["request_id"], payload_digest=x["payload_digest"], now=x["now"],
                                   decisions=x.get("decisions", ("approve", "deny")), origins=x["origins"], counter=x.get("counter", 0),
                                   allow_root=x.get("allow_root", False))
    got = {"ok": True, "kid": r["kid"], "counter": r["counter"]} if r["ok"] else {"ok": False, "error": r["error"]}
    assert got == c["expect"], r.get("message")


def test_key_states_come_from_their_logs():
    service = json.loads((VEC / "approval-2.0" / "keys.json").read_text())["keys"]["service"]["jwk"]
    ctx = A["cases"][0]["context"]
    for name, log in A["key_logs"].items():
        r = openentity.verify_key_log(log["did"], log["log"], log["first_seen_at"], now=ctx["now"], origins=ctx["origins"], service_keys=[service])
        assert r["ok"], r.get("message")
        assert {k: r["state"][k] for k in ("did", "root", "approvers", "closed")} == A["key_states"][name]


def test_pair_sas():
    words = json.loads((VEC / "pair-sas-1" / "words.json").read_text())
    assert list(PAIR_SAS_WORDS) == words["words"] and len(set(words["words"])) == 256
    for c in json.loads((VEC / "pair-sas-1" / "vectors.json").read_text())["cases"]:
        assert hashlib.sha256(c["preimage"].encode()).hexdigest() == c["sha256"]
        assert openentity.pair_sas(c["code"], c["agent_did"]) == c["items"]
    for code, did in (("OE-123", "did:key:z6Mk"), ("OE-1234-5678", "not a did"), ("OE-1234-5678", "did:key:z6Mk\n")):
        with pytest.raises(openentity.InvalidInputError):
            openentity.pair_sas(code, did)


def test_hostile_input_is_refused_never_raised():
    """Review gate: deep JSON, NaN and truncated DER give a verifier failure (a 422), never an exception (a 500)."""
    from openentity.owner import _der_to_raw
    deep = "[" * 100_000 + "]" * 100_000
    for bad in (deep, '{"n": NaN}', '{"n": Infinity}', '[-Infinity]'):
        with pytest.raises(openentity.InvalidInputError):
            openentity.parse_json(bad)
    v = json.loads((VEC / "keylog-1" / "genesis-device.json").read_text())
    r = openentity.verify_key_log(v["did"], [deep], v["first_seen_at"], now=v["now"])
    assert (r["ok"], r["error"]) == (False, "malformed")
    case = next(c for c in A["cases"] if c["name"] == "webauthn-web-origin")
    x = case["context"]
    import base64
    for client in (deep, '{"type":"webauthn.get","n":NaN}'):
        approval = {**case["approval"], "client_data_json": base64.urlsafe_b64encode(client.encode()).rstrip(b"=").decode()}
        r = openentity.verify_approval(approval, key_log=A["key_states"][x["key_state"]], verifier_did=x["verifier_did"], owner_did=x["owner_did"],
                                       request_id=x["request_id"], payload_digest=x["payload_digest"], now=x["now"], origins=x["origins"])
        assert (r["ok"], r["error"]) == (False, "bad_webauthn")
    summary = []
    for _ in range(100_000):
        summary = [summary]
    with pytest.raises(openentity.InvalidInputError):
        openentity.payload_digest({"n": summary})
    good = bytes.fromhex("3006020101020101")
    assert _der_to_raw(good) is not None
    for n in range(len(good)):  # every truncation, and a length byte that points past the end
        assert _der_to_raw(good[:n]) is None
    for der in (bytes.fromhex("3006020401020304"), bytes.fromhex("30060201010204ff"), bytes.fromhex("3008020101020201ff")):
        assert _der_to_raw(der) is None
