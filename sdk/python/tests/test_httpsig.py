import base64
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from openentity import HttpSigError, Identity, core, sign_request, verify_request, verify_response
from openentity.httpsig import _digest, http_sig_base

VEC = json.loads((Path(__file__).resolve().parents[3] / "test-vectors/http-signature.json").read_text())
SEED = bytes(range(1, 33))  # published throwaway seed, test-vectors/keys.json
KP = core.KeyPair(SEED)
URL, NOW, BODY = "https://gw.example.com/v1/x", 1_800_000_000, b'{"a":1}'
NONCE = "AAECAwQFBgcICQoLDA0ODw"


def req(**kw):
    return sign_request("POST", URL, BODY, SEED, KP.did, created=NOW, nonce=NONCE, **kw)


def check(h, code, **kw):
    with pytest.raises(HttpSigError) as e:
        verify_request(kw.pop("method", "POST"), kw.pop("url", URL), h, kw.pop("body", BODY), now=kw.pop("now", NOW), **kw)
    assert e.value.code == code


def forge(params, comps=("@method", "@target-uri", "content-digest"), body=BODY, key=SEED):
    """A correctly signed request with arbitrary Signature-Input parameters."""
    h = {"Content-Digest": _digest(body)} if body else {}
    sig = Ed25519PrivateKey.from_private_bytes(key).sign(http_sig_base("POST", URL, list(comps), h.get("Content-Digest"), params))
    return {**h, "Signature-Input": f"sig1={params}", "Signature": f"sig1=:{base64.b64encode(sig).decode()}:"}


def params(created=NOW, expires=NOW + 60, nonce=NONCE, keyid=KP.did, alg="ed25519", comps='"@method" "@target-uri" "content-digest"'):
    n = f';nonce="{nonce}"' if nonce else ""
    return f'({comps});created={created};expires={expires}{n};keyid="{keyid}";alg="{alg}"'


@pytest.mark.parametrize("case", VEC["valid"], ids=lambda c: c["name"])
def test_vectors_sign_and_verify(case):
    h = sign_request(case["method"], case["url"], case["body"].encode(), SEED, VEC["did"], created=case["created"],
                     expires_in=case["expires_in"], nonce=case["nonce"])
    assert h == case["headers"]  # byte-identical to the TS SDK
    out = verify_request(case["method"], case["url"], case["headers"], case["body"].encode(), now=VEC["now"])
    assert out == {"did": VEC["did"], "keyid": VEC["did"], "created": case["created"], "expires": case["created"] + 60, "nonce": case["nonce"]}


@pytest.mark.parametrize("case", VEC["invalid"], ids=lambda c: c["name"])
def test_vectors_reject(case):
    check(case["headers"], case["code"], method=case["method"], url=case["url"], body=case["body"].encode(), now=case.get("now", VEC["now"]))


def test_roundtrip_and_key_types():
    assert verify_request("post", URL, req(), BODY, now=NOW)["did"] == KP.did
    for key in (KP, Identity(SEED, "test")):
        assert sign_request("POST", URL, BODY, key, KP.did, created=NOW, nonce=NONCE) == req()
    h = sign_request("GET", URL, b"", SEED, KP.did)
    assert "Content-Digest" not in h and "content-digest" not in h["Signature-Input"]
    assert verify_request("GET", URL, h, b"")["did"] == KP.did


def test_header_lookup_is_case_insensitive():
    h = {k.lower(): v for k, v in req().items()}
    assert verify_request("POST", URL, h, BODY, now=NOW)


def test_missing_headers():
    check({}, "missing_headers")
    check({k: v for k, v in req().items() if k != "Signature"}, "missing_headers")
    check({**req(), "Signature": "garbage"}, "missing_headers")


def test_unknown_alg():
    check(forge(params(alg="rsa-pss-sha512")), "unknown_alg")


def test_bad_keyid():
    check(forge(params(keyid="did:web:example.com")), "bad_keyid")
    check(forge(params(keyid="did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme")), "bad_keyid")  # secp256k1


def test_digest_mismatch():
    check(req(), "digest_mismatch", body=b"other")
    check({k: v for k, v in req().items() if k != "Content-Digest"}, "digest_mismatch")
    check(forge(params(comps='"@method" "@target-uri"')), "digest_mismatch")  # body present, digest not covered


def test_created_in_future_and_skew():
    check(req(), "created_in_future", now=NOW - 6)
    assert verify_request("POST", URL, req(), BODY, now=NOW - 5)


def test_created_too_old():
    check(forge(params(created=NOW - 400, expires=NOW + 10)), "created_too_old")
    check(req(), "created_too_old", now=NOW + 301, max_age=300)


def test_expired():
    check(req(), "expired", now=NOW + 61)


def test_lifetime_too_long():
    check(forge(params(expires=NOW + 301)), "lifetime_too_long")
    check(sign_request("POST", URL, BODY, SEED, KP.did, created=NOW, nonce=NONCE, expires_in=200), "lifetime_too_long", max_age=100)


def test_missing_nonce():
    check(forge(params(nonce=None)), "missing_nonce")
    check(forge(params(nonce="short")), "missing_nonce")


def test_bad_signature():
    check(req(), "bad_signature", url=URL + "?y=1")
    check(req(), "bad_signature", method="GET")
    check(forge(params(), key=bytes(32)), "bad_signature")  # signed by another key


W = VEC["did_web"]


def _web(case, **kw):
    from openentity import httpsig
    httpsig._did_web_keys.clear()
    kw.setdefault("allow_did_web", [W["did"]])
    kw.setdefault("fetch", lambda url: W["document"] if url == W["url"] else None)
    return verify_request(case["method"], case["url"], case["headers"], case["body"].encode(), now=W["now"], **kw)


@pytest.mark.parametrize("case", W["valid"], ids=lambda c: c["name"])
def test_did_web_vectors_verify(case):
    assert _web(case) == {"did": W["did"], "keyid": case["keyid"], "created": case["created"], "expires": case["created"] + 60,
                          "nonce": case["nonce"]}


@pytest.mark.parametrize("case", W["invalid"], ids=lambda c: c["name"])
def test_did_web_vectors_reject(case):
    with pytest.raises(HttpSigError) as e:
        _web(case)
    assert e.value.code == case["code"]


def test_did_web_cache_refetch_and_allow_list():
    from openentity import httpsig
    mk, jk = W["valid"]
    calls = []
    no_jwk = {**W["document"], "verificationMethod": W["document"]["verificationMethod"][:1]}

    def fetch(doc):
        return lambda url: (calls.append(url), doc)[1]
    httpsig._did_web_keys.clear()
    run = lambda c, f, **kw: verify_request(c["method"], c["url"], c["headers"], c["body"].encode(), now=W["now"],
                                            allow_did_web=kw.get("allow", [W["did"]]), fetch=f)
    run(mk, fetch(no_jwk))
    run(mk, fetch(no_jwk))
    assert calls == [W["url"]]  # cached
    with pytest.raises(HttpSigError):  # an unknown key: no refetch within 30 seconds
        run(jk, fetch(W["document"]))
    at, keys = httpsig._did_web_keys[W["did"]]
    httpsig._did_web_keys[W["did"]] = (at - 31, keys)
    assert run(jk, fetch(W["document"]))["did"] == W["did"] and len(calls) == 2  # refetched: a rotation
    with pytest.raises(HttpSigError) as e:  # a DID it was not told to allow: no fetch at all
        run(mk, fetch(W["document"]), allow=[])
    assert e.value.code == "bad_keyid" and len(calls) == 2


R = VEC["responses"]


def _response(case, **kw):
    from openentity import httpsig
    httpsig._did_web_keys.clear()
    kw.setdefault("allow_did_web", [R["did"]])
    kw.setdefault("fetch", lambda url: R["document"] if url == R["url"] else None)
    return verify_response(case["status"], case["headers"], case["body"].encode(), now=case.get("now", R["now"]), **kw)


@pytest.mark.parametrize("case", R["valid"], ids=lambda c: c["name"])
def test_response_vectors_verify(case):
    assert _response(case) == {"did": R["did"], "keyid": case["keyid"], "created": case["created"], "expires": case["expires"]}


@pytest.mark.parametrize("case", R["invalid"], ids=lambda c: c["name"])
def test_response_vectors_reject(case):
    with pytest.raises(HttpSigError) as e:
        _response(case)
    assert e.value.code == case["code"]


def test_response_max_age_and_allow_list():
    case, calls = R["valid"][0], []
    with pytest.raises(HttpSigError) as e:
        _response(case, max_age=59)
    assert e.value.code == "lifetime_too_long"
    for allow in ([], R["did"]):  # a str is not an allow list
        with pytest.raises(HttpSigError) as e:
            _response(case, allow_did_web=allow, fetch=lambda url: (calls.append(url), R["document"])[1])
        assert e.value.code == "bad_keyid"
    assert calls == []  # a DID it was not told to allow is never fetched
