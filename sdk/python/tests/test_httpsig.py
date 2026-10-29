import base64
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from openentity import HttpSigError, Identity, core, sign_request, verify_request
from openentity.httpsig import _base, _digest

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
    sig = Ed25519PrivateKey.from_private_bytes(key).sign(_base("POST", URL, list(comps), h.get("Content-Digest"), params))
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
