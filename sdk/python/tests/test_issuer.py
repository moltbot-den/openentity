"""Issuer helpers: a did:web issuer signs, anyone verifies against the published did.json."""
from datetime import datetime, timedelta, timezone

import pytest

from openentity import core, issuer

KP = core.KeyPair(bytes(range(1, 33)))  # published throwaway seed from test-vectors
SUBJECT = core.KeyPair(bytes(range(33, 65))).did
DID = "did:web:issuer.example"
NOW = datetime(2026, 10, 27, 12, 0, tzinfo=timezone.utc)


def resolver(did):
    assert did == DID
    return {"ed25519": [core.public_from_did_key("did:key:" + issuer.did_document(DID, KP.public)["verificationMethod"][0]["publicKeyMultibase"])]}


def test_attestation_verifies_against_did_json_and_expires_on_ttl():
    a = issuer.attestation(KP, SUBJECT, "trust_tier", {"tier": 2, "platform": "x"}, issuer=DID, ttl=timedelta(days=30), now=NOW)
    assert (a["issuer"], a["created"], a["expires"]) == (DID, "2026-10-27T12:00:00Z", "2026-11-26T12:00:00Z")
    assert a["proof"]["verificationMethod"] == f"{DID}#key-1"
    assert core.verify_object(a, resolver) == (True, DID)
    assert not core.verify_object({**a, "claim": {"tier": 4, "platform": "x"}}, resolver)[0]


def test_did_key_issuer_needs_no_key_id_and_ttl_is_capped():
    a = issuer.attestation(KP, SUBJECT, "stage", {"stage": "agent", "profile": "p"}, evidence={"kind": "t"}, confidence=0.5, now=NOW)
    assert a["issuer"] == KP.did and core.verify_object(a) == (True, KP.did)
    for ttl in (timedelta(0), timedelta(days=366)):
        with pytest.raises(ValueError):
            issuer.attestation(KP, SUBJECT, "stage", {}, ttl=ttl)


def test_revocation_names_the_attestation_hash():
    a = issuer.attestation(KP, SUBJECT, "custom:x:y", {}, issuer=DID, now=NOW)
    r = issuer.revocation(KP, a, issuer=DID, reason="superseded", now=NOW)
    assert r["attestation_sha256"] == core.canonical_hash(a).hex() == issuer.revocation(KP, r["attestation_sha256"], issuer=DID, now=NOW)["attestation_sha256"]
    assert core.verify_object(r, resolver) == (True, DID)


def test_well_known_files_agree_on_the_key():
    d, o = issuer.did_document(DID, KP.public), issuer.openentity_json(DID, KP.public, "Issuer", "An issuer.", extensions={"openentity:observer": {}})
    assert d["id"] == o["eid"] == DID
    assert d["verificationMethod"][0]["publicKeyMultibase"] == o["keys"][0]["publicKeyMultibase"]
    assert d["assertionMethod"] == [o["keys"][0]["id"]]


@pytest.mark.parametrize("claim_type,claim", [
    ("stage", {"stage": "sentient", "profile": "p"}),
    ("layer_scores", {"cognition": 1.2, "presence": 0, "identity_core": 0, "mission": 0, "profile": "p"}),
    ("trust_tier", {"tier": 5, "platform": "x"}),
    ("trust_tier", {"platform": "x"}),
])
def test_refuses_to_sign_a_malformed_core_claim(claim_type, claim):
    with pytest.raises(Exception, match="Attestation"):
        issuer.sign_attestation(KP, SUBJECT, claim_type, claim, now=NOW)


def test_signs_a_valid_core_claim_and_any_custom_claim():
    issuer.sign_attestation(KP, SUBJECT, "trust_tier", {"tier": 4, "platform": "x"}, now=NOW)
    issuer.sign_attestation(KP, SUBJECT, "custom:x:y", {"anything": 1}, now=NOW)
