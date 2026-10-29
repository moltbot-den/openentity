"""The functions that were TypeScript-only before 0.6.1, checked against the shared test vectors and the TS behaviour."""
import base64
import json
from pathlib import Path

import pytest

import openentity as oe

VEC = Path(__file__).resolve().parents[3] / "test-vectors"
load = lambda n: json.loads((VEC / n).read_text())
KEYS = load("keys.json")
ENTITY = oe.key_pair_from_seed(bytes.fromhex(KEYS["entity"]["seed"]))
LOG = oe.key_pair_from_seed(bytes.fromhex(KEYS["log"]["seed"]))


def test_checkpoint_note_and_vkey_match_the_vector():
    cp = load("checkpoint.json")
    body = oe.checkpoint_body(cp["origin"], cp["tree_size"], bytes.fromhex(cp["root_hash"]))
    assert body == cp["body"]
    assert oe.sign_note(body, cp["origin"], LOG) == cp["note"]  # Ed25519 is deterministic
    assert oe.note_vkey(KEYS["log"]["key_name"], LOG.public) == KEYS["log"]["vkey"]
    assert oe.verify_note(cp["note"], cp["origin"], LOG.public)


def test_sign_note_refuses_bad_input():
    for body, name in (("no newline", "k"), ("b\n", ""), ("b\n", "a b"), ("b\n", "a+b")):
        with pytest.raises(oe.InvalidInputError):
            oe.sign_note(body, name, LOG)


def test_consistency_proofs_for_every_size_up_to_40():
    leaves = [oe.leaf_hash(bytes([i])) for i in range(40)]
    flip = lambda b: bytes([b[0] ^ 1]) + b[1:]
    for n in range(1, 41):
        root = oe.merkle_root(leaves[:n])
        for m in range(1, n + 1):
            p, root_m = oe.consistency_proof(m, leaves[:n]), oe.merkle_root(leaves[:m])
            assert oe.verify_consistency(m, n, root_m, root, p)
            assert not oe.verify_consistency(m, n, flip(root_m), root, p)
            if m < n:
                assert not oe.verify_consistency(m, n, root_m, flip(root), p)
            if p:
                assert not oe.verify_consistency(m, n, root_m, root, [*p[:-1], flip(p[-1])])
    for m in (0, 41):
        with pytest.raises(oe.InvalidInputError):
            oe.consistency_proof(m, leaves)


def test_the_vector_log_is_consistent_with_its_prefixes():
    leaves = [oe.leaf_hash(oe.canonicalize(load(f"log-leaf-{i}.json")["object"]).encode()) for i in range(6)]
    assert oe.merkle_root(leaves).hex() == load("checkpoint.json")["root_hash"]
    assert oe.verify_consistency(4, 6, oe.merkle_root(leaves[:4]), oe.merkle_root(leaves), oe.consistency_proof(4, leaves))


def test_hash_data_and_verify_proof_on_the_entity_document_vector():
    doc = load("entity-document.json")["object"]
    ok, signer = oe.verify_proof(doc, doc["proof"])
    assert ok and signer == doc["eid"]
    cfg = {k: v for k, v in doc["proof"].items() if k != "proofValue"}
    assert oe.hash_data(doc, cfg) == oe.canonical_hash(cfg) + oe.canonical_hash({k: v for k, v in doc.items() if k != "proof"})
    assert oe.verify_proof({**doc, "name": "x"}, doc["proof"])[0] is False
    assert oe.verify_proof(doc, {**doc["proof"], "proofPurpose": "authentication"})[0] is False


def test_build_declaration_matches_the_vector_and_signs():
    d = load("declaration.json")["object"]
    built = oe.build_declaration(d["eid"], d["name"], d["created"])
    assert {k: v for k, v in built.items() if k != "nonce"} == {k: v for k, v in d.items() if k not in ("nonce", "proof")}
    assert oe.verify_object(oe.sign_object(built, ENTITY))[0]


def test_build_document_defaults_and_extra():
    doc = oe.build_document(ENTITY, "N", "D", created="2026-10-24T19:00:00Z", extra={"aliases": []})
    assert doc["eid"] == ENTITY.did and doc["seq"] == 1 and doc["updated"] == doc["created"] and doc["aliases"] == []
    assert doc["keys"][0]["publicKeyMultibase"] == ENTITY.did.removeprefix("did:key:")
    assert doc["substrate"]["declared_at"] == doc["created"] and doc["layers"]["mission"]["arcs"] == []
    assert oe.validate("EntityDocument", oe.sign_object(doc, ENTITY)) == []


def test_key_pair_from_jwk():
    b = lambda x: base64.urlsafe_b64encode(x).rstrip(b"=").decode()
    jwk = {"kty": "OKP", "crv": "Ed25519", "d": b(ENTITY.seed), "x": b(ENTITY.public)}
    assert oe.key_pair_from_jwk(jwk).did == ENTITY.did
    for bad in ({**jwk, "x": b(LOG.public)}, {**jwk, "crv": "X25519"}, {"kty": "OKP"}):
        with pytest.raises(oe.InvalidInputError):
            oe.key_pair_from_jwk(bad)


def test_http_sig_base_is_the_rfc_9421_signature_base():
    base = oe.http_sig_base("post", "https://x/y", ["@method", "@target-uri", "content-digest"], "sha-256=:AA==:", "(p)")
    assert base == b'"@method": POST\n"@target-uri": https://x/y\n"content-digest": sha-256=:AA==:\n"@signature-params": (p)'
