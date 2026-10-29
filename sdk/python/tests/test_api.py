"""The public API is pinned: a stray export, a rename or a drift from the TypeScript SDK fails here."""
import pathlib
import re

import pytest

import openentity
from openentity import core, issuer

TS_INDEX = pathlib.Path(__file__).parents[2] / "ts" / "src" / "index.ts"

# Editing this list is how a surface change is made on purpose.
SNAPSHOT = """
A2A_EXTENSION_URI CLIENTS DECLARATION_SHA256 DECLARATION_TEXT DECLARATION_VERSION DEFAULT_REGISTRY DISPUTE_REASONS HttpSigError
Identity InvalidInputError KeyPair OpenEntityError REGISTRY_ERROR_CODES RegistryError SPEC TrustReport VerificationError
a2a_extension adopt agent_card base58btc_decode base58btc_encode build_did_document build_openentity_json build_presentation
build_rotation canonical_hash canonicalize check_stamp check_timestamp clear_trust_cache default_resolver
did_key_from_public_key did_web_resolver dispute eip712_digest find generate_key_pair inclusion_proof key_pair_from_seed leaf_hash
log_leaf merkle_root mint_stamp node_hash normalize_eid now_seconds parse_json present public_key_from_did_key random_nonce
recover_eip712 record record_entry_hash rotate sha256 sha256_hex sign_attestation sign_object sign_proof sign_request
sign_revocation successor_document trust validate verification_method_id verify_inclusion verify_note verify_object
verify_presentation verify_request withdraw
""".split()

# In the TypeScript SDK only (camelCase there). Shrinks as the Python SDK gains them; never grows without a reason.
TS_ONLY = {"build_declaration", "build_document", "checkpoint_body", "consistency_proof", "hash_data", "http_sig_base",
           "key_pair_from_jwk", "note_vkey", "sign_note", "verify_consistency", "verify_proof"}
# In the Python SDK only.
PY_ONLY = {"Identity", "InvalidInputError", "KeyPair", "REGISTRY_ERROR_CODES", "RegistryError", "TrustReport", "VerificationError",
           "canonical_hash", "default_resolver"}


def test_the_public_names_are_pinned():
    assert sorted(openentity.__all__) == sorted(SNAPSHOT)
    for name in openentity.__all__:
        assert hasattr(openentity, name), name


def ts_names():
    names = set()
    for block in re.findall(r"export \{([^}]*)\}", TS_INDEX.read_text()):
        names |= {n.strip() for n in block.split(",") if n.strip() and not n.strip().startswith("type ")}
    snake = lambda n: n if n[0].isupper() or "_" in n else re.sub(r"(?<=[a-z0-9])([A-Z])", lambda m: "_" + m.group(1).lower(), n).lower()
    return {snake(n).replace("open_entity", "openentity") for n in names}


def test_the_two_sdks_match_up_to_naming():
    ts, py = ts_names(), set(openentity.__all__)
    assert ts - py == TS_ONLY
    assert py - ts == PY_ONLY


def test_errors_form_one_hierarchy():
    for cls in (openentity.RegistryError, openentity.HttpSigError, openentity.InvalidInputError, openentity.VerificationError):
        assert issubclass(cls, openentity.OpenEntityError)
    assert issubclass(openentity.InvalidInputError, ValueError) and issubclass(openentity.VerificationError, ValueError)
    e = openentity.RegistryError(409, {"error": "entity_exists", "message": "x"})
    assert (e.code, e.status) == ("entity_exists", 409) and e.code in openentity.REGISTRY_ERROR_CODES
    assert openentity.RegistryError(502, "<html>").code == "registry_error"
    assert openentity.HttpSigError("bad_signature").code == "bad_signature"
    with pytest.raises(openentity.OpenEntityError) as raised:
        core.base58btc_decode("0OIl")
    assert raised.value.code == "invalid_input"


def test_the_0_5_names_still_work():
    assert core.b58encode is core.base58btc_encode and core.now is core.now_seconds and core.nonce is core.random_nonce
    assert core.did_key is core.did_key_from_public_key and core.public_from_did_key is core.public_key_from_did_key
    assert core.verification_method is core.verification_method_id
    assert issuer.attestation is issuer.sign_attestation and issuer.revocation is issuer.sign_revocation
    assert issuer.did_document is issuer.build_did_document and issuer.openentity_json is issuer.build_openentity_json
    assert openentity.RegistryError is openentity.client.RegistryError and openentity.HttpSigError is openentity.httpsig.HttpSigError


def test_the_error_codes_match_the_registry_and_the_ts_sdk():
    registry = set(re.findall(r'fail\(\d+,\s*"([a-z_0-9]+)"', "".join(p.read_text() for p in (TS_INDEX.parents[3] / "registry" / "src").glob("*.ts"))))
    assert registry <= openentity.REGISTRY_ERROR_CODES
    ts = set(re.findall(r'"([a-z_0-9]+)"', (TS_INDEX.parent / "errors.ts").read_text().split("export type LocalErrorCode")[0]))
    assert ts == openentity.REGISTRY_ERROR_CODES
