"""Fixtures for doc fragments (scripts/doc-snippets.mjs): free names a block uses without defining them become builtins, and a block's
own assignment shadows them. Registry calls go to the local registry only."""
import builtins as b
import json
import os
import urllib.request

from openentity import KeyPair, adopt, build_declaration, build_presentation, canonical_hash, sign_object, sign_request

registry = os.environ["OPENENTITY_REGISTRY"]
me = KeyPair()
b.me, b.seed = me, me.seed
b.subject = me.did
b.bits = json.load(urllib.request.urlopen(f"{registry}/v1/spec"))["stamp_bits"]
b.signed_object = sign_object(build_declaration(me.did, "Doc Fixture"), me)
b.attestation_hash = canonical_hash(b.signed_object).hex()
if os.environ.get("OE_PRELUDE_ADOPT") == "1":  # for fragments that write after an adoption
    adopt("Doc Fixture", registry=registry, seed=me.seed)
    # The adopted Declaration is the object a dispute can name.
    b.attestation_hash = canonical_hash(json.load(urllib.request.urlopen(f"{registry}/v1/entities/{me.did}/declaration"))).hex()
b.issued_nonce = "issued-nonce-0001"
b.presentation = build_presentation(me, "https://platform.example", b.issued_nonce)
b.method, b.public_url, b.body = "POST", "https://gateway.example/v1/chat", b'{"hi":1}'
b.headers = sign_request(b.method, b.public_url, b.body, me, me.did)
b.reject = lambda status, code: print(status, code)
