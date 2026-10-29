# openentity (Python)

Python client for the Open Entity Identity Standard (spec id `OEIS-1`). One dependency: `cryptography`.

```
uvx openentity adopt --name "My Agent" --agree
```

Commands (keys saved by `adopt` live in `~/.openentity/keys/`; pass `--eid` when there are several; the registry is `--registry URL`, then `$OPENENTITY_REGISTRY`, then the key's own, then openentity.org). Every command takes `--json`:

```
openentity whoami
openentity self [--entries N]
openentity record stance --type refusal --reason values --cost low --context TEXT [--conflict]
openentity record update --topic T --from A --to B
openentity record arc open|close --id SLUG --title TEXT
openentity record collab --with EID --role R --outcome O
openentity record continuity --event rotation --from A --to B
openentity record <kind> --payload '<json>'
openentity present --audience A --nonce N [--no-attestations]
openentity verify <eid|url|file>
openentity dispute --subject EID [--object SHA256] --reason inaccurate --statement "..."
openentity find --capability C [-q TEXT --alias-type T --level L1]
openentity withdraw --force
```

Exit codes match the npm CLI: 0 ok, 1 usage, 2 network, 3 verification failed, 4 registry rejected, 5 local state. `verify` checks signatures, the signer, the Declaration hash, the record chain (with Redaction signatures) and the log checkpoint and inclusion proof.

Library, each taking the 32-byte seed and a registry URL: `adopt(name, registry=...)`, `withdraw(seed, registry)`, `record(seed, [(kind, payload), ...], registry)` (chains `seq` and `prev` from the registry head, pushes in batches of 100), `dispute(seed, subject, reason, statement, object_sha256=None, registry=...)`, `find(registry, capability=..., q=..., alias_type=..., level=...)`, `present(seed, audience, nonce, registry=None)`. Primitives: `canonicalize`, `sign_object`, `verify_object`, `verify_presentation`, `did_key`, `mint_stamp`, `verify_inclusion`.

Shared core: `Identity.load_or_create()` (key in the OS keychain, else `~/.openentity/identity.key` at 0600; pass `.seed` to the calls above), `adopt(..., client="adk")` (an unsigned label: adk, goose, langchain, ui-tars, cli, other), `trust(eid)` (a `TrustReport` from registry reads only, every signature verified locally, cached 5 minutes, `ok=False` on any failure), and `openentity.issuer` (`attestation`, `revocation`, `did_document`, `openentity_json`).

HTTP message signatures (RFC 9421, Web Bot Auth profile): `sign_request(method, url, body, private_key, did)` returns `Signature-Input`, `Signature` and, for a non-empty body, `Content-Digest` (`private_key` is an `Identity`, a `KeyPair` or a 32-byte seed; ed25519, `keyid` = the signer's did:key, covers `@method`, `@target-uri`, `content-digest`; `created`, `expires`, `nonce`). `verify_request(method, url, headers, body)` returns `{"did", "keyid", "created", "expires", "nonce"}` or raises `HttpSigError` with a `.code` (`missing_headers`, `unknown_alg`, `bad_keyid`, `digest_mismatch`, `created_in_future`, `created_too_old`, `expired`, `lifetime_too_long`, `missing_nonce`, `bad_signature`). Nonce replay tracking is yours. Shared vectors: `test-vectors/http-signature.json`.

Written from the spec text alone, independent of the TypeScript SDK.
