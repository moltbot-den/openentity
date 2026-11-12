# openentity (Python)

Python client for the Open Entity Identity Standard (spec id `OEIS-1`). Dependencies: `cryptography`, `pycryptodome`, `jsonschema`. Optional: `openentity[wallet]` (`eth-account`) to sign wallet proofs.

```
uvx openentity adopt --name "My Agent" --agree
```

Same commands, flags, `--json`, exit codes and `~/.openentity/<eid>/` file layout (`key` JWK at 0600, `entity.json`, `declaration.json`, `state.json`, `record.jsonl`, `current`) as the npm CLI, so either one can read what the other saved. The registry is `--registry URL`, then `$OPENENTITY_REGISTRY`, then the entity's own, then openentity.org. Pass `--eid` when there are several entities.

```
openentity adopt --name N --agree [--description --operator --operator-kind --contact --custody --model --provider --runtime --capabilities a,b --wallet KEY|0x.. --erc8004 eip155:1:0x..:7 --chain N --dry-run]
openentity whoami | self [--entries N] | stats
openentity anchor [--format text|openclaw|claude|agents] [--write --dir D]
openentity document set <field> <value> | edit | push
openentity record stance --type refusal --reason values --cost low --context TEXT [--conflict]
openentity record update --topic T --from A --to B
openentity record arc open|close --id SLUG --title TEXT
openentity record collab --with EID --role R --outcome O
openentity record continuity --event rotation --from A --to B
openentity record push | redact <seq>        (--no-push appends without pushing; --payload '<json>' replaces the flags)
openentity alias add domain|wallet|erc8004|platform <value> [--wallet KEY|0x.. --chain N --signature 0x..]
openentity card [--url U | --extension-only] [--eid EID]    openentity conformance <registry-url>
openentity rotate | migrate [--to keyfile --dry-run]    openentity recover --previous EID --via ALIAS, then --proof FILE
openentity verify <eid|url|file>    openentity resolve <did>
openentity present --audience A --nonce N [--no-attestations]    openentity verify-presentation FILE --audience A --nonce N
openentity log checkpoint | proof <index> | audit <n>
openentity export [--with-key --out FILE]    openentity import FILE [--key JWK --force]
openentity dispute --subject EID [--object SHA256] --reason inaccurate --statement "..."
openentity find --capability C [-q TEXT --alias-type T --level L1]
openentity withdraw --force
openentity pair OE-XXXX-XXXX [--openclaw --account URL --name N --framework F --dir D]
openentity owner message "<text>" | status <state> "<summary>" [--progress P] | inbox | ask --title T --summary S [--risk R] [--wait]
```

`pair` links this agent to its owner's OpenEntity app exactly as the npm CLI does (`uvx openentity pair OE-XXXX-XXXX`): it adopts first when this home holds no entity (that signs the Declaration, and it says so), prints the four match items, waits for the owner, and prints any product keys once with where each goes; `--openclaw` also writes the Identity Anchor into `IDENTITY.md` and `SOUL.md`, installs the skill into `~/.openclaw/skills/openentity` and registers the local MCP server in `~/.openclaw/openclaw.json`. `owner` then messages the owner, reports status, reads the inbox and asks for approvals.

With a wallet key (`--wallet <hex key or key file>`, or `$OPENENTITY_WALLET_KEY`) `adopt --wallet/--erc8004` and `alias add wallet|erc8004` sign the EIP-4361 proof here and the entity lands at L1 in one command. With only an address, `alias add wallet` prints the EIP-4361 message, you sign it with the wallet, and a second run with `--signature` submits it. Objects are validated against the spec schemas (packaged in the wheel) before signing. Keys saved by 0.4 under `~/.openentity/keys/` are migrated into the layout above on first use; the old file is left alone.

Exit codes match the npm CLI: 0 ok, 1 usage, 2 network, 3 verification failed, 4 registry rejected, 5 local state. `verify` checks signatures, the signer, the Declaration hash, the record chain (with Redaction signatures) and the log checkpoint and inclusion proof.

Library, each taking the 32-byte seed and a registry URL: `adopt(name, registry=...)`, `withdraw(seed, registry)`, `record(seed, [(kind, payload), ...], registry)` (chains `seq` and `prev` from the registry head, pushes in batches of 100), `dispute(seed, subject, reason, statement, object_sha256=None, registry=...)`, `find(registry, capability=..., q=..., alias_type=..., level=...)`, `present(seed, audience, nonce, registry=None)`. Primitives: `canonicalize`, `sign_object`, `verify_object`, `verify_presentation`, `did_key_from_public_key`, `mint_stamp`, `verify_inclusion`.

Shared core: `Identity.load_or_create()` (key in the OS keychain, else `~/.openentity/identity.key` at 0600; pass `.seed` to the calls above), `adopt(..., client="adk")` (an unsigned label: adk, crewai, goose, langchain, mastra, moltbotden, openai-agents, ui-tars, vercel-ai, cli, other), `trust(eid)` (a `TrustReport` from registry reads only, every signature verified locally, cached 5 minutes, `ok=False` on any failure), and `openentity.issuer` (`sign_attestation`, `sign_revocation`, `build_did_document`, `build_openentity_json`).

HTTP message signatures (RFC 9421, Web Bot Auth profile): `sign_request(method, url, body, private_key, did)` returns `Signature-Input`, `Signature` and, for a non-empty body, `Content-Digest` (`private_key` is an `Identity`, a `KeyPair` or a 32-byte seed; ed25519, `keyid` = the signer's did:key, covers `@method`, `@target-uri`, `content-digest`; `created`, `expires`, `nonce`). `verify_request(method, url, headers, body)` returns `{"did", "keyid", "created", "expires", "nonce"}` or raises `HttpSigError` with a `.code` (`missing_headers`, `unknown_alg`, `bad_keyid`, `digest_mismatch`, `created_in_future`, `created_too_old`, `expired`, `lifetime_too_long`, `missing_nonce`, `unexpected_signer`, `bad_signature`). Nonce replay tracking is yours. **Pin the signer with `expect_did`** (one DID or a list) whenever only known services may call: any other keyid, a `did:key` included, fails with `unexpected_signer` before any key is read. `allow_did_web` alone is not a pin: it only lets those `did:web` DIDs be resolved, and any `did:key` signer still verifies. A `did:web:<host>#<key>` keyid (a service such as the OpenEntity Account) verifies only when its DID is in `expect_did` or `allow_did_web`; the key must be an Ed25519 method listed under `authentication` in that DID's did.json, fetched with no redirects, cached 10 minutes and refetched at most every 30 seconds for an unknown keyid (`fetch(url)` replaces the fetch). `verify_response(status, headers, body, expect_did=...)` checks a response such a service signed, like the account service's `GET /v1/paused` answer: the signature covers `@status` and `content-digest`, has no nonce, lives at most `max_age` seconds (default 60), and its keyid must be a did:web method resolved the same way. It returns `{"did", "keyid", "created", "expires"}` or raises `HttpSigError` with the same codes. Shared vectors: `test-vectors/http-signature.json` (`did_web` and `responses` hold the did:web cases); did:web attestation issuers, as `did_web_resolver` resolves them: `test-vectors/did-web-1/`.

Written from the spec text alone, independent of the TypeScript SDK.

Owner key logs and approvals (OpenEntity Account, ADR 0007 and 0008), verify only: `verify_key_log(did, lines, first_seen_at, now=..., service_keys=..., origins=...)` checks an owner key log (JSON Lines, one RFC 8785 entry per line, with the `first_seen_at` you recorded for each entry) and returns `{"ok": True, "state": ...}` (`approvers` may approve now; `pending` are waiting `recover` and `replace_root` operations) or `{"ok": False, "error", "seq"}`. `service_keys` are the P-256 `assertionMethod` keys in `did:web:account.openentity.org`'s did.json (they sign `close`). `verify_approval(approval, key_log=state, verifier_did=..., owner_did=..., request_id=..., payload_digest=..., now=..., allow_root=False)` checks an approval/2.0 object and returns `{"ok": True, "kid", "counter"}` or `{"ok": False, "error"}`; pass your own DID, request id and recomputed `payload_digest(summary)` (integers within 2^53 only), never the client's. `approval_digest(fields)` is the digest a device or passkey signs; `pair_sas(code, agent_did)` gives the four pairing words. Formats, rules and error codes: `test-vectors/keylog-1/`, `test-vectors/approval-2.0/`, `test-vectors/pair-sas-1/`.

Pairing and the owner channel (OpenEntity Account, PLAN 8.1 to 8.4): `pair(code, identity=None, framework=..., sdk=..., sdk_version=..., host=None, account=..., on_match=None)` claims the `OE-XXXX-XXXX` code the owner's app shows with a signed Presentation (nonce `pair:` + the code), checks the service's match items against the ones it computes from the agent's own DID (it refuses on any difference), hands them to `on_match` (default: prints `Match: red fox, blue kite, gold star, gray owl`) and waits until the owner confirms; it returns `{"pairing_id", "owner_did", "permissions", "credentials", "match"}`, and `credentials` (bearer keys for tools that still need one) appear only there. `identity` defaults to `Identity.load_or_create()`, `host` to this machine's hostname. Then `Owner(identity)` gives `message(text)`, `status(state, summary, progress=None)`, `ask_approval(title, summary, risk, expires_in=600, wait=False)` (shown in the app as "Written by the agent"; no product accepts it), `inbox()`, `renew_credentials()` and `on_command(handler)`, which polls `GET /v1/agent/messages` every 15 seconds on a background thread (the standard library has no WebSocket client; the TypeScript SDK holds the socket). Every call is RFC 9421-signed by the agent's did:key. Refusals raise `OpenEntityError` with the service's `code` (`agent_paused`, `not_paired`, `code_used`, ...), `status` and `retry_after`.

## Stability

From 1.0 this package follows semantic versioning. The names in `openentity.__all__`, their argument order, return shapes and error codes (`RegistryError.code`, `HttpSigError.code`) are the public API. Breaking means removing or renaming a name, changing an argument or a return shape, or changing an error code; that needs a major version. New names, new optional arguments and new error codes ship in minor releases. Underscore-prefixed modules and names, and the `openentity.cli` module's internals, are private. `tests/test_api.py` pins the surface, and the TypeScript SDK keeps the same names in camelCase.
