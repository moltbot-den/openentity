# @openentity/sdk

Reference TypeScript SDK for the Open Entity Identity Standard ([OEIS-1](https://openentity.org/spec/1.0)): did:key Ed25519 keys, JCS canonicalization, eddsa-jcs-2022 signing and verification, EIP-712 verification, proof-of-work stamps and RFC 6962 Merkle proofs.

```sh
npm install @openentity/sdk
```

Most agents want the CLI instead: `npx openentity@latest adopt`. Start at https://openentity.org/llms.txt.

Shared core: `adopt(kp, {name, client})`, `trust(eid)` (a `TrustReport` from registry reads only, every signature verified locally, cached 5 minutes, `ok: false` on any failure), the issuer helpers `signAttestation`, `signRevocation`, `buildDidDocument`, `buildOpenEntityJson`, and in Node `import { Identity } from "@openentity/sdk/node"` for `Identity.loadOrCreate()` (OS keychain, else `~/.openentity/identity.key` at 0600).

HTTP message signatures (RFC 9421, Web Bot Auth profile): `signRequest({method, url, body, privateKey, did})` returns `Signature-Input`, `Signature` and, for a non-empty body, `Content-Digest` (ed25519, `keyid` = the signer's did:key, covers `@method`, `@target-uri`, `content-digest`; `created`, `expires`, `nonce`). `verifyRequest({method, url, headers, body})` returns `{did, keyid, created, expires, nonce}` or throws `HttpSigError` with a `.code` (`missing_headers`, `unknown_alg`, `bad_keyid`, `digest_mismatch`, `created_in_future`, `created_too_old`, `expired`, `lifetime_too_long`, `missing_nonce`, `bad_signature`). Nonce replay tracking is yours. Shared vectors: `test-vectors/http-signature.json`.

Owner key logs and approvals (OpenEntity Account, ADR 0007 and 0008), verify only: `verifyKeyLog(did, lines, firstSeenAt, {now, serviceKeys, origins, rpId})` checks an owner key log (JSON Lines, one RFC 8785 entry per line, with the `first_seen_at` you recorded for each entry) and returns `{ok: true, state}` (`approvers` are the keys that may approve now; `pending` are waiting `recover` and `replace_root` operations) or `{ok: false, error, seq}`. `verifyApproval(approval, {keyLog: state, verifierDid, ownerDid, requestId, payloadDigest, now, decisions, origins, counter})` checks an approval/2.0 object against that state and returns `{ok: true, kid, counter}` or `{ok: false, error}`; pass your own DID, request id and recomputed `payloadDigest(summary)` (SHA-256 of the RFC 8785 summary; integers within 2^53 only), never the client's. `approvalDigest(fields)` is the 32-byte digest a device or passkey signs. `pairSas(code, agentDid)` gives the four pairing words an agent prints. Formats, rules and error codes: `test-vectors/keylog-1/`, `test-vectors/approval-2.0/`, `test-vectors/pair-sas-1/`.

MIT licensed. Source: https://github.com/moltbot-den/openentity

## Stability

From 1.0 this package follows semantic versioning. The names exported from `@openentity/sdk` and `@openentity/sdk/node`, their argument order, return shapes and error codes (`OpenEntityError.code`, `HttpSigError.code`) are the public API. Breaking means removing or renaming an export, changing an argument or a return shape, or changing an error code; that needs a major version. New exports, new optional arguments and new error codes ship in minor releases. Anything not exported from the package entry points is private. `test/api.test.ts` pins the surface, and the Python SDK keeps the same names in snake_case.
