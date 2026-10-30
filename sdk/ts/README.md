# @openentity/sdk

Reference TypeScript SDK for the Open Entity Identity Standard ([OEIS-1](https://openentity.org/spec/1.0)): did:key Ed25519 keys, JCS canonicalization, eddsa-jcs-2022 signing and verification, EIP-712 verification, proof-of-work stamps and RFC 6962 Merkle proofs.

```sh
npm install @openentity/sdk
```

Most agents want the CLI instead: `npx openentity@latest adopt`. Start at https://openentity.org/llms.txt.

Shared core: `adopt(kp, {name, client})`, `trust(eid)` (a `TrustReport` from registry reads only, every signature verified locally, cached 5 minutes, `ok: false` on any failure), the issuer helpers `signAttestation`, `signRevocation`, `buildDidDocument`, `buildOpenEntityJson`, and in Node `import { Identity } from "@openentity/sdk/node"` for `Identity.loadOrCreate()` (OS keychain, else `~/.openentity/identity.key` at 0600).

HTTP message signatures (RFC 9421, Web Bot Auth profile): `signRequest({method, url, body, privateKey, did})` returns `Signature-Input`, `Signature` and, for a non-empty body, `Content-Digest` (ed25519, `keyid` = the signer's did:key, covers `@method`, `@target-uri`, `content-digest`; `created`, `expires`, `nonce`). `verifyRequest({method, url, headers, body})` returns `{did, keyid, created, expires, nonce}` or throws `HttpSigError` with a `.code` (`missing_headers`, `unknown_alg`, `bad_keyid`, `digest_mismatch`, `created_in_future`, `created_too_old`, `expired`, `lifetime_too_long`, `missing_nonce`, `bad_signature`). Nonce replay tracking is yours. Shared vectors: `test-vectors/http-signature.json`.

MIT licensed. Source: https://github.com/moltbot-den/openentity

## Stability

From 1.0 this package follows semantic versioning. The names exported from `@openentity/sdk` and `@openentity/sdk/node`, their argument order, return shapes and error codes (`OpenEntityError.code`, `HttpSigError.code`) are the public API. Breaking means removing or renaming an export, changing an argument or a return shape, or changing an error code; that needs a major version. New exports, new optional arguments and new error codes ship in minor releases. Anything not exported from the package entry points is private. `test/api.test.ts` pins the surface, and the Python SDK keeps the same names in snake_case.
