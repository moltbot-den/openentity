# OpenEntityKit

Verify-only Swift SDK for Open Entity: owner key logs (keylog-1), approval/2.0, and OEIS-1 signed objects, log inclusion proofs and checkpoints. Foundation and CryptoKit only; no networking, no signing, no registry client.

Products and the OpenEntity iOS app use it to decide whether an owner approved something, so on every vector in `test-vectors/` it gives exactly the results of `@openentity/sdk` (`sdk/ts`) and the Python `openentity` package: the same accept or reject, error code, failing `seq` and state.

## What it verifies

- `verifyKeyLog(did:lines:firstSeenAt:now:serviceKeys:origins:rpId:)`: an owner key log ([keylog-1](../../test-vectors/keylog-1/README.md)) against the owner DID. Returns `KeyLogState` (root, approvers, revoked, pending, closed) as of `now`, or throws `OpenEntityError` with the failing rule's `code` and `seq`. A bad service key throws `invalid_input` with no `seq`.
- `verifyApproval(_:keyLog:verifierDid:ownerDid:requestId:payloadDigest:now:decisions:origins:rpId:counter:allowRoot:)`: an approval/2.0 object ([approval-2.0](../../test-vectors/approval-2.0/README.md)) in the p256 or WebAuthn form. Returns the signing kid and the WebAuthn counter to store.
- `approvalPreimage(...)` and `approvalDigest(...)`: what the app signs. CryptoKit's `P256.Signing.PrivateKey.signature(for:)` over the UTF-8 preimage gives the p256 form (it hashes with SHA-256); the WebAuthn challenge is base64url of the digest.
- `payloadDigest(_:)`: SHA-256 of the RFC 8785 form of the summary the owner sees. The app recomputes it before signing.
- `verifyObject(_:)` and `verifyProof(_:_:)`: eddsa-jcs-2022 proofs by did:key. `leafHash(_:)`, `verifyInclusion(index:size:leaf:proof:root:)` (RFC 9162) and `verifyNote(note:origin:publicKey:)` (the C2SP checkpoint).
- `JSONValue.parse(_:)` and `canonicalize(_:)`: JSON without duplicate keys or lone surrogates, numbers as JavaScript doubles, and its RFC 8785 form. Strings compare byte for byte everywhere, never with Swift's Unicode-equivalence `==`.

## Linking

Nothing is published. The iOS app pins a checkout of this repository beside it and adds the package by path, product `OpenEntityKit` (iOS 17, macOS 14):

```swift
.package(path: "../openentity/sdk/swift")
```

## Tests

```sh
cd sdk/swift && swift test
```

The tests read `test-vectors/` at the repository root: every keylog-1 case, the approval-2.0 digests, payloads, cases and key logs, and the OEIS-1 signed objects, continuity link, rotation, log leaves and checkpoint.

## Not covered

- EIP-712 proofs and did:pkh signers: CryptoKit has no secp256k1 or keccak, so they throw `unsupported`. Signers other than did:key need a resolver and throw `unsupported` too.
- RFC 9421 HTTP message signatures (`test-vectors/http-signature.json`), a server-side profile.
- pair-sas-1, signing and the registry client.
