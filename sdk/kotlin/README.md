# org.openentity:sdk (Kotlin)

Verify-only Kotlin SDK for the Open Entity Identity Standard ([OEIS-1](https://openentity.org/spec/1.0)), for the OpenEntity Android app and JVM products. A plain JVM library (JVM 17 bytecode, Android min SDK 28) with no runtime dependency beyond the Kotlin standard library: crypto comes from `java.security`. It never signs and never touches the network.

It gives the same accept or reject, error code and failing `seq` as `@openentity/sdk` and the Python `openentity` package on every shared vector in `test-vectors/`.

## What it verifies

- **Owner key logs** (keylog-1, ADR 0007): `verifyKeyLog(did, lines, firstSeenAt, now, serviceKeys, origins)` returns a `KeyLogState` (root, approvers, revoked, pending, closed) or throws `OpenEntityException(code, seq, message)` for the first failing entry. Rules: `test-vectors/keylog-1/README.md`.
- **approval/2.0** (ADR 0008): `verifyApproval(approval, keyLog, verifierDid, ownerDid, requestId, payloadDigest, now, ...)` returns `ApprovalOk(kid, counter)` or throws `OpenEntityException` with the vector code. `keyLog` is a `KeyLogState` or any `OwnerKeys` (did, root, approvers, closed). `allowRoot = true` also accepts the root passkey; only account-service flows turn it on. Rules: `test-vectors/approval-2.0/README.md`.
- **What the app signs**: `payloadDigest(summary)` recomputes the digest of the summary the owner is shown; `approvalPreimage(...)` and `approvalDigest(...)` give the bytes a device key signs and the passkey challenge.
- **Signed objects**: `verifyObject(obj)` and `verifyProof(obj, proof)` check eddsa-jcs-2022 proofs by did:key (Ed25519) signers and return the signer's DID.
- **Registry log**: `leafHash`, `verifyInclusion` (RFC 9162 section 2.1.3.2) and `verifyNote` (the C2SP signed note of a checkpoint).
- **JSON**: `JsonValue.parse` (strict: no duplicate keys, no lone surrogates, numbers as doubles the way JavaScript reads them) and `canonicalize` (RFC 8785).

A bad argument (an invalid service key, a summary with a fractional number) throws `IllegalArgumentException`; everything a verifier receives fails with `OpenEntityException`.

```kotlin
val now = System.currentTimeMillis() / 1000
val keys = verifyKeyLog(ownerDid, lines, firstSeenAt, now, serviceKeys, origins = listOf("https://account.openentity.org", appOrigin))
val ok = verifyApproval(JsonValue.parse(body), keys, verifierDid, ownerDid, requestId, payloadDigest(summary), now, origins = listOf("https://account.openentity.org", appOrigin), counter = storedCounter)
// store ok.counter for ok.kid
```

## Linking it from the Android app

The app builds it from source as a composite build. In `openentity-android/settings.gradle.kts`:

```kotlin
includeBuild("../openentity/sdk/kotlin")
```

and in the module that verifies:

```kotlin
dependencies { implementation("org.openentity:sdk") }
```

Gradle substitutes this build for `org.openentity:sdk` (group `org.openentity`, project `sdk`).

## Tests

```
cd sdk/kotlin
./gradlew test
```

JUnit 4 runs every `test-vectors/keylog-1` case, every `approval-2.0` case, digest and payload, the signed object vectors, the checkpoint and its inclusion proofs, plus JCS number and parser checks.

## Limits

- **Ed25519 needs JDK 15+ or Android 13 (API 33)+.** `verifyObject`, `verifyProof` and `verifyNote` use `Signature.getInstance("Ed25519")`; an older runtime throws `OpenEntityException("unsupported")`. Key logs and approvals use P-256 only and work from min SDK 28.
- **Numbers** are formatted from `Double.toString`, which is the shortest form on JDK 19+ and for the short decimals objects carry. An older Android runtime may print a longer form for a rare 16 or 17 digit value, and subnormals below 1e-320 differ: such an object fails to verify, it never verifies wrongly. Key log entries and payload summaries hold integers only.

## Not in this SDK

Signing of any kind, a registry client, EIP-712 proofs by did:pkh signers (no secp256k1 or keccak in the JDK: they fail as `unsupported`), did:web resolution, RFC 9421 HTTP message signatures (server-side), Merkle consistency proofs, proof-of-work stamps, schema validation and pair-sas/1.
