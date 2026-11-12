# org.openentity:sdk (Kotlin)

Verify-only Kotlin SDK for the Open Entity Identity Standard ([OEIS-1](https://openentity.org/spec/1.0)), for the OpenEntity Android app and JVM products. A plain JVM library (JVM 17 bytecode, Android min SDK 28) with no runtime dependency beyond the Kotlin standard library: crypto comes from `java.security`. It never signs, and only a `DidWebResolver` you pass touches the network.

It gives the same accept or reject, error code and failing `seq` as `@openentity/sdk` and the Python `openentity` package on every shared vector in `test-vectors/`.

## What it verifies

- **Owner key logs** (keylog-1, ADR 0007): `verifyKeyLog(did, lines, firstSeenAt, now, serviceKeys, origins)` returns a `KeyLogState` (root, approvers, revoked, pending, closed) or throws `OpenEntityException(code, seq, message)` for the first failing entry. Rules: `test-vectors/keylog-1/README.md`.
- **approval/2.0** (ADR 0008): `verifyApproval(approval, keyLog, verifierDid, ownerDid, requestId, payloadDigest, now, ...)` returns `ApprovalOk(kid, counter)` or throws `OpenEntityException` with the vector code. `keyLog` is a `KeyLogState` or any `OwnerKeys` (did, root, approvers, closed). `allowRoot = true` also accepts the root passkey; only account-service flows turn it on. Rules: `test-vectors/approval-2.0/README.md`.
- **What the app signs**: `payloadDigest(summary)` recomputes the digest of the summary the owner is shown; `approvalPreimage(...)` and `approvalDigest(...)` give the bytes a device key signs and the passkey challenge.
- **Signed objects**: `verifyObject(obj, resolver)` and `verifyProof(obj, proof, resolver)` check eddsa-jcs-2022 proofs and return the signer's DID. The default resolver, `Resolver.DID_KEY`, handles did:key signers offline; pass a `DidWebResolver` for did:web issuers (below). Checking that the signer is the object's `issuer` is yours.
- **Registry log**: `leafHash`, `verifyInclusion` (RFC 9162 section 2.1.3.2) and `verifyNote` (the C2SP signed note of a checkpoint).
- **JSON**: `JsonValue.parse` (strict: no duplicate keys, no lone surrogates, numbers as doubles the way JavaScript reads them) and `canonicalize` (RFC 8785).

A bad argument (an invalid service key, a summary with a fractional number) throws `IllegalArgumentException`; everything a verifier receives fails with `OpenEntityException`.

```kotlin
val now = System.currentTimeMillis() / 1000
val keys = verifyKeyLog(ownerDid, lines, firstSeenAt, now, serviceKeys, origins = listOf("https://account.openentity.org", appOrigin))
val ok = verifyApproval(JsonValue.parse(body), keys, verifierDid, ownerDid, requestId, payloadDigest(summary), now, origins = listOf("https://account.openentity.org", appOrigin), counter = storedCounter)
// store ok.counter for ok.kid
```

## did:web issuers

Most registry attestations come from did:web issuers such as `did:web:moltbotden.com`. `DidWebResolver` resolves them the way `test-vectors/did-web-1/README.md` pins it:

- It fetches `https://<host>/.well-known/did.json`, or `https://<host>/<path>/did.json` for a DID with a path (each part percent-decoded, a port written as `%3A`), and requires the document's `id` to equal the DID.
- Keys are the Ed25519 methods of the document: a `publicKeyMultibase` Ed25519 multikey, or a `publicKeyJwk` with `kty` OKP, `crv` Ed25519 and a strict base64url `x`. Method ids may be absolute or `#relative`. Any of those keys verifies the proof, as in the TS and Python SDKs.
- Keys are cached ten minutes per DID. A proof that names a method the cached keys lack refetches, at most once every 30 seconds per DID, so a rotated key is picked up without bad proofs turning into fetches. A failed fetch is retried after 30 seconds. Keep one resolver for the app's lifetime: the cache lives in it.
- The default fetch is HTTPS only through `HttpURLConnection`: 5-second connect and read timeouts, 10 seconds in all, no redirects, at most 256 KiB. It blocks, so verify off the main thread. Inject your own with `DidWebResolver(fetch = { url -> ... })`, which returns the parsed JSON or throws.
- A document that cannot be fetched or names another DID fails with `OpenEntityException("unresolved")`; a document with no Ed25519 key that verifies fails with `bad_signature`. did:key signers still verify offline through the same resolver.
- Resolve only issuers you accept: verifying an object makes the resolver fetch from the host its signer names.

```kotlin
val resolver = DidWebResolver() // one per app
val signer = verifyObject(attestation, resolver) // throws OpenEntityException
val issuer = ((attestation as JsonValue.Obj).fields["issuer"] as? JsonValue.Str)?.value
val trusted = signer == issuer && signer in acceptedIssuers
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

JUnit 4 runs every `test-vectors/keylog-1` case, every `approval-2.0` case, digest and payload, every `did-web-1` case through an injected fetch (no network), the signed object vectors, the checkpoint and its inclusion proofs, plus checks of the did:web cache, refetch and 30-second floor, JCS numbers and the parser.

## Limits

- **Ed25519 needs JDK 15+ or Android 13 (API 33)+.** `verifyObject`, `verifyProof` and `verifyNote` use `Signature.getInstance("Ed25519")`; an older runtime throws `OpenEntityException("unsupported")`. Key logs and approvals use P-256 only and work from min SDK 28.
- **Numbers** are formatted from `Double.toString`, which is the shortest form on JDK 19+ and for the short decimals objects carry. An older Android runtime may print a longer form for a rare 16 or 17 digit value, and subnormals below 1e-320 differ: such an object fails to verify, it never verifies wrongly. Key log entries and payload summaries hold integers only.

## Not in this SDK

Signing of any kind, a registry client, EIP-712 proofs by did:pkh signers (no secp256k1 or keccak in the JDK: they fail as `unsupported`), RFC 9421 HTTP message signatures (server-side), Merkle consistency proofs, proof-of-work stamps, schema validation and pair-sas/1.
