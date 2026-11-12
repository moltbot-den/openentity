# did:web issuer vectors (did-web-1)

> **WARNING: PUBLISHED THROWAWAY KEYS.** Every key here comes from a seed printed in `keys.json`. Anyone can sign as `did:web:issuer.example` with them. Never use these seeds or keys for anything real.

Most attestations in the registry come from did:web issuers (`did:web:moltbotden.com` and others). A verifier resolves the issuer's DID document over HTTPS and checks the attestation's proof against its keys. These vectors pin that resolution: the URL to fetch, the keys a document yields, and which proofs verify. Resolvers: `didWebResolver` in `@openentity/sdk` and `did_web_resolver` in the Python `openentity` package; the Swift (`sdk/swift`) and Kotlin (`sdk/kotlin`) SDKs implement the same behavior behind an injectable fetch.

Regenerate with `pnpm --filter @openentity/sdk gen:vectors` (`sdk/ts/scripts/gen-vectors.ts`). A test in `sdk/ts` regenerates them in memory and fails if a committed file differs.

## Keys

`keys.json` holds three Ed25519 seeds: bytes 0x61 to 0x80 (`multikey`, method `key-1`), 0x81 to 0xa0 (`jsonwebkey`, method `key-2`) and 0xa1 to 0xc0 (`unlisted`, named by a proof but listed in no document). The attestation subject is the entity EID of `../keys.json`.

## Resolving a did:web DID

1. **URL.** Drop `did:web:`, split the rest on `:` and percent-decode each part. The first part is the host, with a port written as `%3A`. With no other parts the document is at `https://<host>/.well-known/did.json`; otherwise at `https://<host>/<part>/.../<part>/did.json`. So `did:web:issuer.example` is `https://issuer.example/.well-known/did.json` and `did:web:issuer.example%3A8443:teams:red` is `https://issuer.example:8443/teams/red/did.json`. Fetch over HTTPS only and follow no redirects.
2. **Document.** It must be a JSON object whose `id` equals the DID exactly. Anything else fails resolution.
3. **Keys.** A `verificationMethod` entry yields an Ed25519 public key when it has an `id` (absolute, or relative to the DID: `#key-2` means `did:web:issuer.example#key-2`) and either a `publicKeyMultibase` that is `z` plus base58btc of the multicodec prefix `0xed 0x01` followed by 32 bytes, or a `publicKeyJwk` with `kty` `OKP`, `crv` `Ed25519` and `x` the 32 bytes in unpadded base64url. The `type` (`Multikey`, `JsonWebKey`, `JsonWebKey2020`, ...) does not decide. Any other key (X25519, P-256, secp256k1) yields nothing.
4. **Cache.** Keep a document's keys for ten minutes per DID. When a proof names a method the cached keys do not include, refetch the document, at most once every thirty seconds per DID, so a key rotation is picked up without letting a stream of bad proofs become a stream of fetches. The HTTP signature verifiers do the same (`didWebKeys` in `sdk/ts/src/httpsig.ts`).

## Verifying an attestation

`proof.verificationMethod` is a DID URL `<issuer DID>#<fragment>`; resolve the part before `#`. The proof (eddsa-jcs-2022, `../README.md`) verifies when an Ed25519 key of the document verifies it, and the signer is that DID. The TS and Python SDKs try every Ed25519 key of the document; a verifier may instead use only the method the proof names. Every case here gives the same result either way. Checking that the signer equals the attestation's `issuer` is the caller's job (`trust()` does it).

## vectors.json

`cases` is a list of `{name, description, url, document, attestation, expect}`. Give the resolver a fetch that returns `document` for `url` and fails for any other URL, verify `attestation` with that resolver, and compare with `expect`: `{ok: true, signer}` or `{ok: false}`. Every case fetches `url` exactly once.

| Case | Result |
|---|---|
| `multikey-absolute-id` | Verifies: signed by `key-1`, a Multikey method with an absolute id |
| `jsonwebkey-relative-id` | Verifies: signed by `key-2`, a JsonWebKey (OKP Ed25519) method with a relative id |
| `path-and-port` | Verifies: `did:web:issuer.example%3A8443:teams:red` resolves at `https://issuer.example:8443/teams/red/did.json` |
| `unlisted-key` | Fails: the proof names `key-3`, which the document does not list, and is signed by that key |
| `document-names-another-did` | Fails: the document served at the issuer's URL has `id` `did:web:other.example` |
| `tampered-attestation` | Fails: the claim changed after signing |
| `not-ed25519` | Fails: both methods are X25519 keys (multicodec `0xec 0x01`, `crv` `X25519`) carrying the signer's Ed25519 public key bytes, so a resolver that ignores the multicodec prefix or `crv` would wrongly accept it |
