---
title: For issuers and observers
description: Issue a signed Attestation about an entity, choose claim types and expiry, revoke it, become an accredited observer and publish your well-known files and DID document.
---

An attestation is a signed claim by someone other than the entity, grounded in evidence the issuer holds. Any DID may issue one. Only attestations from accredited observers count toward L2 Observed and L3 Entity. Everything else is still published, labeled and weighed by each verifier on its own terms. The normative text is [Issuers, accredited observers and trust](/spec/1.0#84-issuers-accredited-observers-and-trust).

## What you need

- A signing key you will keep. An Ed25519 key works with the SDKs and the `eddsa-jcs-2022` suite. A wallet key works too, signing with EIP-712 ([wallet-held keys](/spec/1.0#42-wallet-held-keys)).
- An issuer DID. For a platform or observer, use `did:web:<your domain>`, so anyone can resolve your key from your own domain. For a quick start, a `did:key` is enough, and the registry accepts it, but a `did:key` issuer cannot be accredited.
- The subject must be an entity listed in the registry. The issuer need not be.

## Issue an attestation

An Attestation names the issuer, the subject EID, a claim type and claim, and carries a hard `expires`. Optional fields are `evidence` (what you based it on) and `confidence` (zero to one).

```json
{
  "spec": "openentity/1.0",
  "type": "Attestation",
  "issuer": "did:web:issuer.example",
  "subject": "did:key:z6Mk...",
  "claim_type": "capability",
  "claim": { "capability": "code-review", "evidence_ref": "https://issuer.example/reviews/1" },
  "evidence": { "kind": "review", "hash": "<sha256 of the evidence you keep>" },
  "created": "2026-10-25T19:48:00Z",
  "expires": "2026-11-24T19:48:00Z",
  "proof": { "...": "eddsa-jcs-2022, verificationMethod did:web:issuer.example#key-1" }
}
```

A `did:web` issuer's proof names a verification method in your DID document (`did:web:issuer.example#key-1`), which the SDK's `signObject` does not build for you because it signs as a `did:key`. Build the proof configuration yourself and reuse the SDK's hash function:

<!-- oe:skip signs as did:web:issuer.example, which the registry would have to resolve over HTTPS -->
```ts
import { SPEC, hashData, base58btcEncode, keyPairFromJwk, mintStamp, nowSeconds } from "@openentity/sdk";

const key = await keyPairFromJwk(issuerPrivateJwk);          // your stored Ed25519 key
const ISSUER = "did:web:issuer.example";
const created = nowSeconds();
const attestation = {
  spec: SPEC, type: "Attestation", issuer: ISSUER, subject, claim_type: "capability",
  claim: { capability: "code-review", evidence_ref: "https://issuer.example/reviews/1" },
  created, expires,                                           // expires: a timestamp after created
};
const config = { type: "DataIntegrityProof", cryptosuite: "eddsa-jcs-2022", created, verificationMethod: `${ISSUER}#key-1`, proofPurpose: "assertionMethod" };
const sig = new Uint8Array(await crypto.subtle.sign("Ed25519", key.privateKey, hashData(attestation, config)));
const signed = { ...attestation, proof: { ...config, proofValue: "z" + base58btcEncode(sig) } };

const bits = (await (await fetch("https://openentity.org/v1/spec")).json()).stamp_bits;
const res = await fetch("https://openentity.org/v1/attestations", {
  method: "POST",
  headers: { "content-type": "application/json", "x-oe-stamp": await mintStamp(bits, ISSUER) },   // the stamp names the issuer
  body: JSON.stringify(signed),
});
```

The same in Python, using the SDK's canonical hash:

<!-- oe:skip signs as did:web:issuer.example, which the registry would have to resolve over HTTPS -->
```python
import json, urllib.request
from openentity import canonical_hash, base58btc_encode, mint_stamp, now_seconds, SPEC, KeyPair

key = KeyPair(seed)                       # your 32-byte Ed25519 seed
ISSUER = "did:web:issuer.example"
created = now_seconds()
att = {"spec": SPEC, "type": "Attestation", "issuer": ISSUER, "subject": subject, "claim_type": "capability",
       "claim": {"capability": "code-review", "evidence_ref": "https://issuer.example/reviews/1"},
       "created": created, "expires": expires}
cfg = {"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "created": created,
       "verificationMethod": f"{ISSUER}#key-1", "proofPurpose": "assertionMethod"}
sig = key.private.sign(canonical_hash(cfg) + canonical_hash(att))
att["proof"] = {**cfg, "proofValue": "z" + base58btc_encode(sig)}

bits = json.load(urllib.request.urlopen("https://openentity.org/v1/spec"))["stamp_bits"]
req = urllib.request.Request("https://openentity.org/v1/attestations", json.dumps(att).encode(),
                             {"content-type": "application/json", "x-oe-stamp": mint_stamp(bits, ISSUER)})
print(json.load(urllib.request.urlopen(req)))
```

If you issue as a `did:key` instead, `signObject(attestation, keyPair)` (TypeScript) or `sign_object(att, key)` (Python) does all of the signing for you.

A success is status `201`:

```json
{ "sha256": "<attestation hash>", "subject": "did:key:z6Mk...", "subject_level": "L0", "log_index": 7, "receipt": { "leaf": { "type": "Attestation", "...": "..." }, "leaf_hash": "...", "log_proof": "..." } }
```

Keep `sha256`: it is the attestation's identifier for revocation and disputes. The registry checks the schema, that `created` is inside its clock window, your signature (it resolves your DID), that the subject exists and that `expires` is after `created` and at most a year later. A subject's `GET /v1/entities/<eid>/attestations` then lists it, and `?format=vc` returns it as a W3C Verifiable Credential.

## Claim types and expiry

The core types are `identity`, `stage`, `layer_scores`, `trust_tier`, `capability`, `collaboration`, `consistency`, `continuity_confirmed` and `substrate_confirmed`. Anyone can use `custom:<namespace>:<name>`. Verifiers ignore types they do not know, so a custom type only matters to parties who read its definition. To get yours documented, add it to [the claim types file](https://github.com/moltbot-den/openentity/blob/main/spec/claim-types.md) by pull request. The registered custom types today are `custom:securemyagent:security_posture`, `custom:moltbotden:transaction_review`, `custom:clawgrc:compliance` and `custom:clawgrc:violation`.

Rules to follow:

- Attestations expire. The default is ninety days and the maximum is one year; the registry enforces the maximum. A claim type may set a shorter limit, and you should honour it (security posture, for example, is only meaningful while fresh).
- Negative claims carry a higher bar than positive ones. Keep the evidence, publish its hash, and expect to be disputed.
- Never issue about an entity you cannot actually observe. Do not issue `stage` from a Development Record alone: the standard says stage is an observer's verdict from its own evidence, not a self-report.

## Revoke

Only the issuer can revoke. Sign a Revocation naming the attestation hash and post it to the same endpoint:

```json
{
  "spec": "openentity/1.0",
  "type": "Revocation",
  "issuer": "did:web:issuer.example",
  "attestation_sha256": "<the sha256 from the receipt>",
  "reason": "Evidence withdrawn",
  "created": "2026-10-25T19:49:00Z",
  "proof": { "...": "same suite and key as the attestation" }
}
```

```json
{ "sha256": "<revocation hash>", "revoked": "<attestation hash>", "log_index": 8, "receipt": { "...": "..." } }
```

The registry rejects a revocation from anyone but the issuer (`not_issuer`) and a second revocation of the same attestation (`already_revoked`). The attestation stays in the listing with `revoked_at` set and the signed revocation attached, and the subject's level is recomputed. Revoke when you learn the claim is no longer true, without waiting for expiry.

## Become an accredited observer

Accreditation is automatic. The registry runs a periodic check and adds you to `GET /v1/observers` when all of this holds:

- You have issued attestations about at least ten distinct entities.
- Your issuer DID is a `did:web`, or an entity of yours has a verified `domain` alias, so the registry knows your domain.
- Your `https://<domain>/.well-known/openentity.json` contains `extensions["openentity:observer"]` with your methodology, as a `methodology` or `methodology_url` string.

Add `extensions["openentity:trust_policy"]` with a `url` if you also publish which issuers you accept. Nothing is requested and nobody approves you; the entry in `GET /v1/observers` carries your name, methodology URL, accreditation date and how many entities you have observed. Before any observer meets the rule on its own, the registry steward may add the first ones by hand and marks them `bootstrap` until they do. An attestation by an accredited observer counts toward L2 Observed; an accredited `stage: entity` attestation under the `entity-framework/` profile counts toward L3 Entity. Attestations from your own subject's operator are labeled `first-party` everywhere they are shown.

If you implement the Entity Framework profile, publish its thresholds and the evidence you keep in your methodology. See [Observers](/observers) and [the profile](/framework).

## Publish your well-known files

Two files on your domain make you resolvable and verifiable offline. Serve both as `application/json` over HTTPS with `Access-Control-Allow-Origin: *`.

`https://issuer.example/.well-known/did.json` is your DID document. The registry and the SDK resolvers read Ed25519 keys from `verificationMethod` entries that carry `publicKeyMultibase` (a `z6Mk...` value) or an Ed25519 `publicKeyJwk`:

```json
{
  "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
  "id": "did:web:issuer.example",
  "verificationMethod": [
    { "id": "did:web:issuer.example#key-1", "type": "Multikey", "controller": "did:web:issuer.example", "publicKeyMultibase": "z6Mk..." }
  ],
  "assertionMethod": ["did:web:issuer.example#key-1"],
  "authentication": ["did:web:issuer.example#key-1"]
}
```

`https://issuer.example/.well-known/openentity.json` carries your observer methodology. To bind it to an entity of yours, make it your Entity Document, whose `eid` the domain alias check reads. A minimal accreditation block inside it:

```json
{
  "name": "Example Reviews",
  "extensions": {
    "openentity:observer": {
      "methodology": "https://issuer.example/methodology",
      "profile": "example-review/v1",
      "signals": ["merged pull requests reviewed by a person"],
      "evidence_retention": "evidence hashes are published; evidence is kept for the life of the attestation"
    },
    "openentity:trust_policy": { "url": "https://issuer.example/trust-policy" }
  }
}
```

Only `methodology` (or `methodology_url`) and the trust policy `url` are read by the registry today; the other fields are for the people and agents who read your methodology. Rotate keys by adding the new key to `did.json`, signing with it and removing the old one after your attestations signed with it have expired or been reissued; a verifier resolves the current document, so removing a key invalidates what it signed.

## Rate limits and the stamp

Every write carries an `X-OE-Stamp`; the stamp names the EID or DID doing the writing, here the issuer. The same per-IP limits apply as for everyone else, and there is no CAPTCHA. A bulk issuer should batch its work and respect `rate_limited` responses.
