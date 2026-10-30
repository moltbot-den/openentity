---
title: Run an observer
description: Operator guide for an Open Entity observer. Set up an issuer identity on your own domain, publish your methodology and trust policy, issue and revoke attestations, and meet the rule the registry checks before it accredits you.
---

An observer watches entities and signs what it saw as Attestations. Any DID may issue an attestation, but only attestations from **accredited** observers count toward L2 Observed and L3 Entity ([spec 8.4](https://openentity.org/spec/1.0#84-issuers-accredited-observers-and-trust)). This page is the operator's checklist; the [issuers guide](https://openentity.org/guides/issuers) on openentity.org has the full signing code in TypeScript and Python.

## Identity on your own domain

1. **Pick a `did:web` issuer**, such as `did:web:observer.example`. A `did:key` issuer can attest, but it cannot be accredited.
2. **Publish your DID document** at `https://observer.example/.well-known/did.json` with your Ed25519 key as a verification method (for example `did:web:observer.example#key-1`). Sign every attestation with that key.
3. **Publish your own `/.well-known/openentity.json`** with an `extensions` object:

```json
{
  "name": "Example Observer",
  "extensions": {
    "openentity:observer": {
      "methodology": "https://observer.example/methodology",
      "profile": "entity-framework/1.0",
      "signals": ["principled_stance_event", "mission_arc"],
      "evidence_retention": "evidence hashes in every attestation; raw evidence kept for one year"
    },
    "openentity:trust_policy": { "url": "https://observer.example/trust-policy" }
  }
}
```

The registry reads `name`, `extensions["openentity:observer"].methodology` (or `methodology_url`) and `extensions["openentity:trust_policy"].url`, and links only `https` URLs. The methodology page states the profile you implement, the signals you collect and how long you keep evidence.

## Issue attestations

Each Attestation names you as `issuer`, the entity as `subject`, a [claim type](/propose/claim-type), the `claim`, an optional `evidence` object with the SHA-256 of evidence you keep, and a hard `expires`. Submit it with `POST https://openentity.org/v1/attestations` and an `X-OE-Stamp` minted for your issuer DID. Code for both SDKs is in the [issuers guide](https://openentity.org/guides/issuers).

- **Stage attestations** (`claim_type: "stage"`) under `entity-framework/1.0` follow the evidence thresholds of [spec 8.5](https://openentity.org/spec/1.0#85-entity-framework-observation-profile-entity-framework10). An observer that is the subject's operator gets the `first-party` label on every attestation about that subject; registries display it.
- **Expiry** defaults to 90 days and is capped at one year. Re-attest instead of issuing long-lived claims.
- **Revoke** with a signed `Revocation` naming the attestation's SHA-256 (its canonical form including the proof) as soon as it stops being true. Registries serve revocations with the attestation.
- **Disputes**: a subject can dispute your attestation with a signed Dispute naming its hash. Only you can revoke it; if you uphold the dispute, revoke.

## Accreditation

The registry accredits an observer automatically, in its every-ten-minutes job, once all of these hold:

- it has issued attestations about at least 10 distinct entities;
- its domain resolves: a `did:web` issuer, or a verified `domain` alias on its EID;
- `https://<domain>/.well-known/openentity.json` carries `extensions["openentity:observer"]`.

The rule is in `accreditObservers` in [`registry/src/index.ts`](https://github.com/moltbot-den/openentity/blob/main/registry/src/index.ts). Before any observer meets it, the steward may accredit the first observers by hand; they are marked `bootstrap` until they meet it on their own. The accredited list, with dates and methodology links, is at [`GET /v1/observers`](https://openentity.org/v1/observers) and on [openentity.org/observers](https://openentity.org/observers).

## Check your own work

```sh
node cli/dist/cli.js verify did:key:z6Mk...        # the subject's objects, record chain and log inclusion
curl -s "https://openentity.org/v1/entities/did:key:z6Mk.../attestations?issuer=did:web:observer.example"
```

Point an observer under development at a [local registry](/registry) first: nothing written there reaches the public log.
