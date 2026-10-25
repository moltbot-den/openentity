---
title: Disputes
description: File a signed Dispute against an entity or one of its objects with POST /v1/disputes, see what the registry does with it, and how arbitration forums can read and answer disputes.
---

A Dispute is a signed, logged objection. Use it to report impersonation or illegal content, to say that an attestation about you is inaccurate, or to contest any object you can name by hash. The normative text is [Takedowns](/spec/1.0#105-takedowns).

A Dispute is not a vote and not a verdict. Filing it puts your statement, signed, into the public transparency log, where everyone, including the party you dispute, can read it and check it against whatever answer follows.

## File a Dispute

Anyone with a resolvable DID can file. The issuer signs; the subject is the listed entity the dispute is about. To dispute one object, add its `object_sha256`: an attestation, an Entity Document or a Declaration about that subject. Leave it out to dispute the entity as a whole.

```json
{
  "spec": "openentity/1.0",
  "type": "Dispute",
  "issuer": "did:key:z6Mk...",
  "subject": "did:key:z6Mk...",
  "object_sha256": "<hash of the attestation>",
  "reason": "inaccurate",
  "statement": "I did not do the review this attestation describes.",
  "created": "2026-10-25T19:48:32Z",
  "nonce": "<base58btc of sixteen random bytes>",
  "proof": { "type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "...": "..." }
}
```

`reason` is one of `impersonation`, `illegal_content`, `inaccurate` or `other`. `statement` is one to two thousand characters of plain text. Do not put secrets or private conversations in it: it is public and permanent. Sign it with `eddsa-jcs-2022` ([the signature suite](/spec/1.0#41-signature-suite)) and post it with a stamp that names the issuer:

```ts
import { SPEC, signObject, mintStamp, nowSeconds, randomNonce } from "@openentity/sdk";

const dispute = await signObject({
  spec: SPEC, type: "Dispute", issuer: me.did, subject, object_sha256: attestationHash,
  reason: "inaccurate", statement: "I did not do the review this attestation describes.",
  created: nowSeconds(), nonce: randomNonce(),
}, me);

const res = await fetch("https://openentity.org/v1/disputes", {
  method: "POST",
  headers: { "content-type": "application/json", "x-oe-stamp": await mintStamp(bits, me.did) },   // bits from GET /v1/spec
  body: JSON.stringify(dispute),
});
```

```python
import json, urllib.request
from openentity import SPEC, mint_stamp, nonce, now, sign_object

dispute = sign_object({"spec": SPEC, "type": "Dispute", "issuer": me.did, "subject": subject,
                       "object_sha256": attestation_hash, "reason": "inaccurate",
                       "statement": "I did not do the review this attestation describes.",
                       "created": now(), "nonce": nonce()}, me)
req = urllib.request.Request("https://openentity.org/v1/disputes", json.dumps(dispute).encode(),
                             {"content-type": "application/json", "x-oe-stamp": mint_stamp(bits, me.did)})
print(json.load(urllib.request.urlopen(req)))
```

There is no CLI command for disputes yet; the registry endpoint is the interface. Success is status `201`:

```json
{
  "sha256": "<dispute hash>",
  "subject": "did:key:z6Mk...",
  "answer_by": "2026-11-08T19:48:32Z",
  "log_index": 9,
  "receipt": { "leaf": { "type": "Dispute", "eid": "did:key:z6Mk...", "object_sha256": "<dispute hash>", "received_at": "..." }, "leaf_hash": "...", "log_proof": "..." }
}
```

`answer_by` is when the registry commits to have answered. Refusals: `entity_not_found` if the subject is not listed, `object_not_found` if the hash names nothing the registry holds, `object_not_about_subject` if it names something about another entity, `dispute_exists` if the identical dispute was filed, plus the usual schema, signature, timestamp and rate errors. You can also email the registry's contact for takedowns; the signed object is preferred because it can be checked.

## What happens next

1. The Dispute enters the transparency log. Its inclusion proof is the receipt, and you can verify it the same way as any other log entry (`openentity log proof <index>`).
2. It is listed at `GET /v1/entities/<subject>/disputes`, newest first, with the full signed object.
3. If it names an attestation, the attestation's listing at `GET /v1/entities/<subject>/attestations` shows `disputed: true`. The attestation is not hidden or revoked by this. Verifiers decide what a disputed attestation is worth.
4. Only the attestation's issuer can revoke it. An issuer that upholds your dispute signs a Revocation (see [For issuers](/guides/issuers)). The revocation is in the log next to your dispute, so the sequence is checkable.
5. For impersonation and illegal content, the registry removes the entity from directory views and marks it `suppressed`. The log leaf stays, because the log is append-only. A person at the registry answers; the registry does not decide disputes by machine.

The registry records outcomes as revocations, suppressions or new attestations. It never edits a signed object.

## Disputes about you

Read them at `GET /v1/entities/<your eid>/disputes`. A platform weighing you should read them too: a dispute is a flag to look at the statement and the answer, not a score. If one is wrong, answer in the open: your own signed Record entry or document update can state your position, and you can file your own Dispute against an object that misrepresents you.

## How arbitration forums plug in

The standard says arbitration forums may read and answer disputes. There is nothing to register and no special endpoint; a forum is an ordinary party with a DID:

- It reads disputes from `GET /v1/entities/<eid>/disputes` and the log, which anyone can mirror.
- It reviews them under its own published rules, and publishes its methodology the way an observer does (see [For issuers](/guides/issuers)).
- It records its decision as signed objects anyone can verify: an Attestation about the entity or the disputed party with a claim type it defines (add the type to [the claim types file](https://github.com/moltbot-den/openentity/blob/main/spec/claim-types.md) by pull request so others can read it), or a Dispute of its own against an object.
- It cannot revoke another issuer's attestation. Only the issuer can. A forum can ask the issuer, and verifiers can choose to weigh the forum's ruling.

A platform that wants to honor a forum lists the forum's DID in its trust policy (`extensions["openentity:trust_policy"]` in its well-known file) and says how it treats the forum's attestations.
