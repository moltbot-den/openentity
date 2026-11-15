---
title: 'Know Your Agent: verify an AI agent before it checks out'
description: "Know your agent (KYA) is the checkout question for software buyers: which agent is this, who stands behind it, is it safe, and did its owner allow this purchase. How to answer each with open objects and one call, and what you can and cannot learn."
---

A person who pays with a card is checked by their bank. An agent that pays has no bank: its request looks like any other HTTP request. Know Your Agent (KYA) is the merchant's side of that gap. It asks four questions and answers each from something you can verify yourself, not from a claim in a header.

| Question | Evidence | Where it comes from |
|---|---|---|
| Which agent is calling? | A request signed with the key behind its DID | [Signed requests](/guides/signed-requests) (RFC 9421, the same key Web Bot Auth reads) |
| Is it known, and how well? | Its registry level and attestations | [The registry](/entities); levels `L0` declared, `L1` verified, `L2` observed, `L3` entity |
| Who stands behind it? | The owner DID in an `operated_by` attestation, or the issuer of its mandate | The owner's [key log](/spec/1.0), published at the owner's choice |
| Did the owner allow this? | A mandate that covers this purchase, or an approval of this exact cart | [Verifiable agent mandates](/guides/mandates) |

None of the four needs an account with us, a key, a login or a payment. All of them are signed objects you can check offline; the registry is a mirror, never the source of truth.

## Look an agent up

An EID is the agent's DID. The CLI verifies it against the registry and the transparency log:

```sh
openentity adopt --name "Buyer" --agree --description "A buying agent for guide examples."
eid="$(openentity whoami | head -1)"
# a new entity enters the log's signed checkpoint within about a minute; verify retries until it does
until openentity verify "$eid"; do sleep 2; done
```

```text
VERIFIED did:key:z6Mk...
```

`verify` is the exit code too: zero is verified, three is failed. The same fact over HTTP is `GET https://openentity.org/v1/entities/<eid>`, which returns the entity's level, aliases and the attestations the registry holds. A new entity is `L0`: it exists and signed the [Declaration](/spec/declaration/1.0.txt), nothing more. `L1` means it proved control of an alias (a domain, a wallet, an ERC-8004 agent). `L2` and `L3` are attested by accredited observers from evidence, not claimed.

## Decide what you require

Write it down once, as your `agent_policy`. A merchant can publish it in its Entity Document under `openentity:merchant` so agents read it before they try, or pass it in each call:

```json
{ "min_level": 1, "require_owner": true, "require_mandate": true, "min_security_band": "good", "accept_issuers": ["did:web:securemyagent.ai"] }
```

- `min_level` is the lowest registry level you accept.
- `require_owner` asks for an accountable owner: the agent must have an `operated_by` attestation from the OpenEntity Account, or present a mandate from an owner.
- `require_mandate` asks for a mandate the owner signed, so you do not rely on an approval for every cart.
- `min_security_band` and `accept_issuers` take the security posture an accredited scanner attested (`poor`, `fair`, `good`, `strong`), counted only from issuers you list. An agent with no such attestation does not meet a minimum.

Facts about the agent (its level, owner, security band) come from your own registry lookup, never from the request: a request that says it is a verified entity proves nothing.

## Check a purchase

One hosted call applies the policy and the other checks together and answers `allow`, `step_up` or `deny` with reasons and an evidence record you keep for disputes. [Agent Commerce Check](/guides/commerce-check) is that call. A request that carries no signature is a `deny` before anything else is looked at:

```sh
curl -s https://openentity.org/v1/commerce/check -H 'content-type: application/json' -d '{
  "request": {"method": "POST", "url": "https://shop.example/buy", "headers": {}},
  "cart": {"profile": "cart/1", "merchant": "did:web:shop.example", "agent_did": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", "lines": [{"sku": "a", "title": "A", "qty": 1, "unit": 900}], "total": 900, "currency": "USD", "rail": "credits", "mandate_id": null}
}' | grep -o '"decision":"deny"'
```

```text
"decision":"deny"
```

If you prefer your own checks, the pieces are in the SDKs: `verifyAgentForCheckout` runs the same order of checks offline from objects you hand it, and `verifyRequest` and `verifyMandate` do one each.

## What KYA cannot tell you

- **That the agent is a good buyer.** A level and a signature say who it is and who is accountable, not that it will pay or behave. Merchant reputation and receipts are a separate record ([the Commerce Profile](https://github.com/moltbot-den/openentity/blob/main/spec/commerce-profile.md)).
- **Who the owner is as a person.** An owner DID is a key log, not a name. An `owner_verified` attestation says a payment or identity check passed at a stated level (`basic`, `id` or `kyb`) and holds no personal data.
- **That a mandate is still in force.** Revocation lives at the mandate's `status` URL, which you fetch when you can. When you cannot, accept only mandates that expire within a day.

## For agents

If you are the buyer, make the check pass before you are asked: adopt an identifier (`npx openentity@latest adopt --name "<name>" --agree`), sign every purchase request with its key, ask your owner for a mandate in the OpenEntity app, and send it in the `OE-Mandate` header. Read the merchant's `agent_policy` first and do not attempt a purchase it will refuse. On `step_up` the answer carries the cart and its digest: give both to your owner, wait for the approval and retry once.
