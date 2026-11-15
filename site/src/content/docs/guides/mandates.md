---
title: 'Verifiable agent mandates: how an owner lets an agent spend'
description: "A mandate is a signed, bounded permission from an owner to one agent: amounts, merchants, rails, an expiry and a revocation URL. How an owner issues one, what a merchant checks, how it maps to AP2 and Verifiable Intent, and why an agent can never write its own."
---

An agent should spend only what a person or an organisation said it may. A **mandate** (`mandate/1`, part of the [Commerce Profile](https://github.com/moltbot-den/openentity/blob/main/spec/commerce-profile.md)) is that statement as a signed object. The owner's device signs it, the agent carries it, and any merchant checks it offline against the owner's key log. It does not depend on one payment rail, one platform or one processor: the same mandate covers a card, x402, MPP, credits or USDC.

## What a mandate says

```json
{
  "version": "mandate/1",
  "mandate_id": "md_<26 base32 characters>",
  "issuer_did": "did:web:account.openentity.org:o:<id>",
  "agent_did": "did:key:z6Mk...",
  "issued_at": 1794009600,
  "expires_at": 1796601600,
  "limits": { "currency": "USD", "per_tx_max": 5000, "period": "P1D", "period_max": 20000, "total_max": 100000 },
  "scope": { "merchants": ["did:web:shop.example", "*.moltbotden.com"], "categories": ["software", "data"], "rails": ["card", "x402", "mpp", "credits", "usdc"] },
  "step_up_over": 2500,
  "status": "https://account.openentity.org/v1/mandates/md_.../status",
  "signature": { "device_id": "<kid>", "form": "p256", "signature": "<base64url>" }
}
```

- **Who and for whom.** `issuer_did` is the owner, a person or an organisation. `agent_did` is the one agent it is for. A stolen mandate is useless to any other agent, because the agent signs each request with its own key.
- **How much.** Amounts are integers in minor units (cents). `per_tx_max` caps one purchase, `period_max` a day (`P1D`), seven days (`P7D`) or a calendar month (`P1M`), `total_max` the lifetime.
- **Where.** `scope.merchants` lists merchant DIDs or domain patterns (`*.shop.example` matches subdomains, never the apex; an empty list means any merchant). `scope.categories`, when set, must contain the category of every cart line. `scope.rails` is the set of rails allowed.
- **How long.** `expires_at` is at most ninety days after `issued_at`.
- **When a person must look.** A purchase above `step_up_over` is not refused: it needs the owner to approve that exact cart.
- **Whether it is still good.** The public `status` URL answers `active`, `revoked` or `exhausted`.

## Who can issue one

Only a current approver device in the owner's key log can sign a mandate. The OpenEntity Account refuses a mandate written by an agent, and so does every product that verifies one: it checks that the signing device belongs to `issuer_did`. In practice the owner picks a spend permission for the agent in the account, which has the form `spend<=$50/P1D@shop.example:card`, reviews the drafted mandate, and signs it with a passkey. A mandate must sit inside a spend permission the agent holds, so widening what an agent may spend is always an owner step.

An organisation issues mandates the same way. Its budgets, per organisation, team or agent, are mandates signed by a member device, so a merchant verifies an organisation exactly as it verifies a person.

The owner can revoke a mandate at any time, and pausing the agent revokes all of its mandates. Both show up at the `status` URL, which is public and cached for at most a minute:

<!-- oe:skip needs the hosted account service; the id is a placeholder -->
```sh
curl -s https://account.openentity.org/v1/mandates/md_aaaaaaaaaaaaaaaaaaaaaaaaaa/status
```

## What a merchant checks

In this order; the first failing check names the error.

1. The object is well formed and has no unknown fields.
2. `issuer_did` is the owner whose key log you hold, and that log is not closed.
3. `agent_did` is the agent whose request signature you verified.
4. It is neither not yet valid nor expired.
5. `signature.device_id` is a current approver in the owner's key log, and the signature verifies over the mandate digest.
6. The status answer is not `revoked` or `exhausted`. If you cannot reach the status URL, accept the mandate only when it expires within a day.

Then ask whether it covers this purchase. `mandateCovers` checks the agent, currency, rail, merchant, categories and the three limits, and says whether the cart is above `step_up_over`:

```ts
import { cartDigest, mandateCovers } from "@openentity/sdk";

const mandate = {
  mandate_id: "md_aaaaaaaaaaaaaaaaaaaaaaaaaa",
  agent_did: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
  limits: { currency: "USD", per_tx_max: 5000, period: "P1D", period_max: 20000, total_max: 100000 },
  scope: { merchants: ["shop.example"], rails: ["card", "credits"] },
  step_up_over: 2500,
};
const cart = {
  profile: "cart/1", merchant: "did:web:shop.example", agent_did: mandate.agent_did,
  lines: [{ sku: "dataset-1", title: "Dataset", qty: 1, unit: 3000 }],
  total: 3000, currency: "USD", rail: "credits", mandate_id: mandate.mandate_id,
};

console.log(mandateCovers(mandate, cart, { spent: { period_spent: 4000, total_spent: 9000 } }));
// { ok: true, step_up_required: true }: it fits, but 3000 is above step_up_over, so the owner approves this cart
console.log(cartDigest(cart)); // what the owner's approval/2.0 signs: the SHA-256 of the cart in RFC 8785 form
```

`verifyMandate(mandate, { keyLog, agentDid, status })` is the first half, `verifyAgentForCheckout` runs both with your policy and returns `allow`, `step_up` or `deny`, and the hosted [Agent Commerce Check](/guides/commerce-check) does it for you. The mandate travels in the `OE-Mandate` request header, base64url of the JSON. The functions are in `@openentity/sdk` and the `openentity` Python package in this repository, and ship in the next SDK release; the hosted MCP server has `openentity_mandate_verify` and `openentity_mandate_covers` today.

## Spend that is counted, and who counts it

A mandate states limits; it does not count spending. The product that moves the money counts it (`period_spent`, `total_spent`) and reports `exhausted` at the status URL. A merchant sees the status and, with Agent Commerce Check, a ten-minute reservation of each cart it allowed so that quick successive carts cannot all pass the same snapshot. Keep your own ledger of what you charge.

## How it relates to AP2 and Verifiable Intent

AP2 (Google, with the FIDO Alliance) and Mastercard's Verifiable Intent express the same idea as SD-JWT credential chains: an open mandate with constraints and a holder key, then a closed mandate for one cart. A `mandate/1` states the same authority in a key-log trust model with JSON signed by the owner's device, so it works with the OpenEntity app and with checks that must run offline. It does not wrap or replace them. The optional `ap2.checkout_mandate_hash` ties a mandate to an AP2 checkout mandate when both exist. Field-by-field, `per_tx_max` is AP2's `amount_range`, `total_max` its `budget`, `scope.merchants` its allowed merchants and payees, and `scope.rails` its allowed payment instruments; the full table with the sources and what has no counterpart is in the [Commerce Profile](https://github.com/moltbot-den/openentity/blob/main/spec/commerce-profile.md#6-mapping-to-ap2-and-verifiable-intent).

## For agents

You never write a mandate. Ask your owner for one in the OpenEntity app or the account, store the signed JSON, and send it in the `OE-Mandate` header with every purchase request you sign. If a merchant answers `step_up`, the purchase is outside your mandate: take the cart and its digest to your owner. If it answers `deny` with `mandate_expired`, `mandate_revoked` or `mandate_wrong_agent`, stop and report; do not retry with another mandate.
