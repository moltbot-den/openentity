---
title: 'Agent Commerce Check: verify any agent before you take its money'
description: "Agent checkout verification in one call. Agent Commerce Check answers allow, step_up or deny for an agent purchase, with reasons and a hash-chained evidence record. One hosted call or one line of middleware for Express, Hono, Next.js, FastAPI and Django. Free, no key."
---

A merchant, API seller or platform asks one question before it accepts a purchase from an agent: is this really agent A, does an owner stand behind it, and is this spend inside what the owner allowed? Agent Commerce Check answers it with `allow`, `step_up` or `deny`, the reasons, and an `evidence_id` you keep for disputes.

It is free and needs no key, no login and no CAPTCHA, like the rest of the registry. It is built on the Commerce Profile (`mandate/1`, `cart/1`, `receipt/1`) of the [spec](/spec/1.0).

## What it checks

In this order; each failure is a reason code in the answer.

| Check | Fails with |
|---|---|
| `signature`: the request carries a valid RFC 9421 signature for the agent DID, the request URL is on the host of `cart.merchant` (a `did:web` DID), and the nonce was not used before | `request_unverified`, `request_wrong_audience`, `request_replayed`, `agent_mismatch` |
| `registry`: the DID is not withdrawn and meets your `min_level` | `agent_withdrawn`, `level_too_low` |
| `owner`: an accountable owner stands behind the agent (the mandate's issuer, or the `operated_by` attestation of the OpenEntity Account) | `owner_unknown`, `owner_not_verified`, `owner_key_log_fork` |
| `security`: the Secure My Agent posture band from an accredited observer meets your minimum, and no live ClawGRC violation | `security_band_too_low`, `issuer_not_accepted`, `clawgrc_violation` |
| `mandate`: the `mandate/1` verifies against the owner's key log, is not revoked, and covers the cart | `mandate_required`, `mandate_expired`, `mandate_revoked`, `mandate_wrong_agent`, `mandate_bad_signature`, `mandate_status_unavailable`, `no_key_log` |
| `policy`: your `agent_policy`, inline or published in your Entity Document under `openentity:merchant` | `step_up`: above the mandate's `step_up_over`, the owner must approve this exact cart |

What gets each answer: `deny` when the request is unsigned, signed for another host or replayed, names another agent, fails your policy, or carries a dead mandate. `step_up` when the signature and policy hold but no mandate covers the cart: no `OE-Mandate` and `require_mandate` is off (`no_mandate`), the cart is over the mandate's `step_up_over` (`step_up_over`) or its limits (`mandate_over_limit`). `allow` when a mandate from the owner covers the cart (`mandate_covers_cart`) or the owner approved this exact cart (`owner_approved_cart`). A mandate is signed by the owner's device in the OpenEntity app, so `allow` needs a real owner; an agent alone reaches `deny` and `step_up`.

`step_up` is not a refusal: the answer carries the cart and its digest. The owner approves it in the OpenEntity app (an `approval/2.0` whose `payload_digest` is that digest), the agent sends the approval back, and the same check answers `allow`. Your middleware passes it on through the `approval` option (a function that returns `{approval, verifier_did, request_id}` from the retried request, for example from a header you choose); `verifier_did` and `request_id` are the ones you gave the owner, and `verifier_did` is your merchant DID. An approval works once. `deny` is final.

A mandate is accepted only with a live status answer from the OpenEntity Account: when it cannot be fetched the check answers `deny` with `mandate_status_unavailable` (the one-day offline rule belongs to the library below). The check keeps a ten-minute reservation of every cart it allowed, and adds it to the mandate's `period_spent` and `total_spent`, so rapid carts cannot pass the same status snapshot. Settled spend is still counted by the account that enforces the mandate; keep your own ledger of what you charge.

## One call

<!-- oe:skip needs a real agent signature and a mandate from an owner's device -->
```sh
curl -s https://openentity.org/v1/commerce/check -H 'content-type: application/json' -d '{
  "request": {"method": "POST", "url": "https://shop.example/buy", "headers": {"signature-input": "...", "signature": "..."}},
  "cart": {"profile": "cart/1", "merchant": "did:web:shop.example", "agent_did": "did:key:z6Mk...", "lines": [{"sku": "dataset-1", "title": "Dataset", "qty": 1, "unit": 1000}], "total": 1000, "currency": "USD", "rail": "credits", "mandate_id": "md_..."},
  "policy": {"require_mandate": true, "require_owner": true, "min_security_band": "good"}
}'
```

The agent sends its mandate in the `OE-Mandate` request header (base64url of the JSON), so your server forwards the header it received; or put the mandate in the body as `mandate`. Add `body` (or `body_b64`) when the agent signed over the request body.

A request that is not signed is a deny, with evidence:

```sh
curl -s https://openentity.org/v1/commerce/check -H 'content-type: application/json' -d '{
  "request": {"method": "POST", "url": "https://shop.example/buy", "headers": {}},
  "cart": {"profile": "cart/1", "merchant": "did:web:shop.example", "agent_did": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", "lines": [{"sku": "a", "title": "A", "qty": 1, "unit": 900}], "total": 900, "currency": "USD", "rail": "credits", "mandate_id": null}
}' | grep -o '"decision":"deny","reasons":\["request_unverified"\]'
```

The answer is `{decision, reasons, agent_did?, owner_did?, mandate_id?, cart?, cart_digest?, evidence_id}`. The endpoint is limited per IP; there is no key to buy a higher limit.

## Evidence

Every call writes one record to a hash chain: the digest of the inputs, the result of each check, the attestation hashes used, the mandate hash, the decision, the time and the verifier version. Each record carries `prev_hash`, and its own `hash` is the SHA-256 of its RFC 8785 form without `hash`.

`GET /v1/commerce/evidence/<evidence_id>` returns the record and `intact: true` when its hash holds. `intact` belongs to the answer, not to the record: to check a record yourself, drop `hash` and `intact`, canonicalize what is left (RFC 8785; `canonicalize` in `@openentity/sdk`), take the SHA-256 and compare it with `hash`. A record has `evidence_id`, `seq`, `created_at`, `inputs_digest`, `checks` (one result per check: `pass`, `fail`, `step_up` or `skipped`), `attestation_ids`, `mandate_hash`, `decision`, `reasons`, `agent_did`, `owner_did`, `verifier_version`, `prev_hash` and `hash`. `GET /v1/commerce/head` returns the newest `seq` and `hash`. Records are kept for `400` days, the longest card dispute window plus margin, then deleted. The record holds a digest of your request, not the request.

## Middleware

<!-- oe:skip needs the @openentity/commerce-check package, released with the next package batch -->
```ts
import { expressCheck } from "@openentity/commerce-check"; // also honoCheck (Hono, Workers) and nextCheck (Next.js)

// Your cart/1 for this request. `merchant` is the did:web of the host agents call (did:web:shop.example, or did:web:127.0.0.1%3A8080 on a
// local port); the check refuses a signature made for another host. `agentDid` is the signer; the check verifies it, you only name it here.
const cartFor = (req, agentDid) => {
  const total = Number(new URL(req.url).searchParams.get("total") ?? 1000); // minor units
  return { profile: "cart/1", merchant: "did:web:shop.example", agent_did: agentDid, lines: [{ sku: "dataset-1", title: "Dataset", qty: 1, unit: total }], total, currency: "USD", rail: "credits", mandate_id: null };
};

app.post("/buy", expressCheck({
  policy: { require_mandate: true, require_owner: true },
  cart: cartFor,
}), (req, res) => res.json({ bought: true, evidence_id: req.agentCheck.evidence_id }));
```

Until the package is released, call the hosted check yourself as in [One call](#one-call): the middleware is that call plus the status codes below. The package's `examples/` and `proof.mjs` (a fresh merchant and a fresh agent that hit all three decisions and fetch every evidence record back) show the whole loop.

`step_up` answers `428` with the cart, `deny` answers `403`, both with the `evidence_id`; set `enforce: false` for observe mode, which attaches `req.agentCheck` and never blocks. If the check cannot run, an enforcing server answers `503` and an observing one carries on. Agents sign your public URL, so behind a proxy set `publicOrigin: "https://shop.example"` (`public_origin` in Python): the check refuses a request signed for another host, and a URL built from the incoming `Host` header would let anyone choose it. The raw body bytes are sent as `body_b64`; for Express keep them with `express.json({ verify: (req, _res, buf) => (req.rawBody = buf) })`.

<!-- oe:skip needs the openentity Python package with FastAPI installed, released with the next package batch -->
```python
from fastapi import FastAPI, Request
from openentity.commerce import CommerceCheckMiddleware

app = FastAPI()
app.add_middleware(CommerceCheckMiddleware, paths=["/buy"], cart=cart_for, policy={"require_mandate": True, "require_owner": True})

@app.post("/buy")
def buy(request: Request):
    return {"bought": True, "evidence_id": request.state.agent_check["evidence_id"]}
```

For Django, add `openentity.commerce.django_middleware(...)` to `MIDDLEWARE` and read `request.agent_check`.

## Offline

The check is a library first. `verifyAgentForCheckout` in `@openentity/sdk` and `openentity` runs the same decision with no call home: you bring the registry facts, the owner's key log and the mandate status.

## For agent platforms

The [remote MCP server](/guides/adopt-mcp) has `openentity_commerce_check`, `openentity_mandate_verify` and `openentity_mandate_covers`, for platforms that broker purchases on behalf of agents.

## For agents

Before you buy, send your owner's mandate in the `OE-Mandate` header and sign the request with your key ([Know Your Agent](/guides/know-your-agent), [mandates](/guides/mandates)). Read the answer, not only the status code: `allow` means proceed, `428` with `step_up` means give the cart and its digest to your owner and retry once with their approval, and `403` with `deny` means stop and report the reasons. Keep the `evidence_id` with the receipt. The MCP tool `openentity_commerce_check` at https://mcp.openentity.org/mcp runs the same check.
