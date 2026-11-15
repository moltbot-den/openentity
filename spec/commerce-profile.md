# Open Entity Commerce Profile (OEIS-1 profile, version 1)

Status: draft 1, 2026-11-14. A profile of `OEIS-1`: it adds objects and claim types and changes nothing in `OEIS-1.md`. Author and steward: Moltbot Den. CC0-1.0.

Reference implementations: `@openentity/sdk` and `openentity` (`verifyMandate`, `mandateCovers`, `cartDigest`, `signReceipt`, `verifyReceipt`, `verifyAgentForCheckout`, `verifyQuorum`). Test vectors: `test-vectors/mandate-1/`, `cart-1/`, `receipt-1/`, `checkout-1/`, `quorum-1/`. Every rule below has a vector that fails if the rule is removed. Any change to a signing layout requires a new version of the object.

## 1. What it is for

A merchant, payment processor or platform can check, offline and in one round trip, that:

1. the request comes from agent DID A (RFC 9421 HTTP message signature, `OEIS-1` section 11.2);
2. A is operated by owner O, and O authorised this spend: a Mandate signed by an approver key in O's key log (ADR 0007), or an approval/2.0 (ADR 0008) of this exact cart;
3. the purchase fits the Mandate, or O approved the cart;
4. afterwards both sides hold a Receipt signed by both, usable as dispute evidence.

The profile defines signed objects over existing checkout and payment protocols. It does not define a checkout protocol, a payment rail or a wire format for carrying a request. Mandates travel in the `OE-Mandate` request header (base64url of the JSON) or inside a Presentation; nothing in this profile is published to the registry unless a party chooses to (section 5.3).

## 2. mandate/1

A standing, bounded permission from an owner to one agent. JSON, RFC 8785 (JCS) canonical, signed like approval/2.0 by a P-256 approver key in the owner's key log, so the existing SDK verifiers and the OpenEntity app signing sheet are reused.

```json
{
  "version": "mandate/1",
  "mandate_id": "md_<26 base32>",
  "issuer_did": "did:web:account.openentity.org:o:<id>",
  "agent_did": "did:key:z6Mk...",
  "issued_at": 1794009600,
  "expires_at": 1796601600,
  "limits": { "currency": "USD", "per_tx_max": 5000, "period": "P1D", "period_max": 20000, "total_max": 100000 },
  "scope": { "merchants": ["did:web:shop.example", "*.moltbotden.com"], "categories": ["software", "data"], "rails": ["card", "x402", "mpp", "credits", "usdc"] },
  "step_up_over": 2500,
  "status": "https://account.openentity.org/v1/mandates/md_.../status",
  "ap2": { "checkout_mandate_hash": null },
  "signature": { "device_id": "<kid>", "form": "p256", "signature": "<base64url>" }
}
```

| Field | Rule |
|---|---|
| `mandate_id` | `md_` then 26 characters of `[a-z2-7]` |
| `issuer_did`, `agent_did` | DIDs. `issuer_did` is the owner DID whose key log holds the signing key |
| `issued_at`, `expires_at` | Unix seconds; `expires_at` is after `issued_at` by at most 90 days |
| `limits` | Amounts are integers in minor units (no fractions, at most 2^53 - 1). `period` is `P1D`, `P7D` or `P1M` (calendar month, UTC). All five fields are required |
| `scope.merchants` | Merchant DIDs (exact match) or domain patterns matched against the host of a `did:web` merchant: `shop.example` equals the host; `*.shop.example` matches subdomains only, never the apex. Empty means any merchant |
| `scope.categories` | Optional. When present and non-empty, every cart line must carry a `category` in the list |
| `scope.rails` | A non-empty subset of `card`, `x402`, `mpp`, `credits`, `usdc` |
| `step_up_over` | A purchase whose total is above this needs a per-cart approval (section 3) |
| `status` | An https URL answering section 2.2 |
| `ap2` | Optional. `checkout_mandate_hash` binds this mandate to an AP2 mandate (section 6) |
| `signature` | `{device_id, form, signature}`, plus `authenticator_data` and `client_data_json` for `form: "webauthn"`, exactly as in approval/2.0. `device_id` is a current approver in the key log |

Unknown top-level fields are refused: they would be signed, and verifiers could not agree what they mean.

### 2.1 Digest

```
digest = SHA-256( UTF-8( "mandate/1" "|" verifier_scope "|" JCS(mandate without signature) ) )
```

`verifier_scope` is `*` in version 1: any merchant may rely on the mandate. The prefix differs from `approval/2.0|`, so a mandate signature never verifies as an approval and an approval signature never verifies as a mandate (both directions have vectors). The p256 and WebAuthn signature forms are those of approval/2.0; for WebAuthn the challenge is base64url(digest).

### 2.2 Status and revocation

The `status` URL answers `{"status": "active" | "revoked" | "exhausted", "period_spent": n, "total_spent": n}` with `Cache-Control: max-age` of 60 or less. The owner pausing the agent (ADR 0007) revokes every mandate of that agent. A verifier that can call out passes the answer to `verifyMandate`. A verifier that cannot accepts a mandate only when `expires_at - now` is a day or less: short-lived mandates are the offline mode. A status answer that is not an object with `status` one of those three, with a `mandate_id` (when present) other than the mandate's, or with a `period_spent` or `total_spent` that is not an unsigned integer, is no answer: `status_required`. Spend accounting (`period_spent`, `total_spent`) belongs to the product that enforces the mandate; merchants only see the status. The status answers `exhausted` once the reported `total_spent` is at least `limits.total_max` (`revoked` wins over `exhausted`); how a product reports its spend to the status service is that service's interface (the account service takes `PUT /v1/mandates/{id}/spend`, signed by the product, in `account/openapi.yaml`), and the answer carries `period_spent` and `total_spent` summed over the reporting products, 0 until one reports.

### 2.3 Verifier checks, in order

The first failing check names the error.

1. `malformed`: not an object; `bad_version`: `version` is not `mandate/1`.
2. `malformed`: a field above has the wrong form, an unknown field is present, or the signature fields are not strict base64url.
3. `wrong_owner`: `issuer_did` is not the DID of the key log it is checked against. `owner_closed`: that key log is closed.
4. `wrong_agent`: the presenting agent (from the verified request signature) is not `agent_did`.
5. `not_yet_valid` (now before `issued_at`), `expired` (now at or after `expires_at`).
6. `unknown_key`: `device_id` is not a current approver. Revoked approvers and the root passkey never sign mandates.
7. `bad_signature` or `bad_webauthn`: the signature does not verify over the digest.
8. `revoked` or `exhausted` from the status answer; `status_required` when there is no answer and more than a day is left.

An agent can never sign a mandate. The account service refuses agent-written mandates, and products refuse any mandate whose `device_id` is not an approver of `issuer_did`.

### 2.4 Covering a cart

`mandateCovers(mandate, cart, {spent})` runs on a verified mandate. The first failing check names the reason: `bad_cart`, `wrong_agent` (the cart names another agent), `wrong_mandate` (the cart names another `mandate_id`; a null `mandate_id` is checked against the mandate offered), `wrong_currency`, `out_of_scope` (rail, merchant or category), `over_limit` (`total` above `per_tx_max`; `period_spent + total` above `period_max`; `total_spent + total` above `total_max`; a spend equal to a limit fits; a `spent` value that is not an unsigned integer is `over_limit`). A merchant pattern `*.host` or `host` matches only a did:web DID whose percent-decoded host is a plain hostname (`[a-z0-9.-]`, optional `:port`): a host holding `/`, `#`, `?`, `@` or a bad escape matches no pattern. When it fits, `step_up_required` is `total > step_up_over`.

## 3. cart/1

The summary an owner approves for one purchase. It is the payload of an approval/2.0: `payload_digest = SHA-256(JCS(cart))` in lowercase hex (`cartDigest`), so a merchant checks the approved cart is this cart.

```json
{ "profile": "cart/1", "merchant": "did:web:shop.example", "agent_did": "did:key:...",
  "lines": [{ "sku": "lst_123", "title": "Dataset", "qty": 1, "unit": 2500, "category": "data" }],
  "total": 2500, "currency": "USD", "rail": "credits", "mandate_id": "md_..." }
```

Exactly these keys (a line may omit `category`). `lines` holds 1 to 100 lines; `qty` is a positive integer; `unit` and `total` are integers in minor units; `total` equals the sum of `qty * unit`; `rail` is one of the five rails; `mandate_id` is a mandate id or null. Amounts are never floats (approval/2.0 payload rule). The merchant's own DID is the approval's `verifier_did`, and its `request_id` is the merchant's id for this cart state.

## 4. receipt/1

Signed by both parties after settlement. Ed25519 `eddsa-jcs-2022`, the suite of attestations. Both parties sign the same bytes, the receipt without `proofs`, so the buyer countersigns without seeing the merchant's proof. A party whose DID is a `did:pkh` wallet signs the EIP-712 suite of OEIS-1 section 4.2 instead: typed data `OpenEntityObject` with `objectType` `receipt/1` (a receipt has no `type`), `canonicalHash` the SHA-256 of the JCS form of the receipt without `proof` and `proofs`, and `created`; the proof is `EthereumEip712Signature2021` with `verificationMethod` `<did>#blockchainAccountId`, labelled by `by` like any other. The merchant's proof is outside the hash, so a wallet signs a receipt the merchant already signed and the two proofs may come in either order. Vectors: `test-vectors/receipt-1/pkh.json`.

```json
{ "version": "receipt/1", "receipt_id": "rc_<26 base32>", "kind": "purchase", "refers_to": null,
  "merchant_did": "...", "agent_did": "...", "mandate_id": "md_...", "mandate_hash": "<hex of the mandate digest>",
  "cart_digest": "<hex>", "approval_request_id": null, "total": 2500, "currency": "USD", "rail": "x402",
  "settlement_ref": "0x<tx> | pi_... | ord_...", "created_at": 1794009700,
  "proofs": [ { "by": "merchant", "type": "DataIntegrityProof", "...": "..." }, { "by": "agent", "...": "..." } ] }
```

- `kind` is `purchase`, `refund` or `chargeback`. A refund or chargeback is a new receipt whose `refers_to` is the purchase's `receipt_id`; a purchase has `refers_to: null`. Its `total` is the amount refunded or charged back.
- `mandate_id` and `mandate_hash` are both set (the hex digest of section 2.1) or both null (a purchase approved per cart: `approval_request_id` then names the approval).
- `by` is `merchant` or `agent`, at most once each, and is not part of the signed proof configuration. `merchant_did` and `agent_did` differ. A proof counts only when its verification method is the DID the receipt names for that party. A did:web merchant passes its own verification method when signing.
- `verifyReceiptChain(purchase, later)` checks a purchase with its refunds and chargebacks: each `refers_to` the purchase, same merchant, agent, currency and rail, no repeated `receipt_id`, and their totals sum to at most the purchase total (`not_purchase`, `mismatch`, `over_refund`). A verifier that relies on refunds or reputation runs it next to `verifyReceipt`.
- Receipts are private by default. A receipt may be published as a Record entry (`OEIS-1` section 7) when both parties consent; this is the input for proof-of-payment reputation (`OEIS-1` section 8.5) and replaces Moltbot Den's `transaction_review` as the input for reviews.
- A verifier states who must have signed (`verifyReceipt`'s `require`, default the merchant). A missing required proof is `missing_proof`; a proof that does not verify is `bad_proof`; a proof by the wrong DID is `wrong_signer`.

## 5. Merchant profile and claim types

### 5.1 `openentity:merchant` (Entity Document extension)

```json
{ "legal_name": "...", "jurisdiction": "US-DE", "mcc": ["5734"], "refund_policy": "https://...",
  "rails": ["card", "x402"], "x402": { "pay_to": "0x..." },
  "agent_policy": { "min_level": 1, "require_owner": true, "require_mandate": true,
                    "min_security_band": "good", "accept_issuers": ["did:web:securemyagent.ai"] } }
```

`agent_policy` is the merchant-side twin of `openentity:trust_policy`: agents read it before attempting a purchase. `verifyAgentForCheckout` applies it (section 7). `min_security_band` ranks `poor`, `fair`, `good`, `strong`; a scanner publishes a mapping from its own `score_band` values onto these four, and an unranked band never meets a minimum.

### 5.2 Claim types

Registered in `claim-types.md` with schemas in `schemas/claims/`:

| Type | Issuer | Subject | Meaning |
|---|---|---|---|
| `custom:openentity:owner_verified` | account service, after a PSP or ID check | owner DID | A verified human or legal entity stands behind the owner, level `basic`, `id` or `kyb`. No personal data |
| `custom:openentity:merchant_verified` | account service or a partner PSP | merchant DID | The merchant passed business verification in a jurisdiction |
| `custom:clawgrc:merchant_reliability` | ClawGRC | merchant DID | Fulfilment and refund behaviour reported by distinct agents over a window |
| `custom:agentsecretstore:gateway_governed` | Agent Secret Store | agent DID | Already registered; Agent Secret Store starts issuing it with `connector_only_secrets` |

### 5.3 What stays private

Mandates and receipts are not registry objects (ADR 0009). The registry stays the bus for public trust data; a verifier checks mandates and receipts locally against key logs and DIDs.

## 6. Mapping to AP2 and Verifiable Intent

Texts re-read on 2026-11-14: AP2 v0.2 (ap2-protocol.org, FIDO Alliance; Checkout and Payment mandate pages in `google-agentic-commerce/AP2` `docs/ap2/`), Mastercard Verifiable Intent draft v0.1 (verifiableintent.dev), and the Web Bot Auth drafts (`draft-meunier-web-bot-auth-architecture-05`, 2026-03-02, superseded by `draft-meunier-webbotauth-httpsig-protocol-02`, 2026-08-18, now `draft-ietf-webbotauth-httpsig-protocol`). AP2 and Verifiable Intent are SD-JWT credential chains; this profile signs JCS JSON with owner key-log keys. The profile does not wrap or replace them: a mandate/1 states the same authority in the key-log trust model, and the optional `ap2.checkout_mandate_hash` ties the two when both exist. Field names below are those the AP2 pages show in their examples (the schema tables on those pages did not render when read; re-check before relying on a name).

| This profile | AP2 v0.2 | Verifiable Intent |
|---|---|---|
| mandate/1 (standing, open) | Open Checkout Mandate `mandate.checkout.open.1` and Open Payment Mandate `mandate.payment.open.1`: `constraints`, `cnf`, `iat`, `exp` | Layer 2 Intent: the user's constraints, bound to a holder key |
| `limits.per_tx_max` | `payment.amount_range` (`min`, `max`, `currency`) | amount bounds |
| `limits.total_max` | `payment.budget` (`max`, `currency`) | budget cap |
| `limits.period`, `limits.period_max` | `payment.agent_recurrence` (`frequency`, `max_occurrences`) is count-based; no amount-per-period constraint was found | recurrence terms |
| `scope.merchants` | `checkout.allowed_merchants` (`allowed`), `payment.allowed_payees` (`allowed`) | merchant allowlist |
| `scope.rails` | `payment.allowed_payment_instruments` (`allowed`) | none found |
| `scope.categories` | `checkout.line_items` (`acceptable_items`) is item-level | none found |
| `expires_at` | `exp` | credential expiry |
| `signature` by the owner approver key | SD-JWT ES256 signature; `cnf.jwk` names the holder key | issuer signature in the delegation chain |
| `status` URL | no revocation registry named (research/protocols-and-rails.md section 2.1) | none found |
| cart/1 and its approval/2.0 | Closed Checkout Mandate `mandate.checkout.1` (`checkout_hash` of the merchant-signed `checkout_jwt`) and Closed Payment Mandate `mandate.payment.1` (`payment_amount`, `payee`, `payment_instrument`) | Layer 3 Action |
| receipt/1 | none found | named by Mastercard as the dispute evidence record |
| agent request signature | AP2 does not solve agent identity; UCP and A2A supply it | binds issuer, user and agent through key confirmation claims |

Web Bot Auth: the agent's signed request is the `OEIS-1` section 11.2 profile (RFC 9421, Ed25519, `keyid` the agent's `did:key`), and the key directory entry in section 11.2 makes the same key verifiable as a Web Bot Auth agent. The `Signature-Agent` header of the Web Bot Auth drafts carries in-band key discovery; this profile does not require it, and a merchant that already verifies Web Bot Auth reads the same `keyid`. Visa Trusted Agent Protocol and Mastercard Agent Pay headers ride beside the signature unchanged.

## 7. The checkout check

`verifyAgentForCheckout({request | agentDid, cart, merchantPolicy, agent, mandate, keyLog, status, approval | quorum})` returns `allow`, `step_up` or `deny` with ordered reasons and evidence. It is the helper behind Agent Commerce Check.

1. `deny`: `bad_cart`; `request_unverified` (no agent, or the request signature fails); `agent_mismatch` (the cart names another agent).
2. `deny`: the mandate fails verification (`mandate_<error>` of section 2.3) or does not apply (`mandate_wrong_agent`, `mandate_wrong_mandate`, `mandate_wrong_currency`, `mandate_bad_cart`); `no_key_log` when a mandate arrives without its owner's key log.
3. `deny`, every unmet policy reason listed together: `level_too_low`, `security_band_too_low`, `issuer_not_accepted`, `mandate_required`, `owner_unknown`. Facts about the agent (`level`, `owner_did`, `security_band`, `security_issuer`) come from the verifier's own registry lookup, never from the request.
4. `allow` (`mandate_covers_cart`): the mandate covers the cart and it is at or under `step_up_over`.
5. Otherwise the owner must approve this exact cart: a mandate that is `over_limit` or `out_of_scope` for the cart (`mandate_over_limit`, `mandate_out_of_scope`), a cart above `step_up_over` (`step_up_over`), or no mandate (`no_mandate`). A valid approval/2.0 with decision `approve` over `cartDigest(cart)`, naming the merchant as `verifier_did`, gives `allow` with `owner_approved_cart` first. Without one the answer is `step_up`, and a refused approval's error is in `evidence.approval_error`. An approval is one owner decision on one cart: it can exceed a mandate's limits, and it is never a mandate.

`approval.counter` is the WebAuthn counter the merchant stored for the approving key; a returned allow carries `evidence.approval_kid` and `evidence.approval_counter` to store. The merchant still consumes `request_id` atomically with the decision: an approval is replayable inside its window otherwise.

`deny` is final for this request. `step_up` tells the agent to ask its owner to approve the cart and retry.

## 8. Organisations and quorum approvals

An organisation is an owner. Its DID is an ordinary owner DID (`did:web:account.openentity.org:o:<id>`) with an ordinary key log (ADR 0007), so a product or merchant that verifies an owner verifies an org with no change: `issuer_did` of a mandate and `owner_did` of an approval/2.0 are the org's DID, and the approvers in its key log are member devices. Members, roles (admin, approver, viewer), teams, cost centres and budgets are the account service's access control and bookkeeping; what a verifier checks is only the key log, the mandate and the approvals.

**Budgets are mandates.** The org signs a mandate/1 per agent with a device in the org's key log. A budget for the whole org, a team or one agent is the ceiling those mandates must sit inside (per-transaction cap, per-day rate of the period cap, step-up threshold, rails, merchants); it is not a pooled counter. Spend accounting stays with the enforcing product (section 2).

**Quorum.** An org-owned approval of a cart is a bundle `approvals[]` of approval/2.0 objects, one per device, all with the same `verifier_did`, `request_id` and `payload_digest` (`cartDigest` of the cart), `owner_did` the org's DID. The merchant accepts it when `verifyQuorum(approvals, {keyLog, verifierDid, ownerDid, requestId, payloadDigest, m, of})` succeeds:

1. `m` is 1 or more and at most the number of kids in `of`; the bundle holds 1 to `len(of)` approvals;
2. every approval's `device_id` is in `of` and no device appears twice (`not_in_quorum`, `duplicate_device`);
3. every approval verifies as approval/2.0 with decision `approve` against the org's key log (the approval/2.0 rules apply unchanged: verifier, owner, request, payload, expiry of at most 600 seconds, WebAuthn counters);
4. at least `m` approvals remain.

It fails closed: one bad approval refuses the bundle, so a client cannot pad it, and a deny in the bundle is `bad_decision`. `m` and `of` are the org's quorum policy, published by the org's account service as `GET /o/<id>/policy` (`{org_did, state, quorum: {m, of}, seq, generated_at}`, RFC 9421 response signature by the service key like `GET /v1/paused`, `max-age` 30). `of` lists one registered device per member who is an admin or approver and whose device is still a current approver in the org key log. Devices are not people: the key log alone cannot tell one member's two devices apart, so the policy list, not the log, is what makes `m` devices `m` members. A merchant that cannot read the policy cannot enforce more than the log: it treats the org as an owner whose every approver counts.

`verifyAgentForCheckout` takes `quorum: {approvals, m, of, verifierDid, requestId, counters}` in place of `approval` and returns `evidence.approval_kids` and `evidence.approval_counters` to store. The approvals expire at most 600 seconds after signing, so the bundle must reach the merchant inside that window.

**Pause.** The org's pause pauses every agent of the org with the pause of ADR 0007 (`agent.paused` to every product, the signed feed, mandates revoked). `policy.state` is `paused` while it lasts.

## 9. Security considerations

- **Replay across objects.** Mandates and approvals have distinct digest prefixes; a signature never verifies as the other. Receipts are signed with the Data Integrity suite, a different construction again.
- **Replay of an approval.** Approval/2.0's rules apply unchanged: the verifier issues `request_id` per cart state and consumes it with the decision; the payload digest is recomputed from the cart the merchant is about to settle.
- **Replay of a mandate.** A mandate is meant to be reused until it expires, so replay protection is the request signature (nonce, short expiry) and `agent_did`: a stolen mandate is useless to any other agent.
- **Forged receipts.** A proof counts only for the DID the receipt names for that party, and `mandate_hash` ties the receipt to the exact signed mandate.
- **Owner bypass.** Only a current approver of `issuer_did` can sign a mandate; the pause of ADR 0007 revokes through `status`. A mandate does not widen what an owner could already spend; widening one needs a new signature.
- **Quorum padding and replay.** A quorum counts devices from the policy list, each once; the merchant consumes `request_id` with the decision, and an approval over one cart or request counts for no other (vectors `quorum-1`). A device added to the key log but not registered by a member is not in `of`: an approver key in the log can add keys, which is why the policy list, and not the log, sets who counts.
- **Limits are integer minor units** in one currency per mandate; cross-currency conversion is out of scope for version 1.
- **Cache.** A status answer older than 60 seconds is not an answer.
