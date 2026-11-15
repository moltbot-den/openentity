# Standards notes: agent commerce (drafts)

Status: DRAFT for Will to send. Nothing here has been sent. Date drafted 2026-11-15. One note per body, each short, each with a concrete offer and one question. Facts about each body are from `docs/commerce/research/protocols-and-rails.md` (re-read 2026-11-14); recheck draft numbers and membership terms on the day you send.

Common facts to cite: the Commerce Profile is at https://github.com/moltbot-den/openentity/blob/main/spec/commerce-profile.md (CC0), test vectors in `test-vectors/{mandate-1,cart-1,receipt-1,checkout-1,quorum-1,http-signature.json}`, verifiers in TypeScript, Python, Kotlin and Swift. Agent Commerce Check is free at https://openentity.org/guides/commerce-check.

## 1. IETF webbotauth working group

Venue: the `webbotauth` mailing list; comment on `draft-ietf-webbotauth-httpsig-protocol` (adopted as a working-group document from `draft-meunier-webbotauth-httpsig-protocol-02`). Subscribe before posting; the list expects a participant.

Subject: Comment on the HTTP message signatures draft: a DID-to-key binding in production, and test vectors to share

Hello,

I maintain the Open Entity Identity Standard (OEIS-1, CC0). Section 11.2 profiles RFC 9421 for agents: Ed25519, `keyid` is the agent's `did:key`, the signature covers `@method`, `@target-uri` and `content-digest`, and the key is published in a key directory so a verifier that already reads Web Bot Auth reads the same key. A merchant uses it in production to bind a signed purchase request to a registry entry and to an owner's signed mandate.

Two things I would like to offer. First, a set of test vectors for the signed request (`test-vectors/http-signature.json`) that include the failure cases we found in practice: a signature made for another host, a replayed nonce and a `keyid` that does not match the cart's agent. Second, our experience with the `Signature-Agent` header: we do not require it, because the `keyid` carries the discovery we need, and I would like to know whether the group expects it for commerce.

Question: is the group's intent that the `keyid` can be a DID URL, so that the same key serves identity, mandates and receipts, or should a commerce profile register its own key-discovery rule?

## 2. FIDO Alliance (AP2 and Mastercard Verifiable Intent)

Venue: the FIDO Alliance agentic payments work (AP2 was contributed in April 2026). Membership may cost money; ask whether comments or a mapping note are accepted from non-members before paying anything.

Subject: Mapping note: mandate/1 and AP2 v0.2 / Verifiable Intent, and a revocation question

Hello,

We published a profile of our agent identity standard that carries an owner's standing permission as `mandate/1`, signed by an approver key in the owner's key log, with a public `status` URL. Section 6 of the profile maps it to AP2 v0.2 open checkout and payment mandates and to Verifiable Intent Layer 2 field by field. It does not wrap or replace them: an optional `ap2.checkout_mandate_hash` ties the two when both exist.

Findings from writing the map that may help the specification: (1) the AP2 pages we read name no revocation mechanism for an open mandate, and a merchant that cannot reach the issuer has no way to learn a mandate was revoked; we use a status URL and a one-day rule for offline verifiers; (2) AP2 recurrence is count-based and we found no amount-per-period constraint, which is what owners ask for; we use `period` and `period_max`; (3) the agent's own identity is outside AP2, so we bind the request to an agent DID with RFC 9421.

Question: would the working group welcome a revocation and per-period constraint proposal, and in what form?

## 3. x402 Foundation (Linux Foundation)

Venue: the foundation's contact or working channel; membership may cost money, so do not join without Will's yes on the fee.

Subject: Agent Commerce Check as a trust extension for x402 merchants, and a facilitator-using reference merchant

Hello,

Moltbot Den accepts x402 payments on its marketplace and in pay-and-call, and signs a `receipt/1` that names the settlement transaction as its `settlement_ref`. We built Agent Commerce Check so that an x402 merchant can verify who is paying and whether the owner allowed it before it asks the facilitator to settle: one call, free, allow, step_up or deny with evidence. It does not change the x402 wire format.

I would like to list Moltbot Den as a merchant that uses a facilitator and to describe Agent Commerce Check as an optional trust extension in the ecosystem material, if the foundation keeps such a list. I would also like to know whether the foundation wants a standard place for an agent's identity and mandate in the payment payload, or prefers to leave it to headers.

## 4. UCP (Universal Commerce Protocol)

Venue: the UCP specification repository and its working group channel for the identity linking extension point.

Subject: Proposal: an Open Entity agent identity method for the UCP identity extension

Hello,

UCP lets a business accept any `UCP-Agent` profile URI, so identity is negotiated rather than enforced. Moltbot Den's `/.well-known/ucp` follows the 2026-08-25 version, serves REST checkout and signs its order webhooks with a key tied to its own Open Entity DID (`did:web:moltbotden.com`), so one DID already identifies the business side. We propose registering an agent identity method whose proof is an RFC 9421 signature by the key behind a DID, with the business resolving the DID against the Open Entity registry and checking a mandate in the `OE-Mandate` header.

What we can contribute: the method text, the verifier in two languages, a reference business that runs it, and test vectors.

Question: does the identity extension accept a method defined outside the core repository, and what conformance evidence do you ask for?

## Log

| Date | Body | Sent by | Reply |
| --- | --- | --- | --- |
