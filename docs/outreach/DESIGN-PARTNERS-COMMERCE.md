# Design partner outreach: agent commerce trust layer (C7.3)

Status: DRAFT for Will to send. Nothing here has been sent. Date drafted 2026-11-15. Source of the target list and the market facts: `docs/commerce/research/market-and-players.md` and `docs/commerce/STRATEGY.md` in the oneentity meta repo.

The ask is small and the same for every target: run Agent Commerce Check in observe mode on their agent traffic for two weeks and tell us where the decisions are wrong. We want three to five partners, one from each group. Success is a partner who names a real purchase flow where `allow`, `step_up` or `deny` changed what they did.

## What is true today (check before sending)

Every claim below is live or in the repository on 2026-11-15; re-check the last four before you send.

- Agent Commerce Check is a free hosted endpoint, `POST https://openentity.org/v1/commerce/check`, no key, no login: https://openentity.org/guides/commerce-check
- The Commerce Profile defines `mandate/1` (an owner's signed, bounded permission), `cart/1` and `receipt/1`, with test vectors and verifiers in TypeScript, Python, Kotlin and Swift: https://github.com/moltbot-den/openentity/blob/main/spec/commerce-profile.md
- It maps to AP2 v0.2 and Mastercard Verifiable Intent field by field (section 6) and reads the same RFC 9421 signature Web Bot Auth reads.
- Moltbot Den, an open agent marketplace, runs the check on each agent purchase in observe mode, signs a `receipt/1` on every settled order on four rails (credits, card, x402, MPP) and enforces owner spend limits over every way an agent spends.
- Agent Secret Store lets an agent pay through a connector without ever holding the key or card.

## One core note (adapt the second paragraph per group)

Subject: Verify the agent before you take its money: a free check, and a request for your hardest cases

Hello [name],

I run Open Entity, the open standard and registry for AI agent identity (spec and text CC0, code MIT). We have extended it to the moment an agent pays.

When an agent reaches your checkout, three questions have no shared answer today: which agent is this, who is accountable for it, and did its owner allow this exact purchase. Agent Commerce Check answers them in one call and returns allow, step_up or deny with reasons and a hash-chained evidence record you can keep for disputes. It is free, needs no key, and works beside Web Bot Auth, AP2 and Verifiable Intent rather than replacing them: a mandate is a signed JSON object from the owner's device that any merchant checks offline.

[Group paragraph, below.]

What I would like: two weeks in observe mode on a slice of your agent traffic (the check logs what it would decide and blocks nothing), then thirty minutes on the decisions you disagree with. In return you get the evidence records, a direct line to the people who maintain the spec, and a say in the next version of the Commerce Profile. There is no contract, no fee and no exclusivity.

The guide is https://openentity.org/guides/commerce-check and the spec is linked from it. I am glad to run a first call against your sandbox myself.

Will
Open Entity, identity@openentity.org

## Group paragraphs and targets

### Payment service providers (pick two)

Targets: Checkout.com (its survey of merchants is cited in our research), Adyen, Worldpay.

Paragraph: Your merchants will ask you how to tell a legitimate agent from a bot and who is liable when an agent buys the wrong thing. A mandate gives the merchant and you the same signed proof of what the owner allowed, and the receipt both sides sign is a record neither can rewrite. We would like to see whether the check can sit in front of your agentic checkout, and whether `mandate/1` can ride beside the network tokens you already receive.

### Agent platforms and wallets (pick two)

Targets: Skyfire (KYAPay), Nekuda (agentic mandates), Crossmint, Basis Theory (leads the Agentic Commerce Consortium), Catena Labs, Natural.

Paragraph: You already issue some form of agent identity or mandate. We are not asking you to replace it. A DID-keyed `mandate/1` states the same authority in a form any merchant verifies without calling you, and your tokens can carry its hash. We would like to test your agents against Agent Commerce Check, and to map your mandate fields to ours in the open so merchants see one shape.

### Marketplaces and directories (pick one)

Targets: an x402 service directory such as the Coinbase x402 Bazaar, Moltbot Den's own peers in the ERC-8004 directories, or a vertical marketplace that already sells to agents.

Paragraph: Sellers on your marketplace cannot tell a verified agent from a throwaway key. We would like to give your sellers an `agent_policy` they set per listing (minimum level, owner required, mandate required) and run the check for them. Moltbot Den is the working example: sellers set `agent_policy` per listing and read every decision at `GET /marketplace/sellers/me/agent-checks`.

## Follow-up after a yes

1. Send the sandbox call: `curl` of the deny example in the guide, then a signed request from a fresh agent (the independent-agent proof in `integrations/commerce-check/proof.mjs`).
2. Agree the slice of traffic and the two-week window in writing in the thread.
3. After two weeks, fetch each evidence record (`GET /v1/commerce/evidence/<id>`) and review disagreements together. Record every one in `GAPS_AND_BUGS.md`.
4. A partner who wants to be named is listed in `docs/commerce/PLAN.md`. Never list a partner without their written yes.

## Log

| Date | Target | Sent by | Reply |
| --- | --- | --- | --- |
| | | | |
