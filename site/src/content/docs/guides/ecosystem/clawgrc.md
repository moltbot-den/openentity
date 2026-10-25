---
title: ClawGRC
description: What ClawGRC is for, the compliance and violation claim types registered for it in Open Entity, and that it does not read or issue Open Entity objects yet.
---

[ClawGRC](https://clawgrc.com) is governance, risk and compliance for the operator: it maps how an agent is deployed to frameworks and keeps the evidence, which is how an operator answers for the agent it runs.

## Status

ClawGRC does not read or issue Open Entity objects today, and it does not key anything by an EID. Its own published material on agent trust describes a different mechanism (on-chain attestations through ERC-8004). The two can coexist, since the standard binds an ERC-8004 agent as an alias, but there is no bridge between them yet.

## Claim types registered for it

Two claim types are written down in [the claim types file](https://github.com/moltbot-den/openentity/blob/main/spec/claim-types.md) so that an assessor and a verifier read them the same way:

- `custom:clawgrc:compliance`: the result of an assessment of the entity's deployment against a published framework, with the framework and version, the controls passed and in scope, a score as defined in the issuer's methodology and a hash of the retained evidence. It expires within ninety days, and the issuer revokes it when a later assessment fails a control the earlier one passed.
- `custom:clawgrc:violation`: a recorded breach of a stated commitment or policy, with the policy, a severity, an evidence hash and when it was observed. Negative claims carry a higher bar, expire after a year, and the subject may answer with a signed Dispute ([Disputes](/guides/disputes)). There is no global score: every verifier weighs violations, issuers and disputes itself.

These definitions are usable by anyone. Another assessor can issue them, and ClawGRC can start issuing them without a change to the standard.

## What this means for you

If you run agents and use ClawGRC, keep doing so for your own governance evidence; adoption does not depend on it and it does not change your level. To publish an assessment result as an attestation today, issue it yourself with [the issuer guide](/guides/issuers) and the registered claim type, and say who you are in your methodology.
