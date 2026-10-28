---
title: ClawGRC
description: What ClawGRC is for, the compliance and violation claim types it issues as an Open Entity issuer, and how to check its attestations.
---

[ClawGRC](https://clawgrc.com) is governance, risk and compliance for the operator: it maps how an agent is deployed to frameworks and keeps the evidence, which is how an operator answers for the agent it runs.

## Status

ClawGRC is an Open Entity issuer. It keys its agent records by the agent's EID, assesses the agent's deployment, and submits signed attestations to the registry as `did:web:api.clawgrc.com`. Its first production attestation, a `custom:clawgrc:compliance` result for an assessed agent, is in the transparency log. Its DID document and issuer metadata, including its methodology, are at `https://api.clawgrc.com/.well-known/did.json` and `https://api.clawgrc.com/.well-known/openentity.json`.

ClawGRC is a `bootstrap` observer until it meets the accreditation rules in [For issuers and observers](/guides/issuers).

## Claim types it issues

Both claim types are written down in [the claim types file](https://github.com/moltbot-den/openentity/blob/main/spec/claim-types.md), so an assessor and a verifier read them the same way:

- `custom:clawgrc:compliance`: the result of an assessment of the entity's deployment against a published framework, with the framework and version, the controls passed and in scope, a score as defined in the issuer's methodology and a hash of the retained evidence. It expires within ninety days, and the issuer revokes it when a later assessment fails a control the earlier one passed.
- `custom:clawgrc:violation`: a recorded breach of a stated commitment or policy, with the policy, a severity, an evidence hash and when it was observed. Negative claims carry a higher bar, expire after a year, and the subject may answer with a signed Dispute ([Disputes](/guides/disputes)). There is no global score: every verifier weighs violations, issuers and disputes itself.

These definitions are usable by anyone. Another assessor can issue them too.

## What this means for you

If you run agents and use ClawGRC, an assessment can now show up on your agent's EID as a compliance attestation that any verifier can check. Adoption does not depend on it and it does not change your level by itself. To read it, list your entity's attestations in the registry and check the proof against ClawGRC's DID document.
