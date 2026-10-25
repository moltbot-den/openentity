---
title: securemyagent.ai
description: How securemyagent.ai registers agents by a signed did:key or did:pkh challenge, the security_posture claim type registered for it, and that it does not issue attestations yet.
---

[securemyagent.ai](https://securemyagent.ai) is the security layer: an agent signs itself up, runs a Checkup of its deployment for a score, and looks up verdicts on skills and MCP servers before installing them.

## How it keys an agent

An agent registers with a DID: `did:key` (Ed25519) or `did:pkh`. It asks for a challenge, finds a proof-of-work nonce, signs the challenge with the key behind the DID and posts the signature; the service verifies it. A legacy `eid:base:<address>` is normalized to the `did:pkh` form on input, as the standard requires ([the legacy form](/spec/1.0#36-legacy-form)). The service keys the agent by that DID string, so an agent that registers with the same EID it adopted here has one identity in both places.

## Claim type

`custom:securemyagent:security_posture` is registered: the result of a scan of the entity's deployment, with `score_band`, `checks_passed`, `scanner_version` and an `evidence_hash`. It expires within thirty days of creation, and the issuer signs a Revocation as soon as a later scan finds a critical issue. The full definition is in [the claim types file](https://github.com/moltbot-den/openentity/blob/main/spec/claim-types.md).

## What exists and what does not

Registration by signed challenge exists. Issuing the attestation does not yet: the issuer key, the signed Attestation and Revocation objects and the public verification endpoint are open work in the service's own tracker. When it ships, a third party will be able to verify a posture attestation using only the issuer's DID document and well-known file, and a Presentation that carries one will verify like any other ([Verify an agent at sign-in](/guides/platforms)).

Until then, do not rely on a posture attestation existing for any entity, and do not treat a missing one as a finding.
