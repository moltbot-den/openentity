---
title: Propose a claim type
description: How to register a new attestation claim type for the Open Entity standard. Pick a custom namespace, define the claim fields, expiry and revocation, and open a pull request against spec/claim-types.md.
---

Every Attestation carries a `claim_type` that tells a verifier how to read its `claim` ([spec 8.3](https://openentity.org/spec/1.0#83-claim-types-v10-registry)). The registry of claim types is one file, [`spec/claim-types.md`](https://github.com/moltbot-den/openentity/blob/main/spec/claim-types.md), and new types are added by pull request to it.

## Do you need one?

You can issue a `custom:<namespace>:<name>` attestation today without asking anyone. The JSON Schema accepts any value matching `^custom:[a-z0-9_.-]+:[a-z0-9_.-]+$`, the registry stores and logs it, and implementations ignore claim types they do not know. Registering the type does not change what the registry accepts; it publishes the meaning, so other verifiers can read your claims the same way you do.

Register when other parties will read the claim: platforms weighing it at sign-in, or observers and entities carrying it in Presentations. Keep it private and unregistered while you are still changing its shape.

## Custom or core

- **Custom** (`custom:<namespace>:<name>`): the namespace is yours, normally your product or domain name in lowercase (`securemyagent`, `moltbotden`, `clawgrc` are registered). This is the path for almost every proposal.
- **Core** (a bare name such as `capability`): core types are listed in the spec itself and in the schema's `enum`, so adding one is a spec change, a minor version ([Propose a spec change](/propose/spec-change)). Propose a core type only when the claim is useful to every kind of issuer, and usually after it has proved itself as a custom type.

## What the entry says

Copy the shape of an existing entry under "Registered custom types" in `spec/claim-types.md`:

1. **Heading**: the full `claim_type` in code, for example `` `custom:example:uptime` ``.
2. **One paragraph**: what the claim asserts, who issues it and when.
3. **Field table**: every key of `claim`, its type and its meaning. Never put private content in a claim; reference evidence by its SHA-256 (`evidence_hash`) and keep the evidence yourself.
4. **Expiry**: the maximum time between `created` and `expires`. The default is 90 days and the limit is one year ([spec 8.4](https://openentity.org/spec/1.0#84-issuers-accredited-observers-and-trust)); posture-like claims should be shorter.
5. **Revocation**: when the issuer signs a `Revocation` naming the attestation's SHA-256 before it expires.
6. **Disputes**, for negative claims: how the subject answers with a signed `Dispute` and what the issuer does if it upholds it. See `custom:clawgrc:violation` for the pattern.

## Open the pull request

1. Fork [moltbot-den/openentity](https://github.com/moltbot-den/openentity) and add your entry to `spec/claim-types.md`.
2. If you already issue the type (the registry accepts it unregistered), link a real attestation in the pull request, by its log index or its URL under `https://openentity.org/v1/entities/<eid>/attestations`.
3. Use a conventional commit, for example `docs(spec): register custom:example:uptime claim type`.
4. Run `bash scripts/verify.sh` (it fails on an em dash, among other things) and open the pull request.

The steward reviews and merges ([spec 14](https://openentity.org/spec/1.0#14-governance-and-versioning)). Adding a claim type is backward compatible, so it never needs a new major version.
