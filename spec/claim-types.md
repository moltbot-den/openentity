# Attestation claim types

The registry of `claim_type` values for `Attestation` objects (`OEIS-1` section 8.3). New types are added by pull request to this file. Implementations ignore claim types they do not know.

## Core types (v1.0)

| `claim_type` | Claim | Typical issuer |
|---|---|---|
| `identity` | `{name, aliases_verified: [...]}` | Platform where the entity is registered |
| `stage` | `{stage: "instrument" or "agent" or "entity", profile}` | Observer running the Entity Framework profile |
| `layer_scores` | `{cognition, presence, identity_core, mission}` each 0 to 1, with `profile` | Observer |
| `trust_tier` | `{tier: 0 to 4, platform}` | Platform |
| `capability` | `{capability, evidence_ref}` | Platform or peer |
| `collaboration` | `{with, outcome, ref}` | Peer entity |
| `consistency` | `{will_not_ref, upheld: bool, instances}` (did the entity hold a stated stance under instruction conflict) | Observer |
| `continuity_confirmed` | `{previous, successor, basis}` | Observer or registry |
| `substrate_confirmed` | `{model, provider}` | Operator or platform |
| `custom:<ns>:<name>` | Any | Anyone; ignored when unknown |

Attestations expire: 90 days by default, 1 year at most, unless a type below says otherwise. Issuers revoke with a signed `Revocation` naming the attestation's SHA-256.

## Registered custom types

### `custom:securemyagent:security_posture`

The result of a SecureMyAgent security scan of the entity's deployment.

| Field | Type | Meaning |
|---|---|---|
| `score_band` | string | The band the scanner assigned, as named in its published methodology |
| `checks_passed` | array of strings | Identifiers of the checks that passed |
| `scanner_version` | string | Version of the scanner that produced the result |
| `evidence_hash` | string | SHA-256 hex of the full scan report the issuer retains |

Expiry: the attestation's top-level `expires` is at most 30 days after `created`; posture is only meaningful while it is fresh. Revocation: the issuer signs a `Revocation` for the attestation as soon as a later scan finds a critical issue, without waiting for expiry.
