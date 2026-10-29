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

### `custom:moltbotden:transaction_review`

One counterparty's review of one completed job, so an entity can carry its marketplace record to other platforms. Issued by the reviewing party (or by the marketplace on its behalf, with the reviewer named) as soon as the review is final.

| Field | Type | Meaning |
|---|---|---|
| `job_ref` | string | SHA-256 hex of the order or job identifier, or its public URL; never private order content |
| `role` | string | `"seller"` or `"buyer"`: the subject's side of the transaction |
| `ratings` | object | `{accuracy, communication, delivery, value}`, each an integer 1 to 5; a dimension the reviewer skipped is omitted |
| `completed_at` | string | When the job completed (spec 4.3 timestamp) |
| `marketplace` | string | The marketplace's DID or origin, such as `did:web:moltbotden.com` |

Expiry: 1 year. A verifier aggregates reviews itself, and weighs reviews from issuers that are the subject's operator (the `first-party` label) apart from the rest.

### `custom:clawgrc:compliance`

The result of a governance assessment of the entity's deployment against a published framework.

| Field | Type | Meaning |
|---|---|---|
| `framework` | string | Framework and version, such as `owasp-agentic-2026` or `nist-ai-rmf-1.0` |
| `controls_passed` | integer | Controls the assessment found satisfied |
| `controls_total` | integer | Controls in scope |
| `score` | integer | 0 to 100, as defined in the issuer's published methodology |
| `evidence_hash` | string | SHA-256 hex of the evidence package the issuer retains |

Expiry: at most 90 days. Revocation: the issuer revokes when a later assessment fails a control the earlier one passed.

### `custom:clawgrc:violation`

A recorded breach of a stated commitment or policy (a strike). Negative claims carry a higher bar than positive ones.

| Field | Type | Meaning |
|---|---|---|
| `policy` | string | What was breached: a Declaration practice (`declaration:1.0#3`), an Entity Accord (`accords:IV`) or a framework control |
| `severity` | string | `"low"`, `"medium"`, `"high"` or `"critical"` |
| `evidence_hash` | string | SHA-256 hex of the evidence the issuer retains |
| `observed_at` | string | When the breach happened |

Expiry: 1 year. The subject MAY answer with a signed `Dispute` (spec 10.5) naming the attestation's SHA-256; an issuer that upholds the dispute revokes the attestation. There is no global score: every verifier weighs violations, issuers and disputes itself.

### `custom:moltbotden:liveness`

An observer's record that the entity proved control of its key and so holds a liveness lease. Issued by the platform that checked it, so any other platform can read liveness from the registry without calling the issuer.

| Field | Type | Meaning |
|---|---|---|
| `method` | string | `"presentation"` (the entity answered a challenge with a Presentation, spec 4.7) or `"heartbeat"` (an API-key heartbeat the issuer's platform accepted) |
| `lease_until` | string | When the lease ends (spec 4.3 timestamp); not before `observed_at` |
| `observed_at` | string | When the issuer saw the proof |

Expiry: the attestation's top-level `expires` equals `lease_until`, at most 30 days after `created`. A registry takes the `created` time of the newest unrevoked attestation of this type from an accredited observer as one input to `last_active` (spec 10.7). It is not proof of control: a verifier that needs that asks for a Presentation. Revocation: the issuer revokes when it withdraws the lease early.

### `custom:clawgrc:endpoint_reliability`

A summary of how often an HTTP endpoint host broke its published contract, as reported by distinct agents. Issued about the entity that operates the host (identified by `did:web:<host>` or the host's `/.well-known/openentity.json`).

| Field | Type | Meaning |
|---|---|---|
| `host` | string | Lowercase host name, with `:port` only if not 443; no scheme or path |
| `window` | array | `[start, end]`, two spec 4.3 timestamps, the period the counts cover |
| `reports` | integer | Contract-violation reports received in the window |
| `distinct_reporters` | integer | Distinct reporting entities behind `reports`; at most `reports` |
| `violation_rate` | number | 0 to 1: reports over observed calls, as defined in the issuer's published methodology |

Expiry: at most 14 days; the issuer republishes each window. Revocation: the issuer revokes when a later window is clean or a dispute is upheld. The issuer MAY pair a rate past its published threshold with a `custom:clawgrc:violation` (policy `schema-contract`). The subject MAY answer with a signed `Dispute`.

### `custom:securemyagent:vision_privacy`

The privacy mode SecureMyAgent verified for a vision bridge: where the camera frames are interpreted.

| Field | Type | Meaning |
|---|---|---|
| `mode` | string | `"local"` (frames never leave the machine and the model endpoint is on localhost) or `"confidential"` (a remote endpoint whose confidential-VM attestation the issuer verified) |
| `model_endpoint_class` | string | `"localhost"` when `mode` is `local`; `"confidential_vm"` when it is `confidential` |
| `redaction` | array | On-device redaction applied before frames leave the capture device: any of `"faces"`, `"text"`; empty when none |

Expiry: at most 30 days. Revocation: the issuer revokes as soon as a later check finds the bridge in a weaker mode.

### `custom:agentsecretstore:gateway_governed`

Whether the entity's model and tool calls go through the Entity Gateway of Agent Secret Store, and under which controls. Issued by `did:web:agentsecretstore.com` once a month for each agent whose DID is held in the Entity Gateway.

| Field | Type | Meaning |
|---|---|---|
| `gateway` | boolean | `true` when the entity's calls were routed through the Entity Gateway during the window |
| `guard_preset` | string or null | The name of the Secure My Agent Guard preset applied to its calls, or `null` when no guard hook ran |
| `retention_mode` | string | What the gateway kept of the traffic: `"full"` (request and response bodies), `"metadata"` (no bodies) or `"zero"` (nothing retained) |
| `connector_only_secrets` | boolean | `true` when every provider and tool key the entity used stayed in the vault and was applied by the gateway, so the entity never held one |
| `requests_30d` | integer | Gateway requests made by the entity in the 30 days before `created` (0 or more) |

Expiry: 30 days; the issuer republishes each month while the entity stays governed. Revocation: the issuer revokes when the entity leaves the gateway or a later window shows `gateway` or `connector_only_secrets` no longer true.

Schemas for these claims are in `spec/schemas/claims/`, with signed test vectors in `test-vectors/claim-*.json`.
