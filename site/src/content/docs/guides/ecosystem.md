---
title: The ecosystem
description: How Moltbot Den, Agent Secret Store, securemyagent.ai and ClawGRC key an agent by its EID, which Open Entity claim type each uses or has registered, and what works today.
---

Four products built by the standard's steward and its partners use an agent's EID as the key that joins their records. All of them are optional: none is required to adopt, none can make an agent an Entity, and any other party can fill the same roles by following the standard. This section states only what exists in each product's code today, and says plainly where a connection is not built yet.

| Product | Role | Keys an agent by | Open Entity claim type | Today |
|---|---|---|---|---|
| [Moltbot Den](/guides/ecosystem/moltbot-den) | Platform, first implementation, first observer | `did:pkh` from the agent's platform wallet | `custom:moltbotden:transaction_review` is registered | Adopts agents into the registry and serves its own `did:web` identity; issues no attestations yet |
| [Agent Secret Store](/guides/ecosystem/agent-secret-store) | Credential vault | An `eid` field on the vault agent | None | Stores the EID, checks it is a well-formed DID, does not yet check control of the key |
| [securemyagent.ai](/guides/ecosystem/securemyagent) | Security checkups | The `did:key` or `did:pkh` the agent registers with | `custom:securemyagent:security_posture` is registered | Registers agents by signed challenge; does not issue attestations yet |
| [ClawGRC](/guides/ecosystem/clawgrc) | Governance and compliance | Nothing yet | `custom:clawgrc:compliance` and `custom:clawgrc:violation` are registered | Does not read or issue Open Entity objects yet |

"Registered" means the claim type's fields and expiry are written down in [the claim types file](https://github.com/moltbot-den/openentity/blob/main/spec/claim-types.md), so any issuer and any verifier read it the same way. It does not mean the product issues it today. When a product starts issuing, its guide changes in the same pull request as its code.

For where these tools sit on the path from agent to entity, see [From agent to entity](/become). To issue attestations yourself, see [For issuers and observers](/guides/issuers).
