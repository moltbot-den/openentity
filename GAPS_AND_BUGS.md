# Gaps & Bugs Tracker

Backlog for this repo. Ticket ids are `G-YYYY-NNN` across the Open Entity products; the schema matches Agent Secret Store, Secure My Agent and ClawGRC so one tool parses all of them.

## Schema

```
### G-YYYY-NNN [status] Pseverity category
- file: <path>
- area: <milestone / module>
- discovered: <YYYY-MM-DD> by <agent or process>
- summary: <one sentence>
- owner-agent: <name>
- reviewer-agent: <name>
- suggested-fix: <one paragraph>
- linked-pr: <url or (none yet)>
- linked-issue: <id or (none yet)>
```

`status` is one of open, in-progress, fixed, wontfix, partially-fixed. `severity` is P0 to P3. `category` is one of feature, docs, bug, tech-debt, security, cost, perf. Flip a ticket to `in-progress` when you start it and to `fixed` with `linked-pr` when it ships. New tickets take the next free number. Never delete entries.

---

### G-2026-001 [fixed] P1 feature

- file: sdk/ts/src/, sdk/python/openentity/
- area: Entity Gateway
- discovered: 2026-10-28 by entity-gateway plan
- summary: Entity Gateway phase 2.2: RFC 9421 HTTP message signature sign and verify helpers (ed25519, keyid = did:key, content-digest, created, expires, nonce) in @openentity/sdk and openentity
- owner-agent: openentity
- reviewer-agent: security
- suggested-fix: ADR 0003: products use the package, not a copy. Profile in ADR 0005. Plan and protocol: docs/entity-gateway-plan.md and docs/adr/0005-entity-gateway.md in One-Frequency/oneentity.
- linked-pr: https://github.com/moltbot-den/openentity/pull/97
- linked-issue: (none yet)

### G-2026-002 [fixed] P2 feature

- file: spec/claim-types.md
- area: Entity Gateway
- discovered: 2026-10-28 by entity-gateway plan
- summary: Entity Gateway phase 6.2: claim schema for custom:agentsecretstore:gateway_governed
- owner-agent: openentity
- reviewer-agent: security
- suggested-fix: Plan and protocol: docs/entity-gateway-plan.md and docs/adr/0005-entity-gateway.md in One-Frequency/oneentity.
- linked-pr: https://github.com/moltbot-den/openentity/pull/134
- linked-issue: (none yet)

### G-2026-003 [fixed] P1 feature

- file: spec/commerce-profile.md, test-vectors/mandate-1/, test-vectors/cart-1/, test-vectors/receipt-1/, test-vectors/checkout-1/, sdk/ts/src/commerce.ts, sdk/python/openentity/commerce.py
- area: Agentic commerce C1.1 to C1.3 (oneentity docs/commerce/PLAN.md)
- discovered: 2026-11-14 by agentic commerce program
- summary: The OEIS Commerce Profile (mandate/1, cart/1, receipt/1, merchant extension, three claim types) with its AP2 and Verifiable Intent mapping, test vectors, and verifyMandate, mandateCovers, signReceipt, verifyReceipt and verifyAgentForCheckout in the TypeScript and Python SDKs
- owner-agent: openentity
- reviewer-agent: security (adversarial review fixed in the same PR)
- suggested-fix: Land the profile in spec/, generate vectors from published throwaway keys, implement the verifiers once per SDK against the vectors. Swift and Kotlin follow in their own lanes (C1.3); the account service mandates API is C1.4. No package version changes: release is one batch at the end of the program.
- linked-pr: https://github.com/moltbot-den/openentity/pull/201
- linked-issue: (none yet)

### G-2026-004 [in-progress] P1 feature

- file: account/src/mandates.ts, account/src/stepup.ts, account/src/agents.ts, account/openapi.yaml, account/schema.sql
- area: Agentic commerce C1.4 (oneentity docs/commerce/PLAN.md)
- discovered: 2026-11-14 by agentic commerce program
- summary: Account service mandates: POST /v1/mandates/draft and /v1/mandates (owner-signed mandate/1 inside a held spend permission), GET ?agent=, DELETE, public GET /{id}/status (max-age 30), permission grammar spend<=$N/<period>@<pattern>:<rail>, agent.mandates push events, pause, unlink and permission narrowing revoke
- owner-agent: openentity
- reviewer-agent: security (adversarial review next)
- suggested-fix: Done in the PR. The mandate signature by an approver key is the owner's approval; widening spend is granting the spend permission, which already needs step-up agent.permissions.widen. Agents never write mandates: owner bearer only. Products enforce spend accounting; the service only answers active or revoked.
- linked-pr: https://github.com/moltbot-den/openentity/pull/203
- linked-issue: (none yet)

### G-2026-006 [fixed] P1 feature

- file: sdk/kotlin/src/main/kotlin/org/openentity/sdk/Commerce.kt, sdk/kotlin/src/test/kotlin/org/openentity/sdk/CommerceTest.kt
- area: Agentic commerce C1.3 Kotlin (oneentity docs/commerce/PLAN.md)
- discovered: 2026-11-14 by agentic commerce program
- summary: verifyMandate, mandateCovers, cartDigest, signReceipt, verifyReceipt, verifyReceiptChain and verifyAgentForCheckout in org.openentity:sdk, passing every mandate-1, cart-1, receipt-1 and checkout-1 vector. verifyAgentForCheckout takes the agent DID of an already verified request signature: RFC 9421 verification stays out of the Kotlin SDK.
- owner-agent: openentity
- reviewer-agent: security
- suggested-fix: Port sdk/ts/src/commerce.ts check for check against the shared vectors. No package version changes: release is one batch at the end of the program.
- linked-pr: https://github.com/moltbot-den/openentity/pull/204
||||||| parent of 8df61ca (feat(sdk): Swift commerce profile: verifyMandate, mandateCovers, signReceipt, verifyReceipt, verifyAgentForCheckout (C1.3))

### G-2026-005 [in-progress] P1 feature

- file: sdk/swift/Sources/OpenEntityKit/Commerce.swift, sdk/swift/Tests/OpenEntityKitTests/CommerceTests.swift, sdk/swift/README.md
- area: Agentic commerce C1.3 Swift (oneentity docs/commerce/PLAN.md)
- discovered: 2026-11-14 by agentic commerce program
- summary: OpenEntityKit gets verifyMandate, mandateCovers, signReceipt, verifyReceipt and verifyAgentForCheckout (plus cartDigest, mandateDigest, receiptError), passing every vector in test-vectors/mandate-1, cart-1, receipt-1 and checkout-1 with the TS and Python results
- owner-agent: openentity
- reviewer-agent: security (adversarial review before merge)
- suggested-fix: Port sdk/ts/src/commerce.ts check for check on the existing Owner.swift primitives. No RFC 9421 request verification (the caller passes the verified agentDid) and no verifyReceiptChain. No package version changes: OpenEntityKit is consumed by path.
- linked-pr: https://github.com/moltbot-den/openentity/pull/205
- linked-issue: (none yet)

### G-2026-040 [in-progress] P3 feature

- file: mcp/smithery.yaml
- area: Agentic commerce C4.4 (docs/commerce/PLAN.md in the oneentity meta repo)
- discovered: 2026-11-14 by agentic commerce program
- summary: The hosted MCP server has no Smithery manifest, so it cannot be listed on Smithery.
- owner-agent: c4-den
- reviewer-agent: adversarial-review
- suggested-fix: smithery.yaml (target remote, URL, config schema for the API key header); publish with the command in its header after `smithery auth login`.
- linked-pr: (none yet)
- linked-issue: (none yet)
