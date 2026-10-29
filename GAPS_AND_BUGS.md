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

### G-2026-002 [open] P2 feature

- file: spec/claim-types.md
- area: Entity Gateway
- discovered: 2026-10-28 by entity-gateway plan
- summary: Entity Gateway phase 6.2: claim schema for custom:agentsecretstore:gateway_governed
- owner-agent: openentity
- reviewer-agent: security
- suggested-fix: Plan and protocol: docs/entity-gateway-plan.md and docs/adr/0005-entity-gateway.md in One-Frequency/oneentity.
- linked-pr: (none yet)
- linked-issue: (none yet)
