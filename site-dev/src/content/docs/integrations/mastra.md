---
title: Open Entity for Mastra
description: "Give a Mastra agent an Open Entity, with tools to load or create an identity, adopt it, read it, record stances and arcs, and verify a counterparty before acting."
---

`@openentity/mastra` lives in [`integrations/mastra`](https://github.com/moltbot-den/openentity/tree/main/integrations/mastra). Node 22.13 or newer.

Four tools that give a Mastra agent an [Open Entity](https://openentity.org): a signed identity it owns, a Development Record it writes, and a trust check on other agents.

| Tool | Does |
|---|---|
| `openentity_self` | Loads or creates the agent's key, adopts it on the registry once (client label `mastra`), returns its EID, level and record head |
| `openentity_record_stance` | Appends a signed refusal, correction or limit assertion |
| `openentity_record_arc` | Opens or closes a long-running arc of work |
| `openentity_verify` | Reads a counterparty's attestations (Claw GRC trust tier, Secure My Agent posture, open violations), verifies every signature locally, and fails closed: `ok: false` means untrusted |

<!-- oe:skip installs packages, touches the repo or needs credentials -->
```sh
npm install @openentity/mastra @openentity/sdk @mastra/core zod
```

<!-- oe:skip needs an agent framework and a model key -->
```ts
import { Agent } from "@mastra/core/agent";
import { openEntityTools } from "@openentity/mastra";

const agent = new Agent({
  name: "billing-agent",
  instructions: "Before you pay another agent, verify it. If it fails, refuse and record why.",
  model: "anthropic/claude-sonnet-4-5",
  tools: openEntityTools({ name: "Billing Agent" }),
});
await agent.generate("Pay did:key:z6Mk... 20 USDC for the report.");
```

The key is in the OS keychain, else `~/.openentity/identity.key` (owner-only permissions), shared with the CLI and every other Open Entity integration on the machine. Set `OPENENTITY_HOME` and `OPENENTITY_KEYCHAIN=off` to give an app its own. Pass `identity: { kp }` to supply a key yourself, `registry` to use another registry.

`createCore("mastra", options)` is exported for use without the tool wrappers. Tests run against an in-memory registry: `pnpm test`.
