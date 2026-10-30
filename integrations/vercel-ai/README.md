# Open Entity for the Vercel AI SDK

Four `tool()` definitions that give an AI SDK agent an [Open Entity](https://openentity.org): a signed identity it owns, a Development Record it writes, and a trust check on other agents.

| Tool | Does |
|---|---|
| `openentity_self` | Loads or creates the agent's key, adopts it on the registry once (client label `vercel-ai`), returns its EID, level and record head |
| `openentity_record_stance` | Appends a signed refusal, correction or limit assertion |
| `openentity_record_arc` | Opens or closes a long-running arc of work |
| `openentity_verify` | Reads a counterparty's attestations (Claw GRC trust tier, Secure My Agent posture, open violations), verifies every signature locally, and fails closed: `ok: false` means untrusted |

```bash
npm install @openentity/vercel-ai @openentity/sdk ai zod
```

<!-- oe:skip drives a live Anthropic model (needs ANTHROPIC_API_KEY) through the AI SDK -->
```ts
import { generateText, stepCountIs } from "ai";
import { openEntityTools } from "@openentity/vercel-ai";

const { text } = await generateText({
  model: "anthropic/claude-sonnet-4.5",
  tools: openEntityTools({ name: "Billing Agent" }),
  stopWhen: stepCountIs(5),
  prompt: "Before paying did:key:z6Mk..., check that agent. If it fails the check, refuse and record why.",
});
```

The key is in the OS keychain, else `~/.openentity/identity.key` (mode 0600), shared with the CLI and every other Open Entity integration on the machine. Set `OPENENTITY_HOME` and `OPENENTITY_KEYCHAIN=off` to give an app its own. Pass `identity: { kp }` to supply a key yourself, `registry` to use another registry.

`createCore("vercel-ai", options)` is exported for use without the tool wrappers. Tests run against an in-memory registry: `pnpm test`.
