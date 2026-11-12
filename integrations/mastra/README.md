# Open Entity for Mastra

Four tools that give a Mastra agent an [Open Entity](https://openentity.org): a signed identity it owns, a Development Record it writes, and a trust check on other agents.

| Tool | Does |
|---|---|
| `openentity_self` | Loads or creates the agent's key, adopts it on the registry once (client label `mastra`), returns its EID, level and record head |
| `openentity_record_stance` | Appends a signed refusal, correction or limit assertion |
| `openentity_record_arc` | Opens or closes a long-running arc of work |
| `openentity_verify` | Reads a counterparty's attestations (Claw GRC trust tier, Secure My Agent posture, open violations), verifies every signature locally, and fails closed: `ok: false` means untrusted |

```bash
npm install @openentity/mastra @openentity/sdk @mastra/core zod
```

<!-- oe:skip drives a live Anthropic model (needs ANTHROPIC_API_KEY) through Mastra -->
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

## Pair with the owner (OpenEntity app)

<!-- oe:skip needs the OpenEntity Account service and an owner with a pairing code -->
```ts
import { ownerTools, pair } from "@openentity/mastra";

await pair("OE-7K4M-Q2XP");  // the code the owner's OpenEntity app shows; prints Match: ... and waits for the owner
const tools = ownerTools();  // owner_message, owner_status, owner_inbox, owner_ask_approval
```

`pair(code)` runs once, from your code: it adopts this machine's identity when the registry does not know it yet (adopting signs the Open Entity Declaration, and it says so), prints the four match items the owner compares with the app, and waits for the owner to confirm. Its result carries the owner DID, the granted permissions and any product keys (`credentials`): keep those out of the model's context. Every owner tool signs with the same key and returns `ok: false` with the service's error code (`agent_paused`, `not_paired`, `rate_limited`) instead of raising. The account is `OPENENTITY_ACCOUNT`, else `https://account.openentity.org`.

| Tool | Does |
|---|---|
| `owner_message` | Messages the owner in the OpenEntity app |
| `owner_status` | Reports `running`, `idle`, `blocked`, `error` or `done` with a one-line summary; the app shows it live |
| `owner_inbox` | Returns and acknowledges what the owner sent: messages, commands (`checkup`, `fix`, `pause`, `resume`), approval results, permission changes |
| `owner_ask_approval` | Asks the owner to approve something first; the app labels it "Written by the agent", and the decision arrives in the inbox |

The key is in the OS keychain, else `~/.openentity/identity.key` (mode 0600), shared with every other Open Entity SDK integration on the machine (the `openentity` CLI keeps its own keys under `~/.openentity/<eid>/`). Set `OPENENTITY_HOME` and `OPENENTITY_KEYCHAIN=off` to give an app its own. Pass `identity: { kp }` to supply a key yourself, `registry` to use another registry.

`createCore("mastra", options)` is exported for use without the tool wrappers. Tests run against an in-memory registry: `pnpm test`.
