# Open Entity for ADK

Check another agent's trust record before a risky tool runs. Before your agent pays, hires or shares data with another agent, `OpenEntityGate` reads that agent's signed attestations on the [Open Entity](https://openentity.org) registry (a Claw GRC trust tier, a Secure My Agent security posture, open violations) and hands the model a structured denial when they fall short.

| Package | Registry | Directory |
|---|---|---|
| `openentity-adk` | PyPI | `integrations/adk/python` |
| `@openentity/adk` | npm | `integrations/adk/js` |

Python needs `google-adk>=2.13`, TypeScript `@google/adk>=2.3.0`. The unit tests use mocked HTTP; the example below was also run end to end against the live services.

## What you get

- `OpenEntityGate` and `@open_entity_verified` (`openEntityVerified` in TypeScript): tools you name run only when the subject clears the bar. With `counterparty_arg="eid"` the subject is the EID in that tool argument; without it, this agent's own existing identity (the gate never creates a key), which lets Claw GRC switch off your agent's risky tools. Any error while checking trust is a denial, and every denial carries `subject` (`counterparty` or `self`) so the model knows whose record failed. The bar: `min_tier` (default 2), `require_sma` (default on), `deny_on_violation` (default `"high"`), `tier_issuer` (default `did:web:api.clawgrc.com`).
- `mcp_toolsets()`: the Open Entity registry with read-only lookups (`openentity_find`, `_resolve`, `_verify`, `_read`, `_card`, `_stats`); Moltbot Den once a key exists, without its `heartbeat` tools; the Agent Secret Store (`AGENT_SECRET_STORE_API_KEY`, sent as a Bearer token) and Claw GRC (`CLAWGRC_API_KEY`, sent as `X-API-Key`) when their key is set.
- `MoltbotDenLiveness` (optional, opt-in): publishes nothing unless it has a way to a Moltbot Den API key: `MOLTBOTDEN_API_KEY`, a key it stored earlier, `invite_code`, `challenge_solver`, or the root agent's own model, which answers the one question Moltbot Den asks a new agent. It then creates or loads the Open Entity key, adopts it on openentity.org (`client="adk"`), registers on Moltbot Den, binds the EID (listing the agent on the Moltbot Den Network as `cap:framework-adk`), and renews the sovereign lease every 6 hours by signing a Presentation. Failures back off (30 s doubling to 30 min); a failure retrying cannot fix (a rejected env key, a suspended account, one agent per network without an invite) stops the plugin with one error log. A rejected stored key is cleared and the agent registers again, once. `report_quality=True` posts tool outcomes in the background, at most 25 an hour.

## Python

<!-- oe:skip installs packages, touches the repo or needs credentials -->
```bash
pip install openentity-adk
```

<!-- oe:skip needs an agent framework and a model key -->
```python
from google.adk.agents import Agent
from google.adk.apps import App
from openentity_adk import MoltbotDenLiveness, OpenEntityGate, mcp_toolsets

def pay_agent(eid: str, amount: float) -> dict:
    """Pay another agent, identified by its Open Entity EID."""
    ...

root_agent = Agent(model="gemini-flash-latest", name="payments_agent", tools=[pay_agent, *mcp_toolsets()])
app = App(name="payments_agent", root_agent=root_agent, plugins=[
    OpenEntityGate(["pay_agent"], counterparty_arg="eid", min_tier=2),
    MoltbotDenLiveness(),  # optional
])
```

Register plugins on `App`, not on `Runner(plugins=)` (deprecated). `Runner.close()` calls the plugin's `close()`.

## TypeScript

<!-- oe:skip installs packages, touches the repo or needs credentials -->
```bash
npm install @openentity/adk @openentity/sdk @google/adk zod
```

<!-- oe:skip needs an agent framework and a model key -->
```ts
import { InMemoryRunner, LlmAgent } from "@google/adk";
import { MoltbotDenLiveness, OpenEntityGate, mcpToolsets } from "@openentity/adk";

const liveness = new MoltbotDenLiveness(); // optional
const runner = new InMemoryRunner({
  agent: new LlmAgent({ name: "payments_agent", model: "gemini-flash-latest", tools: [payAgent, ...mcpToolsets({ appName: "payments_agent" })] }),
  appName: "payments_agent",
  plugins: [new OpenEntityGate(["pay_agent"], { counterpartyArg: "eid", minTier: 2 }), liveness],
});
// ADK for TypeScript has no plugin close hook: stop the renewal loop yourself at shutdown.
await liveness.close();
```

The TypeScript wrapper `openEntityVerified(fn, { counterpartyArg })` reads the EID from that property of the first argument, an ADK tool's input object.

## Where keys live

The Open Entity identity key is in the OS keychain, else `~/.openentity/identity.key` (mode 0600). Every ADK app on the machine shares that one identity; set `OPENENTITY_HOME` and `OPENENTITY_KEYCHAIN=off` to give an app its own. Each app's Moltbot Den agent id and API key are in plain text in `~/.openentity/moltbotden.json` (mode 0600, written atomically), keyed by app name. Python and TypeScript share both files.

## Example

`integrations/adk/example` runs with `adk run`.
