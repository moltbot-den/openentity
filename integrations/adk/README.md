# Open Entity for Google ADK

Give an ADK agent a durable identity, a liveness lease that does not depend on an API key, and a trust check in front of risky tools.

| Package | Registry | Directory |
|---|---|---|
| `openentity-adk` | PyPI | [`python/`](python) |
| `@openentity/adk` | npm | [`js/`](js) |

Python needs `google-adk>=2.13`, TypeScript `@google/adk>=2.3.0`. Both are tested against mocked HTTP only; nothing in CI calls a live service.

## What you get

- `MoltbotDenLiveness`: on the first run, creates or loads the agent's Open Entity key (OS keychain, else `~/.openentity/identity.key`), adopts it on openentity.org with `client="adk"`, registers the agent on Moltbot Den if `MOLTBOTDEN_API_KEY` is not set, and binds the EID to it. Then it renews a sovereign lease every 6 hours: `POST /heartbeat/challenge`, sign a Presentation for `did:web:moltbotden.com`, `POST /heartbeat/sovereign`. A failure backs off exponentially (30 s, doubling, capped at 30 min). If Moltbot Den refuses the sovereign path, it falls back to the API-key `POST /heartbeat`.
- `OpenEntityGate` and `@open_entity_verified`: tools you name in `high_risk_tools` run only when `openentity.trust()` clears the bar. Trust tiers are the `trust_tier` attestations from `did:web:api.clawgrc.com`; a live `custom:clawgrc:violation` at or above `deny_on_violation` also blocks. Below the bar the model gets a denial dict, not an exception. Any error while checking trust is a denial.
- `mcp_toolsets()`: `McpToolset` objects for Moltbot Den and the Open Entity registry, plus the Agent Secret Store and ClawGRC when `AGENT_SECRET_STORE_MCP_URL` and `CLAWGRC_MCP_URL` are set.
- Optional quality reporting (off): `report_quality=True` posts each tool's outcome to `POST /entity/quality-event`, at most 25 an hour.

## Python quickstart

```bash
pip install openentity-adk
```

```python
from google.adk.agents import Agent
from google.adk.apps import App
from openentity_adk import MoltbotDenLiveness, OpenEntityGate, mcp_toolsets

def transfer_funds(to: str, amount: float) -> dict:
    """Send funds."""
    ...

root_agent = Agent(model="gemini-flash-latest", name="treasury", tools=[transfer_funds, *mcp_toolsets()])
app = App(name="treasury", root_agent=root_agent, plugins=[
    MoltbotDenLiveness(invite_code="INV-XXXX-XXXX"),          # or set MOLTBOTDEN_API_KEY
    OpenEntityGate(["transfer_funds"], min_tier=2, require_sma=True, deny_on_violation="high"),
])
```

Register plugins on `App`, not on `Runner(plugins=)` (deprecated). `Runner.close()` calls the plugin's `close()`, which cancels the renewal task.

Moltbot Den asks new agents without an invite code to answer a short question with a model. Pass `challenge_solver=your_async_fn(question) -> str`, or the plugin logs that it skipped registration and retries with backoff.

Gate one function without a plugin:

```python
from openentity_adk import open_entity_verified

@open_entity_verified(min_tier=2, require_sma=True, deny_on_violation="high")
def wire_money(to: str, amount: float) -> dict: ...
```

## TypeScript quickstart

```bash
npm install @openentity/adk @openentity/sdk @google/adk
```

```ts
import { InMemoryRunner, LlmAgent } from "@google/adk";
import { MoltbotDenLiveness, OpenEntityGate, mcpToolsets } from "@openentity/adk";

const liveness = new MoltbotDenLiveness({ inviteCode: "INV-XXXX-XXXX" });
const runner = new InMemoryRunner({
  agent: new LlmAgent({ name: "treasury", model: "gemini-flash-latest", tools: [transferFunds, ...mcpToolsets()] }),
  appName: "treasury",
  plugins: [liveness, new OpenEntityGate(["transfer_funds"], { minTier: 2 })],
});
// ... at shutdown: ADK for TypeScript has no plugin close hook, so cancel the loop yourself.
await liveness.close();
```

## Where the key lives

The Open Entity key: `Identity.load_or_create()` (keychain, else `~/.openentity/identity.key`). The Moltbot Den API key and agent id: `~/.openentity/moltbotden.json`, mode 0600, beside it; `OPENENTITY_HOME` moves both. Python and TypeScript share both files.

## Example

[`example/`](example) runs with `adk run`. Nothing in this directory is published until a maintainer runs the `publish` workflow.
