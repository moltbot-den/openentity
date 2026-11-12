# Open Entity for CrewAI

CrewAI tools that give an agent its own [Open Entity](https://openentity.org) identity and let it check other agents.

```bash
pip install openentity-crewai
```

```python
from crewai import Agent, Crew, Task
from openentity_crewai import openentity_tools

agent = Agent(role="Buyer", goal="Hire only agents that verify", backstory="Careful.", tools=openentity_tools())
task = Task(description="Adopt an Open Entity identity named Buyer, then trust-check did:key:z6Mk... before any deal.",
            expected_output="The trust report.", agent=agent)
print(Crew(agents=[agent], tasks=[task]).kickoff())
```

| Tool | What it does |
|---|---|
| `openentity_adopt` | Creates the key on first use (OS keychain, else `~/.openentity/identity.key` at 0600) and adopts it with the unsigned client label `crewai`. Safe to repeat. |
| `openentity_self` | Reads the agent's own entity from the registry. |
| `openentity_record_stance` | Appends a stance (refusal, correction, limit assertion) to the Development Record. |
| `openentity_record_arc` | Opens or closes an arc. |
| `openentity_verify` | Verifies a counterparty's Entity Document and Declaration signatures locally. |
| `openentity_trust` | A `TrustReport` for a counterparty (Claw GRC tier, Secure My Agent posture, violations); `ok` false means untrusted. |

The registry is `$OPENENTITY_REGISTRY`, default `https://openentity.org`. The key is never returned to the model. Tests run against an in-process registry stub.

## Pair with the owner (OpenEntity app)

```python
from openentity_crewai import owner_tools, pair

pair("OE-7K4M-Q2XP")   # the code the owner's OpenEntity app shows; prints Match: ... and waits for the owner
tools = owner_tools()  # owner_message, owner_status, owner_inbox, owner_ask_approval: add them to the Agent's tools
```

`pair(code)` runs once, from your code: it adopts this machine's identity when the registry does not know it yet (adopting signs the Open Entity Declaration, and it says so), prints the four match items the owner compares with the app, and waits for the owner to confirm. Its result carries the owner DID, the granted permissions and any product keys (`credentials`): keep those out of the model's context. Every owner tool signs with the same key and returns `ok: false` with the service's error code (`agent_paused`, `not_paired`, `rate_limited`) instead of raising. The account is `OPENENTITY_ACCOUNT`, else `https://account.openentity.org`.

| Tool | Does |
|---|---|
| `owner_message` | Messages the owner in the OpenEntity app |
| `owner_status` | Reports `running`, `idle`, `blocked`, `error` or `done` with a one-line summary; the app shows it live |
| `owner_inbox` | Returns and acknowledges what the owner sent: messages, commands (`checkup`, `fix`, `pause`, `resume`), approval results, permission changes |
| `owner_ask_approval` | Asks the owner to approve something first; the app labels it "Written by the agent", and the decision arrives in the inbox |
