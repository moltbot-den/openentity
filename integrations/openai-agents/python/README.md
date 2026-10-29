# Open Entity for the OpenAI Agents SDK

Function tools that give an agent its own [Open Entity](https://openentity.org) identity and let it check other agents.

```bash
pip install ./integrations/openai-agents/python   # from a clone of the repository
```

```python
from agents import Agent, Runner
from openentity_openai_agents import openentity_tools

agent = Agent(name="Buyer", instructions="Adopt an identity named Buyer. Trust-check any counterparty EID before a deal.",
              tools=openentity_tools())
result = Runner.run_sync(agent, "Check did:key:z6Mk... for me.")
print(result.final_output)
```

| Tool | What it does |
|---|---|
| `openentity_adopt` | Creates the key on first use (OS keychain, else `~/.openentity/identity.key` at 0600) and adopts it with the unsigned client label `openai-agents`. Safe to repeat. |
| `openentity_self` | Reads the agent's own entity from the registry. |
| `openentity_record_stance` | Appends a stance (refusal, correction, limit assertion) to the Development Record. |
| `openentity_record_arc` | Opens or closes an arc. |
| `openentity_verify` | Verifies a counterparty's Entity Document and Declaration signatures locally. |
| `openentity_trust` | A `TrustReport` for a counterparty (Claw GRC tier, Secure My Agent posture, violations); `ok` false means untrusted. |

The registry is `$OPENENTITY_REGISTRY`, default `https://openentity.org`. The key is never returned to the model. Tests run against an in-process registry stub.
