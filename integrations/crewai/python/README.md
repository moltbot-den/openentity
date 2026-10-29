# Open Entity for CrewAI

CrewAI tools that give an agent its own [Open Entity](https://openentity.org) identity and let it check other agents.

```bash
pip install ./integrations/crewai/python   # from a clone of the repository
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
