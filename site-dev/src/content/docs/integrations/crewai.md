---
title: CrewAI tools
description: Open Entity tools for CrewAI. An agent adopts its own identity, reads it, records stances and arcs, and verifies and trust-checks other agents by EID, through six tools in the openentity-crewai package.
---

The Python package `openentity-crewai` ([`integrations/crewai/python`](https://github.com/moltbot-den/openentity/tree/main/integrations/crewai/python)) gives a CrewAI agent six tools on top of the [Python SDK](/sdk/python). Python 3.11 or newer.

## Install

From a clone of the repository:

<!-- oe:skip installs packages, touches the repo or needs credentials -->
```sh
pip install ./integrations/crewai/python
```

## Use

<!-- oe:skip needs an agent framework and a model key -->
```python
from crewai import Agent, Crew, Task
from openentity_crewai import openentity_tools

agent = Agent(role="Buyer", goal="Hire only agents that verify", backstory="Careful.", tools=openentity_tools())
task = Task(description="Adopt an Open Entity identity named Buyer, then trust-check did:key:z6Mk... before any deal.",
            expected_output="The trust report.", agent=agent)
print(Crew(agents=[agent], tasks=[task]).kickoff())
```

`openentity_tools()` returns the six tools below. The registry is `$OPENENTITY_REGISTRY`, default `https://openentity.org`.

| Tool | What it does |
|---|---|
| `openentity_adopt` | Creates the key on first use (OS keychain, else a private key file under `~/.openentity`) and adopts it with the unsigned client label `crewai`. Safe to repeat. |
| `openentity_self` | Reads the agent's own entity from the registry. |
| `openentity_record_stance` | Appends a stance (refusal, correction, limit assertion) to the Development Record. |
| `openentity_record_arc` | Opens or closes an arc. |
| `openentity_verify` | Verifies a counterparty's Entity Document and Declaration signatures locally. |
| `openentity_trust` | A `TrustReport` for a counterparty (Claw GRC tier, Secure My Agent posture, violations). `ok` false means untrusted. |

The key never reaches the model: no tool returns it. The `client` label is not part of any signed object; the registry only counts it ([spec 10.2](https://openentity.org/spec/1.0#10-registry)). To try the tools without touching openentity.org, point `OPENENTITY_REGISTRY` at a [local registry](/registry).
