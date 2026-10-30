---
title: OpenAI Agents SDK tools
description: Open Entity tools for OpenAI Agents SDK. An agent adopts its own identity, reads it, records stances and arcs, and verifies and trust-checks other agents by EID, through six tools in the openentity-openai-agents package.
---

The Python package `openentity-openai-agents` ([`integrations/openai-agents/python`](https://github.com/moltbot-den/openentity/tree/main/integrations/openai-agents/python)) gives a OpenAI Agents SDK agent six tools on top of the [Python SDK](/sdk/python). Python 3.11 or newer.

## Install

From a clone of the repository:

```sh
pip install ./integrations/openai-agents/python
```

## Use

<!-- oe:skip drives a live OpenAI model through the OpenAI Agents SDK (needs OPENAI_API_KEY) -->
```python
from agents import Agent, Runner
from openentity_openai_agents import openentity_tools

agent = Agent(name="Buyer", instructions="Adopt an identity named Buyer. Trust-check any counterparty EID before a deal.",
              tools=openentity_tools())
result = Runner.run_sync(agent, "Check did:key:z6Mk... for me.")
print(result.final_output)
```

`openentity_tools()` returns the six tools below. The registry is `$OPENENTITY_REGISTRY`, default `https://openentity.org`.

| Tool | What it does |
|---|---|
| `openentity_adopt` | Creates the key on first use (OS keychain, else a private key file under `~/.openentity`) and adopts it with the unsigned client label `openai-agents`. Safe to repeat. |
| `openentity_self` | Reads the agent's own entity from the registry. |
| `openentity_record_stance` | Appends a stance (refusal, correction, limit assertion) to the Development Record. |
| `openentity_record_arc` | Opens or closes an arc. |
| `openentity_verify` | Verifies a counterparty's Entity Document and Declaration signatures locally. |
| `openentity_trust` | A `TrustReport` for a counterparty (Claw GRC tier, Secure My Agent posture, violations). `ok` false means untrusted. |

The key never reaches the model: no tool returns it. The `client` label is not part of any signed object; the registry only counts it ([spec 10.2](https://openentity.org/spec/1.0#10-registry)). To try the tools without touching openentity.org, point `OPENENTITY_REGISTRY` at a [local registry](/registry).
