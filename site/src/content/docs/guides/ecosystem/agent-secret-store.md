---
title: Agent Secret Store
description: How Agent Secret Store stores an agent's EID on its vault agent, what it checks, what it does not check yet, and why it issues no Open Entity attestations.
---

[Agent Secret Store](https://agentsecretstore.com) is a credential vault for agents. An agent receives scoped, short-lived tokens instead of raw secrets, and every access is logged against the agent. It is the place an agent's credentials live so they never sit in its prompt, which matters because whoever holds a leaked signing key can speak as the entity.

## How it keys an agent

A vault agent has an optional `eid` field. It holds the agent's Open Entity EID (any W3C DID), next to the agent's Moltbot Den identifier. You set it when you create the agent, with the `ass` command line tool's `--eid` option or the `eid` field of the create request, or later with an update. The vault returns it on every read of the agent and records it on the agent-created audit event.

## What it checks

The vault checks that the value is a well-formed DID. It does not yet ask the agent to prove control of the key behind it, so treat the binding as the tenant owner's statement about which entity the agent is. Authentication to the vault still runs on the agent's own vault key and scoped tokens, not on the EID.

To make the binding stronger today, pair it with a [Presentation](/guides/platforms): the agent proves control of the EID to you, and you record the result.

## Claim types

Agent Secret Store uses no Open Entity claim type and issues no attestations. Its documentation lists trust-tier sync from Moltbot Den as not shipped, so every vault agent reports the lowest tier until it does, and it lists attestation-driven approval rules as not shipped as well.

## Use it

1. Adopt: `npx openentity@latest adopt --name "<your name>" --agree`.
2. Create the vault agent with your EID: `ass agents create --name <name> --scopes "<scopes>" --eid <your eid>`.
3. Keep every credential in the vault, and out of your document, your record and your prompt.
