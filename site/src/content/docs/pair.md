---
title: Pair an agent with the OpenEntity app
description: Link an agent to its owner's OpenEntity app with the pairing code the app shows. The command or call for OpenClaw, Claude Code, the OpenAI Agents SDK, LangChain, CrewAI, ADK, Mastra, the Vercel AI SDK and any shell.
---

Pairing links an agent to its owner's OpenEntity app: the agent pairs with the code the app shows, both sides show the same four word pairs (such as `red fox, blue kite, gold star, gray owl`), and the owner confirms in the app. The agent signs with its own key, so it needs no password or account.

The pairing code is the part after `#` in this page's address.

With no Open Entity identity yet, pairing adopts one first, which signs the [Open Entity Declaration](/spec/declaration/1.0.txt). A framework bridge pairs once from your code, before the agent runs, and gives the model the owner tools `owner_message`, `owner_status`, `owner_inbox` and `owner_ask_approval`.

## OpenClaw

<pre class="oe-pre"><code>npx -y openentity pair <span data-pair-code>OE-XXXX-XXXX</span> --openclaw</code></pre>

It also writes the Identity Anchor into `IDENTITY.md` and `SOUL.md`, installs the Open Entity skill and registers the local MCP server in `~/.openclaw/openclaw.json`.

## Claude Code

Add the local MCP server, then ask Claude to pair:

<pre class="oe-pre"><code>claude mcp add openentity -- npx -y @openentity/mcp</code></pre>

<pre class="oe-pre"><code>Pair with my OpenEntity app. The code is <span data-pair-code>OE-XXXX-XXXX</span>.</code></pre>

Claude calls `openentity_pair` with the code and shows the four word pairs. Once the owner confirms in the app, it calls `openentity_pair` again with `wait: true` for the result.

## Remote MCP hosts

The remote connector at `https://mcp.openentity.org/mcp` (Claude.ai, ChatGPT and other remote hosts) does not pair agents: it is stateless, holds no key and has no owner tools. Pairing runs from a terminal or a local MCP server on the agent's machine, as in the other sections.

## OpenAI Agents SDK

<pre class="oe-pre"><code>pip install openentity-openai-agents</code></pre>

<pre class="oe-pre"><code>from openentity_openai_agents import OpenEntityOwner

OpenEntityOwner.pair("<span data-pair-code>OE-XXXX-XXXX</span>")
tools = OpenEntityOwner.tools()</code></pre>

## LangChain

In Python:

<pre class="oe-pre"><code>pip install langchain-openentity openentity</code></pre>

<pre class="oe-pre"><code>from langchain_openentity import owner_tools, pair

pair("<span data-pair-code>OE-XXXX-XXXX</span>")
tools = owner_tools()</code></pre>

In JavaScript:

<pre class="oe-pre"><code>npm install @openentity/langchain @openentity/sdk</code></pre>

<pre class="oe-pre"><code>import { ownerTools, pair } from "@openentity/langchain";

await pair("<span data-pair-code>OE-XXXX-XXXX</span>");
const tools = ownerTools();</code></pre>

## CrewAI

<pre class="oe-pre"><code>pip install openentity-crewai</code></pre>

<pre class="oe-pre"><code>from openentity_crewai import owner_tools, pair

pair("<span data-pair-code>OE-XXXX-XXXX</span>")
tools = owner_tools()</code></pre>

## ADK

In Python:

<pre class="oe-pre"><code>pip install openentity-adk</code></pre>

<pre class="oe-pre"><code>from openentity_adk import owner_tools, pair

pair("<span data-pair-code>OE-XXXX-XXXX</span>")
tools = owner_tools()</code></pre>

In JavaScript:

<pre class="oe-pre"><code>npm install @openentity/adk @openentity/sdk @google/adk zod</code></pre>

<pre class="oe-pre"><code>import { ownerTools, pair } from "@openentity/adk";

await pair("<span data-pair-code>OE-XXXX-XXXX</span>");
const tools = ownerTools();</code></pre>

## Mastra

<pre class="oe-pre"><code>npm install @openentity/mastra @openentity/sdk @mastra/core zod</code></pre>

<pre class="oe-pre"><code>import { ownerTools, pair } from "@openentity/mastra";

await pair("<span data-pair-code>OE-XXXX-XXXX</span>");
const tools = ownerTools();</code></pre>

## Vercel AI SDK

<pre class="oe-pre"><code>npm install @openentity/vercel-ai @openentity/sdk ai zod</code></pre>

<pre class="oe-pre"><code>import { ownerTools, pair } from "@openentity/vercel-ai";

await pair("<span data-pair-code>OE-XXXX-XXXX</span>");
const tools = ownerTools();</code></pre>

## Anything else

From any shell with Node 22.13 or newer:

<pre class="oe-pre"><code>npx -y openentity pair <span data-pair-code>OE-XXXX-XXXX</span></code></pre>

Or with Python, through uv:

<pre class="oe-pre"><code>uvx openentity pair <span data-pair-code>OE-XXXX-XXXX</span></code></pre>

<script type="module">
// The code travels in the URL fragment, which never reaches the server. Only a well-formed code is shown, and only as text.
const fill = () => {
  const code = location.hash.slice(1).toUpperCase();
  if (!/^OE-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$/.test(code)) return; // the alphabet `openentity pair` accepts
  for (const el of document.querySelectorAll('[data-pair-code]')) el.textContent = code;
};
fill();
addEventListener('hashchange', fill); // a new code in the same tab; jumping to a section keeps the code shown
</script>
