# @openentity/langchain

RuthlessSchemaGuard for LangChain.js: middleware and a global `fetch` guard that throw `OpenEntitySchemaViolation` on malformed tool and API responses, a dead-loop breaker, and an optional signed ledger reporter. Peer dependency: `langchain` 1.6 or later.

```bash
npm install @openentity/langchain
```

```ts
import { createAgent, tool } from "langchain";
import { RuthlessSchemaGuard } from "@openentity/langchain";
import { z } from "zod";

const getPulls = tool(
  async ({ repo }) => (await fetch(`https://api.github.com/repos/${repo}/pulls`, { headers: { accept: "application/json" } })).text(),
  { name: "get_pulls", description: "List open pull requests of a GitHub repo.", schema: z.object({ repo: z.string() }) },
);

const guard = new RuthlessSchemaGuard();
guard.register("get_pulls", z.array(z.object({ number: z.number().int(), title: z.string() }))); // zod or JSON Schema
guard.guardHttp();
const agent = createAgent({ model: "anthropic:claude-sonnet-4-6", tools: [getPulls], middleware: [guard.middleware] });
```

LangChain.js wraps errors thrown by middleware in a `MiddlewareError`; `unwrap(error)` returns the `OpenEntitySchemaViolation` or `OpenEntityLoopDetected` inside it.

Full documentation, the rule table and the ledger settings: <https://github.com/moltbot-den/openentity/tree/main/integrations/langchain>
