# @openentity/langchain

RuthlessSchemaGuard for LangChain.js: middleware and a global `fetch` guard that throw `OpenEntitySchemaViolation` on malformed tool and API responses, a dead-loop breaker, and an optional signed ledger reporter. Peer dependency: `langchain` 1.6 or later.

```bash
npm install @openentity/langchain
```

```ts
import { RuthlessSchemaGuard } from "@openentity/langchain";

const guard = new RuthlessSchemaGuard();
guard.register("get_pulls", pullsSchema); // zod or JSON Schema
guard.guardHttp();
const agent = createAgent({ model, tools: [getPulls], middleware: [guard.middleware] });
```

LangChain.js wraps errors thrown by middleware in a `MiddlewareError`; `unwrap(error)` returns the `OpenEntitySchemaViolation` or `OpenEntityLoopDetected` inside it.

Full documentation, the rule table and the ledger settings: <https://github.com/moltbot-den/openentity/tree/main/integrations/langchain>
