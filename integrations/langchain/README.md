# Open Entity for LangChain: RuthlessSchemaGuard

LangChain agents trust whatever a tool or API hands back. A login page served with a 200, a truncated JSON body, `{"error": ...}` inside a 200: the model reads it, guesses, and carries on. RuthlessSchemaGuard stops the run instead, with an exception that names the tool, the rules that broke and the first 500 characters of the body. It never turns a violation into a `ToolMessage`.

| Package | Registry | Directory |
|---|---|---|
| `langchain-openentity` | PyPI | [`python/`](python) |
| `@openentity/langchain` | npm | [`js/`](js) |

Both need LangChain 1.x (`langchain>=1.4` for Python, `langchain>=1.6` for JS) and implement the same rules, checked against one shared corpus in [`fixtures/`](fixtures): 362 malformed responses that must all raise and 265 valid ones that must not. Open-SWE: see [OPEN-SWE.md](OPEN-SWE.md).

## Python quickstart

```bash
pip install langchain-openentity            # extras: [requests] [aiohttp] [ledger]
```

```python
from langchain.agents import create_agent
from langchain_openentity import RuthlessSchemaGuard, OpenEntitySchemaViolation
from pydantic import BaseModel

class Pull(BaseModel):
    number: int
    title: str

guard = RuthlessSchemaGuard()
guard.register("get_pulls", list[Pull])                                  # a tool's output
guard.register("GET https://api.github.com/repos/*/pulls", list[Pull])   # a route, on every outbound call
guard.from_openapi("https://example.com/openapi.json")                   # or in bulk (OpenAPI 3, JSON)
guard.guard_http()                                                       # httpx, httpx2, requests, aiohttp

agent = create_agent(model, tools=[get_pulls], middleware=[guard])  # guard first
try:
    agent.invoke({"messages": [("user", "list open PRs")]})
except OpenEntitySchemaViolation as e:
    print(e.tool, e.errors, e.raw_excerpt)
```

Put the guard first in `middleware=[...]`. The first entry is outermost, so an inner retry or error middleware cannot hide the exception. A schema can be a Pydantic model or type (validated strictly, so `"1"` is not an `int`) or a JSON Schema dict.

## JS quickstart

```bash
npm install @openentity/langchain
```

```ts
import { createAgent } from "langchain";
import { RuthlessSchemaGuard, unwrap, OpenEntitySchemaViolation } from "@openentity/langchain";
import { z } from "zod";

const guard = new RuthlessSchemaGuard();
guard.register("get_pulls", z.array(z.object({ number: z.number().int(), title: z.string() })));
guard.register("GET https://api.github.com/repos/*/pulls", { type: "array" }); // a JSON Schema works too
await guard.fromOpenapi("https://example.com/openapi.json");
guard.guardHttp(); // wraps global fetch

const agent = createAgent({ model, tools: [getPulls], middleware: [guard.middleware] });
try {
  await agent.invoke({ messages: [{ role: "user", content: "list open PRs" }] });
} catch (e) {
  const v = unwrap(e); // LangChain.js wraps middleware errors in a MiddlewareError; ours is its cause
  if (v instanceof OpenEntitySchemaViolation) console.log(v.tool, v.errors, v.rawExcerpt);
}
```

## What it checks

On a 2xx response (and on tool output for registered tools) where JSON is expected, meaning a schema is registered, the `Content-Type` says JSON or the request sent `Accept: application/json`:

| Rule | Fires on |
|---|---|
| `bom` | a UTF-8 byte order mark before the JSON |
| `empty` | no body (204 and 205 are exempt) |
| `html`, `xml` | a body that starts with `<` |
| `jsonp` | `callback({...})`, `)]}'`, `while(1);` |
| `truncated` | JSON that ends before it closes |
| `invalid_json` | anything else that does not parse (single quotes, trailing commas, `NaN`) |
| `error_envelope` | a 2xx body with a truthy `error` or `errors`, or `success: false` or `ok: false`, unless the schema declares that field |
| `schema` | the registered schema fails, including type drift on required fields |

Streaming responses (`stream=True`, SSE, ndjson) are never read. Pass `ignore=("error_envelope",)` for an API whose 200s legitimately carry `errors` (GraphQL partial results), and `only_registered=True` to skip routes without a schema.

## Other features

- Dead-loop breaker: the same tool with the same arguments failing `max_failures` times in a row (default 3) raises `OpenEntityLoopDetected`. An exception, an error `ToolMessage` and a violation all count; a success resets the count. It matters when an outer layer such as a retry middleware keeps catching the failure. Call `guard.reset()` between unrelated runs.
- `mode="halt"`: instead of raising, the run ends with a `ToolMessage` report as its last message, also kept in `guard.last_report` (`lastReport` in JS).
- A violation raised by a guarded HTTP call inside a tool cannot be swallowed. If the tool catches its own exception, or LangChain.js converts it to an error `ToolMessage`, the middleware still raises it.

## Ledger reporter

Off unless `OPENENTITY_LEDGER_URL` is set (or `ledger="https://..."` is passed). `OPENENTITY_LEDGER_URL=1` selects the default `https://api.clawgrc.com/v1/ledger/schema-violations`. Opt out with `OPENENTITY_LEDGER_OPTOUT=1` or `ledger=False`.

Each violation on an HTTP call becomes a report: `host`, `method`, `path_template`, `expected_schema_hash`, `status`, `content_type`, `body_sha256`, a `sample` of at most 2 KB with secrets scrubbed, `framework` and `reporter_eid`. Reports queue in memory, go out in the background in batches (duplicates in a batch collapse), never block the agent, and a failed post is dropped. Each is signed as an Open Entity object (`eddsa-jcs-2022`) with the `openentity` SDK (`pip install langchain-openentity[ledger]`, `@openentity/sdk` for JS). The sample scrubbing uses the same rules as the ClawGRC secret scanner.

The SDK has no identity-loading helper yet, so the signing key comes from a `keypair=` argument or a 32-byte hex seed in `OPENENTITY_SEED_HEX`. With the ledger URL set and no key, the reporter turns itself off and says so. One report is posted per violation as the signed object itself; if the ledger ingest contract settles on a batch envelope, only `LedgerReporter._send` changes. Violations raised on tool output (no URL) are not reported.

## Tests

```bash
cd python && uv run pytest -q        # 660 tests
cd js && pnpm test                   # 650 tests
```

`scripts/verify.sh` runs both. `fixtures/generate.py` regenerates the corpus and asserts it against the Python implementation; edit it, not the JSON.
