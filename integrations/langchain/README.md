# Open Entity for LangChain: RuthlessSchemaGuard

LangChain agents trust whatever a tool or API hands back. A login page served with a 200, a truncated JSON body, `{"error": ...}` inside a 200: the model reads it, guesses, and carries on. RuthlessSchemaGuard stops the run instead, with an exception that names the tool, the rules that broke and the first 500 characters of the body. In the default `raise` mode it never turns a violation into a `ToolMessage`.

| Package | Registry | Directory |
|---|---|---|
| `langchain-openentity` | PyPI | [`python/`](python) |
| `@openentity/langchain` | npm | [`js/`](js) |

Both need LangChain 1.x (`langchain>=1.4` for Python, `langchain>=1.6` for JS) and implement the same rules, checked against one shared corpus in [`fixtures/`](fixtures): hundreds of malformed responses that must all raise and valid ones that must not. Open-SWE: see [OPEN-SWE.md](OPEN-SWE.md).

## Python quickstart

```bash
pip install langchain-openentity            # extras: [requests] [aiohttp] [ledger]
```

```python
from langchain.agents import create_agent
from langchain_core.tools import tool
from langchain_openentity import RuthlessSchemaGuard, OpenEntitySchemaViolation
from pydantic import BaseModel
import httpx

class Pull(BaseModel):
    number: int
    title: str

@tool
def get_pulls(repo: str) -> str:
    """List open pull requests of a GitHub repo, e.g. langchain-ai/langchain."""
    return httpx.get(f"https://api.github.com/repos/{repo}/pulls", headers={"Accept": "application/json"}).text

guard = RuthlessSchemaGuard()
guard.register("get_pulls", list[Pull])                                  # a tool's output
guard.register("GET https://api.github.com/repos/*/pulls", list[Pull])   # or a route, on every outbound call made inside a tool
guard.guard_http()                                                       # httpx, httpx2, requests, aiohttp

agent = create_agent("anthropic:claude-sonnet-4-6", tools=[get_pulls], middleware=[guard])  # guard first
try:
    agent.invoke({"messages": [("user", "list open PRs of langchain-ai/langchain")]})
except OpenEntitySchemaViolation as e:
    print(e.tool, e.errors, e.raw_excerpt)
```

To register a whole API at once: `guard.from_openapi("https://example.com/openapi.json")` (an `http(s)` URL you trust, a dict, or a JSON string; OpenAPI 3, JSON).

Put the guard first in `middleware=[...]`. The first entry is outermost, so an inner retry or error middleware cannot hide the exception. A schema can be a Pydantic model or type (validated strictly, so `"1"` is not an `int`) or a JSON Schema dict.

## JS quickstart

```bash
npm install @openentity/langchain
```

```ts
import { createAgent, tool } from "langchain";
import { RuthlessSchemaGuard, unwrap, OpenEntitySchemaViolation } from "@openentity/langchain";
import { z } from "zod";

const getPulls = tool(
  async ({ repo }) => (await fetch(`https://api.github.com/repos/${repo}/pulls`, { headers: { accept: "application/json" } })).text(),
  { name: "get_pulls", description: "List open pull requests of a GitHub repo, e.g. langchain-ai/langchain.", schema: z.object({ repo: z.string() }) },
);

const guard = new RuthlessSchemaGuard();
guard.register("get_pulls", z.array(z.object({ number: z.number().int(), title: z.string() }))); // a tool's output (zod or JSON Schema)
guard.register("GET https://api.github.com/repos/*/pulls", { type: "array" });                  // or a route, on every fetch made inside a tool
guard.guardHttp(); // wraps global fetch

const agent = createAgent({ model: "anthropic:claude-sonnet-4-6", tools: [getPulls], middleware: [guard.middleware] });
try {
  await agent.invoke({ messages: [{ role: "user", content: "list open PRs of langchain-ai/langchain" }] });
} catch (e) {
  const v = unwrap(e); // LangChain.js wraps middleware errors in a MiddlewareError; ours is its cause
  if (v instanceof OpenEntitySchemaViolation) console.log(v.tool, v.errors, v.rawExcerpt);
}
```

Bulk registration: `await guard.fromOpenapi(urlOrObject)`. In JS the guard exposes the middleware as `guard.middleware`; in Python the guard is the middleware.

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

HEAD requests and 206 partial responses are never checked. Streaming responses (`stream=True`, SSE, ndjson) are never read. Chunked aiohttp responses and bodies over 10 MB are not buffered, so they are not checked. Several guards can call `guard_http()` at once; each uninstalls on its own. A tool that returns a `Command` with a `ToolMessage` in its `update` is validated like a plain `ToolMessage`. `guard_http()` checks only calls made inside a running tool, so an LLM provider call or a tracing thread can never raise; pass `scope="all"` (`scope: "all"` in JS) to check every call in the process. Pass `ignore=("error_envelope",)` for an API whose 200s legitimately carry `errors` (GraphQL partial results), and `only_registered=True` to skip routes without a schema.

## Other features

- Dead-loop breaker: the same tool with the same arguments failing `max_failures` times in a row (default 3) raises `OpenEntityLoopDetected`. An exception, an error `ToolMessage` and a violation all count; a success resets the count. It matters when an outer layer such as a retry middleware keeps catching the failure. Call `guard.reset()` between unrelated runs.
- `mode="halt"`: instead of raising, the run ends with a `ToolMessage` report as its last message (no final AI message), also kept in `guard.last_report` (`lastReport` in JS).
- LangGraph control flow (`interrupt()`, `Command` jumps) is never counted as a failure.
- A violation raised by a guarded HTTP call inside a tool cannot be swallowed. If the tool catches its own exception, or a layer such as `handleToolErrors` turns it into an error `ToolMessage`, the middleware still raises it.

## Ledger reporter and data sent

Nothing leaves your machine by default. The reporter is off until you set `OPENENTITY_LEDGER_URL` (or pass `ledger="https://..."` or `ledger=True`). `OPENENTITY_LEDGER_URL=1` and `ledger=True` select the default `https://api.clawgrc.com/v1/ledger/schema-violations`. Opt out everywhere with `OPENENTITY_LEDGER_OPTOUT=1` or `ledger=False`.

When on, each violation of an HTTP call becomes one report: `host`, `method`, `path_template` (the route you registered, else the path with numeric, UUID and long-hex segments replaced by `{id}`; never the query string), `expected_schema_hash`, `status`, `content_type`, `body_sha256`, a `sample` of at most 2 KB of the response body with common secrets scrubbed (cloud, LLM, GitHub, Slack, Stripe, JWT, private keys, URL credentials, `password`, `token`, `authorization`, `cookie` and similar fields), `framework`, and `reporter_eid`. Request headers, request bodies and your prompts are never sent. Violations on tool output (no URL) are not reported. Do not enable it for APIs whose host names or response bodies are confidential.

Reports queue in memory, go out in the background in batches (duplicates in a batch collapse), never block the agent, and a failed post is dropped. Each is signed as an Open Entity object (`eddsa-jcs-2022`) with the `openentity` SDK (`pip install langchain-openentity[ledger]`, `@openentity/sdk` for JS). You choose the signing key: the `keypair=` argument, else a 32-byte hex seed in `OPENENTITY_SEED_HEX`. Without one the batch is dropped with a warning; no machine identity is created or read implicitly. `reporter_eid` is that key's DID, so reports signed with one key are linkable to each other.

## Tests

```bash
cd python && uv run pytest -q
cd js && pnpm test
```

`scripts/verify.sh` runs both. `fixtures/generate.py` regenerates the corpus and asserts it against the Python implementation; edit it, not the JSON.
