# Drop-in for Open-SWE

Read against `langchain-ai/open-swe` at commit `f78729c` (2026-10-28). Nothing in that repo was changed; the patch below was checked with `git apply --check`.

## Where the tool calls run

Open-SWE no longer has a `get_agent()`. Two files still mention `openswe.server.get_agent` in docstrings, but the function is gone. Every run plays on Managed Deep Agents, and the middleware that wraps tool calls lives in the `mda/` runtime package:

- `mda/agent.py`, `_parts()`: builds the `middleware` list of the main agent and a second list for the `task` subagent. The result is cached per graph and shared by every run. `worker_middleware` is that list plus `AsyncWorkerLaunchMiddleware`, so workers inherit it.
- `openswe/server.py`, `plan_agent()`: builds `surface.middleware`, but the backend graph only runs the model-call and run-boundary hooks from it. `openswe/agent_api/graph.py` says so: "None of the run's tool calls is a tool call here: no tools node, no tool-call middleware." A guard added there would never see a tool result.

So the guard goes into the two lists in `_parts()`.

## The patch

`RuthlessSchemaGuard` subclasses `AgentMiddleware`, so it goes straight into `list[AgentMiddleware]`. Put it first: the first entry is outermost, so `ToolErrorMiddleware` in `mda/rt/tool_errors.py` and the `ToolException` handling in the MCP tools cannot turn a violation into a `ToolMessage` before the guard raises it. `mode="halt"` ends the run with a report as the last message instead of failing it; use the default `mode="raise"` if you want the run to fail and the run-complete webhook to see the exception.

```diff
--- a/mda/agent.py
+++ b/mda/agent.py
@@ -32,6 +32,7 @@
 from deepagents.middleware.filesystem import FilesystemMiddleware
 from deepagents.middleware.subagents import SubAgent
 from langchain.agents.middleware import AgentMiddleware
+from langchain_openentity import RuthlessSchemaGuard
 from managed_deepagents import (
     DeepAgentDefinition,
     ManagedServerRuntime,
@@ -186,6 +187,9 @@
         RuntimeToolsMiddleware(backend, FILE_TOOLS),
         IncidentEvidenceMiddleware(backend),
     ]
+    # First in each list is outermost: nothing inside it can turn a violation into a ToolMessage.
+    guard = RuthlessSchemaGuard(mode="halt")
+    guard.register("mcp_github_list_pull_requests", list[PullRequest])  # your MCP tools' output
     subagent = _SUBAGENTS[inputs.graph]
     subagents: list[SubAgent] = [
         {
@@ -197,6 +201,7 @@
             "middleware": cast(
                 list[AgentMiddleware],
                 [
+                    guard,
                     *reports,
                     skills,
                     files,
@@ -213,6 +218,7 @@
     middleware = cast(
         list[AgentMiddleware],
         [
+            guard,
             BackendRunMiddleware(backend, opened_sandbox),
             replace_sandbox,
             *reports,
--- a/mda/pyproject.toml
+++ b/mda/pyproject.toml
@@ -14,6 +14,7 @@
     "langchain-quickjs>=0.3.10,<0.4.0",
     "langsmith>=0.14.13",
     "httpx2>=2.12.0",
+    "langchain-openentity>=0.1.0",
     # The vendored SDK's browser installs its extension from this package, so this
     # matches managed_deepagents.browser.STAGEHAND_VERSION.
     "stagehand==4.3.0",
```

`PullRequest` stands for your own Pydantic model. MCP tool names are built by `_tool_name()` in `openswe/mcp/runtime.py` as `mcp_<connection>_<tool>`; the name is hashed (`..._<10 hex>`) when the connection name contains `_`, or the tool name has characters outside `[A-Za-z0-9_-]`, or it is longer than 64 characters. Register the name the agent actually sees. MCP tool results arrive as text content blocks; the guard joins them and validates the JSON.

Two properties of the Open-SWE code that the guard accounts for:

- `_wrap_tool()` in `openswe/mcp/runtime.py` catches every exception inside an MCP tool and re-raises a generic `ToolException("MCP call failed...")`, and the tool is built with `handle_tool_error=True`. A violation raised inside the call would be flattened into an error `ToolMessage`. The guard records violations raised by guarded HTTP calls in a context variable scoped to the running tool and raises them from `wrap_tool_call`, so they survive.
- `_parts()` is cached and shared by every run. The loop breaker counts failures per `(thread_id, tool, args hash)`, so concurrent threads do not trip each other.

## Transport guard for the MCP client

The MCP clients are built in `_client()` (`openswe/mcp/runtime.py`) with `httpx_client_factory=partial(mcp_http_client, record.url)`. `mcp_http_client()` in `openswe/mcp/transport.py` returns an `httpx2.AsyncClient`: Open-SWE depends on `httpx2` (>=2.12), not `httpx`, and its `MCPTransport` sends a copy of each request with the URL rewritten to a pinned IP.

`guard_http()` patches `httpx2.Client.send` and `httpx2.AsyncClient.send` along with the `httpx` ones, so no change to the factory is needed. The patch sits above the transport, where the response carries the original request, so routes are matched on the hostname the caller used and not the pinned IP (`test_httpx2_client_with_a_rewriting_transport_like_open_swe` covers this). In the backend process, install it once at start-up, for example at the top of `openswe/webapp.py` (the `http.app` in `langgraph.json`):

```python
from langchain_openentity import RuthlessSchemaGuard

transport_guard = RuthlessSchemaGuard(only_registered=True)
transport_guard.register("GET https://api.github.com/repos/*/pulls", list[PullRequest])
transport_guard.guard_http()
```

Use `only_registered=True` there: it leaves Open-SWE's own backend calls (`mda/rt/backend.py` talks to the Open-SWE API through `httpx2`) alone and checks only the routes you list.

Limit, stated plainly: The `mcp` client opens every POST as a stream (`stream_within_origin` in `mcp.client.streamable_http`), and the guard never reads a streaming response. For MCP traffic the tool-level registration in the patch above is the check that fires; the transport guard covers the plain request-and-response callers (REST tools, `fetch_url`, `http_request`) in whichever process you install it.

## Ledger

Set `OPENENTITY_LEDGER_URL=1` and `OPENENTITY_SEED_HEX` (32 bytes, hex) in the deployment environment to send signed reports for transport violations. Off by default; `OPENENTITY_LEDGER_OPTOUT=1` wins over everything.

## Not verified

The patch applies and the middleware composes with `AgentMiddleware` lists, but Open-SWE needs Python 3.14, `managed-deepagents` and its sandbox, which were not stood up here. No Open-SWE run was executed with the guard in it.
