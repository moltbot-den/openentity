from __future__ import annotations

import contextvars
import hashlib
import json
import urllib.request
from collections.abc import Awaitable, Callable
from typing import Any, Literal
from urllib.parse import urlsplit

from langchain.agents.middleware import AgentMiddleware, hook_config
from langchain_core.messages import ToolMessage

from . import http as _http
from .core import (
    SAMPLE,
    OpenEntityLoopDetected,
    OpenEntitySchemaViolation,
    Routes,
    Schema,
    compile_schema,
    expects_json,
    inspect_response,
    path_template,
    scrub,
    stable_json,
)
from .ledger import LedgerReporter

HALT_FLAG = "openentity_halt"
# Violations raised by guarded HTTP calls inside the running tool. A tool that catches its own exception,
# or a ToolNode that converts it to a ToolMessage, still cannot hide one from wrap_tool_call.
_CALL: contextvars.ContextVar[list | None] = contextvars.ContextVar("openentity_call", default=None)


def _text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(b if isinstance(b, str) else b.get("text", "") for b in content if isinstance(b, (str, dict)))
    return json.dumps(content, default=str)


class RuthlessSchemaGuard(AgentMiddleware):
    """Raise on malformed tool output and malformed HTTP responses instead of letting the model guess.

    Put it first in `middleware=[...]`: the first entry is outermost, so an inner `ToolErrorMiddleware`
    or `ToolRetryMiddleware` cannot turn the violation into a ToolMessage before it is raised.
    """

    def __init__(
        self,
        schemas: dict[str, Any] | None = None,
        *,
        mode: Literal["raise", "halt"] = "raise",
        max_failures: int = 3,
        ledger: LedgerReporter | str | bool | None = None,
        ignore: tuple[str, ...] = (),
        only_registered: bool = False,
    ) -> None:
        super().__init__()
        self.mode, self.max_failures, self.ignore, self.only_registered = mode, max_failures, frozenset(ignore), only_registered
        self.routes = Routes()
        self.tool_schemas: dict[str, Schema] = {}
        # ponytail: one failure counter per guard; call reset() between unrelated runs.
        self._failures: dict[tuple[str, str], int] = {}
        self.last_report: str | None = None
        self.ledger = ledger if isinstance(ledger, LedgerReporter) else LedgerReporter(
            url=ledger if isinstance(ledger, str) else None, enabled=False if ledger is False else None)
        self._uninstall: Callable[[], None] | None = None
        for k, v in (schemas or {}).items():
            self.register(k, v)

    # ---- registration ----
    def register(self, target: str, schema: Any) -> RuthlessSchemaGuard:
        """`"GET https://api.example.com/items/*"` registers a route; a bare name registers a tool."""
        s = compile_schema(schema)
        if "://" in target:
            self.routes.add(target, s)
        else:
            self.tool_schemas[target] = s
        return self

    def from_openapi(self, spec: dict | str, base_url: str | None = None) -> RuthlessSchemaGuard:
        """Register every 2xx application/json response of an OpenAPI 3 document (dict, URL or JSON string)."""
        if isinstance(spec, str):
            if spec.lstrip().startswith("{"):
                spec = json.loads(spec)
            else:
                with urllib.request.urlopen(spec, timeout=15) as r:
                    spec = json.load(r)
        servers = spec.get("servers") or [{}]
        base = (base_url or servers[0].get("url") or "").rstrip("/")
        if "://" not in base:
            raise ValueError("from_openapi needs base_url when the document has no absolute servers[0].url")
        comps = {"components": spec.get("components", {})}
        for path, item in spec.get("paths", {}).items():
            for method, op in item.items():
                if method.upper() not in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD") or not isinstance(op, dict):
                    continue
                for code, resp in op.get("responses", {}).items():
                    if not str(code).startswith("2") or str(code) in ("204", "205"):
                        continue
                    for ct, media in (resp.get("content") or {}).items():
                        if "json" in ct and "schema" in media:
                            self.register(f"{method.upper()} {base}{path}", {**comps, **media["schema"]})
                            break
        return self

    # ---- transport ----
    def guard_http(self) -> Callable[[], None]:
        """Guard httpx, httpx2, requests and aiohttp (whichever are installed). Returns the uninstaller."""
        if self._uninstall is None:
            self._uninstall = _http.install(self)
        return self.unguard_http

    def unguard_http(self) -> None:
        if self._uninstall:
            self._uninstall()
            self._uninstall = None

    def _wants(self, method: str, url: str, status: int, ct: str, accept: str) -> bool:
        schema = self.routes.match(method, url)
        if self.only_registered and not schema:
            return False
        return 200 <= status < 300 and expects_json(ct, accept, schema is not None)

    def _check(self, method: str, url: str, status: int, ct: str, accept: str, get_body: Callable[[], bytes]) -> None:
        if not self._wants(method, url, status, ct, accept):
            return
        hit = self.routes.match(method, url)
        schema = hit[0] if hit else None
        body = get_body()
        errs = inspect_response(status, ct, body, schema, accept, self.ignore)
        if not errs:
            return
        sp = urlsplit(url)
        text = body.decode("utf-8", "replace") if isinstance(body, bytes) else body
        self.ledger.report({
            "host": sp.hostname or "", "method": method.upper(),
            "path_template": hit[1] if hit else path_template(url),
            "expected_schema_hash": schema.hash if schema else "",
            "status": status, "content_type": ct,
            "body_sha256": hashlib.sha256(body if isinstance(body, bytes) else body.encode()).hexdigest(),
            "sample": scrub(text)[:SAMPLE],
        })
        exc = OpenEntitySchemaViolation(f"{method.upper()} {sp.scheme}://{sp.netloc}{sp.path}", errs, text)
        if (seen := _CALL.get()) is not None:
            seen.append(exc)
        raise exc

    # ---- tools ----
    def reset(self) -> None:
        self._failures.clear()

    def _key(self, request: Any) -> tuple[str, tuple[str, str]]:
        """Failures are counted per thread, so a guard shared by concurrent runs does not mix them."""
        tc = request.tool_call
        cfg = getattr(getattr(request, "runtime", None), "config", None) or {}
        thread = str((cfg.get("configurable") or {}).get("thread_id", ""))
        return tc["name"], (thread, hashlib.sha256(f"{tc['name']}\0{stable_json(tc.get('args', {}))}".encode()).hexdigest())

    def _count(self, name: str, key: tuple[str, str]) -> OpenEntityLoopDetected | None:
        self._failures[key] = n = self._failures.get(key, 0) + 1
        return OpenEntityLoopDetected(name, key[1], n) if n >= self.max_failures else None

    def _validate(self, name: str, result: Any) -> None:
        schema = self.tool_schemas.get(name)
        if schema is None or not isinstance(result, ToolMessage) or result.status == "error":
            return
        text = _text(result.content)
        errs = inspect_response(200, "application/json", text, schema, "", self.ignore)
        if errs:
            raise OpenEntitySchemaViolation(name, errs, text)

    def _halted(self, request: Any, exc: BaseException) -> ToolMessage:
        errs = getattr(exc, "errors", None) or [str(exc)]
        self.last_report = f"RuthlessSchemaGuard halted the run: {exc.__class__.__name__} in {request.tool_call['name']}: " + "; ".join(errs[:5])
        return ToolMessage(self.last_report, tool_call_id=request.tool_call["id"], name=request.tool_call["name"],
                           status="error", additional_kwargs={HALT_FLAG: True})

    def _outcome(self, request: Any, run: Callable[[], Any], seen: list) -> Any:
        name, key = self._key(request)
        try:
            result = run()
            if seen:
                raise seen[0]
            self._validate(name, result)
        except (OpenEntitySchemaViolation, OpenEntityLoopDetected) as e:
            return self._exit(request, self._count(name, key) or e)
        except Exception as e:  # noqa: BLE001 - counted; re-raised unchanged until the limit
            loop = self._count(name, key)
            if loop is None:
                raise
            return self._exit(request, loop)
        if isinstance(result, ToolMessage) and result.status == "error":
            if loop := self._count(name, key):
                return self._exit(request, loop)
            return result
        self._failures.pop(key, None)
        return result

    def _exit(self, request: Any, exc: BaseException) -> ToolMessage:
        if self.mode == "halt":
            return self._halted(request, exc)
        raise exc

    def wrap_tool_call(self, request: Any, handler: Callable[[Any], Any]) -> Any:
        seen: list = []
        token = _CALL.set(seen)
        try:
            return self._outcome(request, lambda: handler(request), seen)
        finally:
            _CALL.reset(token)

    async def awrap_tool_call(self, request: Any, handler: Callable[[Any], Awaitable[Any]]) -> Any:
        # Await first, then reuse the sync logic on the outcome.
        seen: list = []
        token = _CALL.set(seen)
        try:
            result = await handler(request)
        except Exception as e:  # noqa: BLE001
            def fail() -> Any:
                raise e
            return self._outcome(request, fail, seen)
        finally:
            _CALL.reset(token)
        return self._outcome(request, lambda: result, seen)

    # ---- halt mode ----
    @hook_config(can_jump_to=["end"])
    def before_model(self, state: Any, runtime: Any) -> dict[str, Any] | None:
        last = state["messages"][-1] if state.get("messages") else None
        if isinstance(last, ToolMessage) and last.additional_kwargs.get(HALT_FLAG):
            return {"jump_to": "end"}
        return None

    @hook_config(can_jump_to=["end"])
    async def abefore_model(self, state: Any, runtime: Any) -> dict[str, Any] | None:
        return self.before_model(state, runtime)
