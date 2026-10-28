"""Response inspection shared by the middleware and the HTTP transport hooks.

The rules and rule names mirror the JS package (`@openentity/langchain`); `fixtures/` holds the
corpus both test suites run, so the two stay in step.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator
from pydantic import TypeAdapter, ValidationError

EXCERPT = 500
SAMPLE = 2048


class OpenEntitySchemaViolation(Exception):
    """A response broke its contract. Never converted to a ToolMessage by this package."""

    def __init__(self, tool: str, errors: list[str], raw_excerpt: str = ""):
        self.tool = tool
        self.errors = list(errors)
        self.raw_excerpt = scrub(raw_excerpt)[:EXCERPT]
        self.rule = self.errors[0].split(":", 1)[0] if self.errors else ""
        super().__init__(f"{tool}: " + "; ".join(self.errors[:3]))


class OpenEntityLoopDetected(Exception):
    """The same tool call with the same arguments failed `count` times in a row."""

    def __init__(self, tool: str, args_hash: str, count: int):
        self.tool, self.args_hash, self.count = tool, args_hash, count
        super().__init__(f"{tool} failed {count} times with identical arguments ({args_hash[:12]})")


# ---- scrubbing (rules ported from the ClawGRC/SMA secret scanner; same list in the JS package) ----
_FULL = [re.compile(p) for p in (
    r"AKIA[0-9A-Z]{16}",
    r"gh[pousr]_[A-Za-z0-9_]{36,255}",
    r"xox[bpsa]-[0-9]+-[0-9A-Za-z-]+",
    r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+",
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|(?![\s\S]))",
    r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|mssql)://[^:\s/]+:[^@\s]+@[^/\s\"']+",
    r"[sr]k_(?:live|test)_[A-Za-z0-9]{20,}",
    r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
    r"[Bb]earer\s+[A-Za-z0-9._~+/=-]{16,}",
    r"https?://[^/\s:@]+:[^/\s@]+@[^\s/\"']+",
)]
_KV = re.compile(
    r"(\"?(?:api[_-]?key|api[_-]?secret|api[_-]?token|auth[_-]?token|access[_-]?token|refresh[_-]?token"
    r"|secret[_-]?key|client[_-]?secret|password|passwd|token|secret)\"?\s*[=:]\s*\"?)[^\s\"',}&]{6,}",
    re.I,
)


def scrub(text: str) -> str:
    for rx in _FULL:
        text = rx.sub("[REDACTED]", text)
    return _KV.sub(lambda m: m.group(1) + "[REDACTED]", text)


# ---- schemas ----
def stable_json(v: Any) -> str:
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


@dataclass
class Schema:
    """A registered contract: a Pydantic model/type, or a JSON Schema dict."""

    json_schema: dict
    _check: Any

    @property
    def hash(self) -> str:
        return hashlib.sha256(stable_json(self.json_schema).encode()).hexdigest()

    @property
    def declared(self) -> set[str]:
        s, defs = self.json_schema, {**self.json_schema.get("$defs", {})}
        if "$ref" in s:
            name = s["$ref"].rsplit("/", 1)[-1]
            s = defs.get(name) or self.json_schema.get("components", {}).get("schemas", {}).get(name, {})
        keys = set(s.get("properties", {}))
        for k in ("allOf", "anyOf", "oneOf"):
            for sub in s.get(k, []):
                keys |= set(sub.get("properties", {}))
        return keys

    def validate(self, parsed: Any, raw: str) -> list[str]:
        return self._check(parsed, raw)


def _nullable(node: Any) -> Any:
    """OpenAPI 3.0 `nullable: true` -> JSON Schema type union."""
    if isinstance(node, list):
        return [_nullable(n) for n in node]
    if not isinstance(node, dict):
        return node
    out = {k: _nullable(v) for k, v in node.items()}
    if out.get("nullable") is True and isinstance(out.get("type"), str):
        out["type"] = [out["type"], "null"]
        if isinstance(out.get("enum"), list) and None not in out["enum"]:
            out["enum"] = [*out["enum"], None]
    out.pop("nullable", None)
    return out


def compile_schema(obj: Any) -> Schema:
    if isinstance(obj, Schema):
        return obj
    if isinstance(obj, dict):
        js = _nullable(obj)
        v = Draft202012Validator(js)

        def check(parsed: Any, _raw: str) -> list[str]:
            errs = sorted(v.iter_errors(parsed), key=lambda e: list(map(str, e.absolute_path)))
            return [f"schema: {'/'.join(map(str, e.absolute_path)) or '$'}: {e.message[:200]}" for e in errs[:10]]

        return Schema(js, check)
    ta = TypeAdapter(obj)

    def check_py(_parsed: Any, raw: str) -> list[str]:
        try:
            ta.validate_json(raw, strict=True)
        except ValidationError as e:
            return [f"schema: {'/'.join(map(str, x['loc'])) or '$'}: {x['msg'][:200]}" for x in e.errors()[:10]]
        return []

    return Schema(ta.json_schema(), check_py)


# ---- routes ----
def _pattern(url: str) -> re.Pattern:
    sp = urlsplit(url)
    path = sp.path.rstrip("/")
    esc = lambda s: re.escape(s).replace(r"\*", "[^/]+")  # noqa: E731
    host = esc(sp.netloc.lower())
    segs = []
    for seg in path.split("/"):
        if seg == "**":
            segs.append(".*")
        elif re.fullmatch(r"\{[^}]*\}", seg) or seg == "*":
            segs.append("[^/]+")
        else:
            segs.append(esc(seg))
    return re.compile(f"{sp.scheme.lower()}://{host}{'/'.join(segs)}/?", re.I)


class Routes:
    def __init__(self) -> None:
        self._routes: list[tuple[str, re.Pattern, str, Schema]] = []

    def add(self, route: str, schema: Schema) -> None:
        method, _, url = route.strip().partition(" ")
        if not url:
            raise ValueError(f"route must look like 'GET https://host/path', got {route!r}")
        self._routes.append((method.upper(), _pattern(url.strip()), urlsplit(url.strip()).path or "/", schema))

    def match(self, method: str, url: str) -> tuple[Schema, str] | None:
        sp = urlsplit(url)
        bare = f"{sp.scheme}://{sp.netloc}{sp.path}"
        for m, rx, path, schema in self._routes:
            if m in ("*", method.upper()) and rx.fullmatch(bare):
                return schema, path
        return None


_ID = re.compile(r"^(?:\d+|[0-9a-f]{8}-[0-9a-f-]{27}|[0-9a-f]{16,})$", re.I)


def path_template(url: str) -> str:
    return "/".join("{id}" if _ID.match(s) else s for s in urlsplit(url).path.split("/")) or "/"


# ---- inspection ----
_WS = " \t\n\r"
_JSONP = re.compile(r"[A-Za-z_$][\w$.]*\s*\(")
_NOT_JSON_STREAM = re.compile(r"ndjson|jsonl|event-stream|octet-stream", re.I)


def _unbalanced(t: str) -> bool:
    depth, in_str, esc = 0, False, False
    for c in t:
        if in_str:
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
        elif c == '"':
            in_str = True
        elif c in "{[":
            depth += 1
        elif c in "}]":
            depth -= 1
    return in_str or depth > 0


def _truthy(v: Any) -> bool:
    return not (v is None or v is False or v == 0 or v == "" or v == [] or v == {})


def _no_const(c: str) -> Any:
    raise ValueError(c)


def expects_json(content_type: str, accept: str, has_schema: bool) -> bool:
    if _NOT_JSON_STREAM.search(content_type):
        return False
    return has_schema or "json" in content_type.lower() or "json" in accept.lower()


def inspect_response(
    status: int,
    content_type: str,
    body: bytes | str,
    schema: Schema | None = None,
    accept: str = "",
    ignore: frozenset[str] | set[str] = frozenset(),
) -> list[str]:
    """Return the violations ("rule: detail") of a response; empty when it is fine or not checked."""
    if not 200 <= status < 300 or status in (204, 205):
        return []
    if not expects_json(content_type, accept, schema is not None):
        return []
    text = body.decode("utf-8", "replace") if isinstance(body, bytes) else body
    if text.startswith("﻿"):
        return ["bom: body starts with a byte order mark"]
    t = text.lstrip(_WS)
    if not t:
        return ["empty: 2xx response with no body"]
    ct = content_type.lower()
    if t[0] == "<":
        if t[:5].lower() == "<?xml" or ("xml" in ct and "html" not in ct):
            return ["xml: body is XML, not JSON"]
        return ["html: body is HTML, not JSON"]
    if t.startswith(")]}'"):
        return ["jsonp: XSSI guard prefix before JSON"]
    if _JSONP.match(t):
        return ["jsonp: body is a function call (JSONP), not JSON"]
    try:
        parsed = json.loads(text, parse_constant=_no_const)
    except ValueError:
        if _unbalanced(t) or t.rstrip(_WS)[-1] in ",:":
            return ["truncated: JSON ends before it is complete"]
        return ["invalid_json: body does not parse as JSON"]
    errs: list[str] = []
    declared = schema.declared if schema else set()
    if isinstance(parsed, dict) and "error_envelope" not in ignore:
        for k in ("error", "errors"):
            if k in parsed and k not in declared and _truthy(parsed[k]):
                errs.append(f"error_envelope: 2xx body carries '{k}'")
        for k in ("success", "ok"):
            if parsed.get(k) is False and k not in declared:
                errs.append(f"error_envelope: 2xx body carries {k}=false")
    if schema is not None and "schema" not in ignore:
        errs += schema.validate(parsed, text)
    return errs
