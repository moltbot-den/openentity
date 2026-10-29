"""0.2.0 hardening: what the independent review found. Each test fails on the 0.1.0 behavior."""

import pytest
from langchain_core.messages import ToolMessage
from langgraph.errors import GraphInterrupt

from langchain_openentity import OpenEntityLoopDetected, OpenEntitySchemaViolation, RuthlessSchemaGuard, scrub
from langchain_openentity.core import Routes, compile_schema, stable_json

JSON = ("application/json", "")


def test_scrub_covers_llm_and_cloud_keys():
    for secret in ("sk-proj-" + "a1B2" * 8, "sk-ant-api03-" + "x" * 30, "AIza" + "a" * 35, "hf_" + "a" * 34, "npm_" + "a" * 36,
                   "glpat-" + "a" * 20, "AccountKey=" + "A" * 30 + "==", "SK" + "0" * 32, "Basic dXNlcjpwYXNzd29yZDEyMw=="):
        assert "[REDACTED]" in scrub(f"x {secret} y"), secret
    for body in ('{"password":"abc12"}', '{"authorization":"abcdefgh"}', "Set-Cookie: session=abcdef123; Path=/", '{"private_key":"abcdefghijkl"}'):
        assert "[REDACTED]" in scrub(body), body


def test_head_and_partial_content_are_not_violations():
    g = RuthlessSchemaGuard(scope="all")
    g._check("HEAD", "https://h.test/x", 200, "application/json", "", lambda: b"")
    g._check("GET", "https://h.test/x", 206, "application/json", "", lambda: b'{"a":')
    with pytest.raises(OpenEntitySchemaViolation):
        g._check("GET", "https://h.test/x", 200, "application/json", "", lambda: b"")


def test_default_scope_only_checks_calls_made_inside_a_tool():
    g = RuthlessSchemaGuard()  # a provider or tracing call outside a tool must never raise
    g._check("GET", "https://h.test/x", 200, "application/json", "", lambda: b"<html>")


def test_violation_message_never_carries_url_credentials():
    g = RuthlessSchemaGuard(scope="all")
    with pytest.raises(OpenEntitySchemaViolation) as e:
        g._check("GET", "https://user:hunter2@h.test:8443/x", 200, "application/json", "", lambda: b"<html>")
    assert "hunter2" not in str(e.value) and "h.test:8443/x" in str(e.value)


def test_interrupt_is_control_flow_not_a_failure():
    g = RuthlessSchemaGuard(max_failures=2)

    class Req:
        tool_call = {"name": "ask", "args": {}, "id": "1"}

    def interrupts(_):
        raise GraphInterrupt()

    for _ in range(3):
        with pytest.raises(GraphInterrupt):
            g.wrap_tool_call(Req(), interrupts)


def test_default_ports_match_and_repeated_double_star_is_rejected():
    rt, s = Routes(), compile_schema({"type": "object"})
    rt.add("GET https://h.test/x", s)
    assert rt.match("GET", "https://h.test:443/x") and rt.match("GET", "https://user@h.test/x")
    with pytest.raises(ValueError):
        rt.add("GET https://h.test/**/a/**/b", s)


def test_invalid_schema_fails_at_register():
    with pytest.raises(Exception):
        RuthlessSchemaGuard().register("t", {"type": "nope"})


def test_format_is_enforced_like_the_js_package():
    assert compile_schema({"type": "string", "format": "email"}).validate("nope", '"nope"')


def test_non_json_args_do_not_break_the_counter():
    assert stable_json({"b": b"x"})


def test_ledger_true_means_the_default_url_and_off_is_the_default():
    from langchain_openentity import DEFAULT_URL

    assert RuthlessSchemaGuard(ledger=True).ledger.url == DEFAULT_URL
    assert RuthlessSchemaGuard().ledger.enabled is False


def test_from_openapi_refuses_non_http_urls():
    with pytest.raises(ValueError):
        RuthlessSchemaGuard().from_openapi("file:///etc/hosts")


def test_command_result_is_validated_like_a_tool_message():
    from langgraph.types import Command

    g = RuthlessSchemaGuard({"t": {"type": "object"}})

    class Req:
        tool_call = {"name": "t", "args": {}, "id": "c1"}

    def returns(text):
        return lambda _: Command(update={"messages": [ToolMessage(text, tool_call_id="c1", name="t")]})

    assert isinstance(g.wrap_tool_call(Req(), returns("{}")), Command)
    with pytest.raises(OpenEntitySchemaViolation):
        g.wrap_tool_call(Req(), returns("<html>"))


def test_stacked_guards_uninstall_independently():
    import httpx

    a, b = RuthlessSchemaGuard(scope="all"), RuthlessSchemaGuard(scope="all")
    orig = httpx.Client.send
    off_a, off_b = a.guard_http(), b.guard_http()
    patched = httpx.Client.send
    off_a()
    assert httpx.Client.send is patched and b._uninstall is not None  # b still guarded after a leaves
    from langchain_openentity import http

    assert http._ACTIVE == [b]
    off_b()
    assert httpx.Client.send is orig and not http._ACTIVE  # last one out restores the library


def test_aiohttp_chunked_body_is_left_unread_for_the_caller(server):
    import asyncio

    import aiohttp

    g = RuthlessSchemaGuard(scope="all")
    g.guard_http()
    try:
        async def go():
            async with aiohttp.ClientSession() as s, s.get(f"{server}/chunked", headers={"Accept": "application/json"}) as r:
                assert r.headers["transfer-encoding"] == "chunked"
                return [c async for c in r.content.iter_any()]

        assert b"".join(asyncio.run(go())) == b'{"a": 1}'  # streamed through, not consumed by the guard
    finally:
        g.unguard_http()
