import asyncio
from types import SimpleNamespace

import pytest
from langchain.agents import create_agent
from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import AIMessage, ToolMessage
from langchain_core.tools import tool
from pydantic import BaseModel

from langchain_openentity import OpenEntityLoopDetected, OpenEntitySchemaViolation, RuthlessSchemaGuard


class Scripted(GenericFakeChatModel):
    def bind_tools(self, tools, **kw):
        return self


def model():
    call = AIMessage(content="", tool_calls=[{"name": "pulls", "args": {"repo": "a/b"}, "id": "c1"}])
    return Scripted(messages=iter([call, AIMessage(content="done")]))


def agent_with(output, guard):
    @tool
    def pulls(repo: str) -> str:
        """List pull requests."""
        return output

    return create_agent(model(), tools=[pulls], middleware=[guard])


class Pull(BaseModel):
    number: int
    title: str


PULLS = {"type": "array", "items": {"type": "object", "required": ["number"], "properties": {"number": {"type": "integer"}}}}


def test_valid_output_passes():
    out = agent_with('[{"number": 1}]', RuthlessSchemaGuard({"pulls": PULLS})).invoke({"messages": [("user", "go")]})
    assert out["messages"][-1].content == "done"


@pytest.mark.parametrize("bad", ["<html>login</html>", "", '[{"number": "1"}]', '{"error": "nope"}', '[{"number": 1'])
def test_malformed_output_raises_not_toolmessage(bad):
    with pytest.raises(OpenEntitySchemaViolation) as e:
        agent_with(bad, RuthlessSchemaGuard({"pulls": PULLS})).invoke({"messages": [("user", "go")]})
    assert e.value.tool == "pulls" and e.value.errors and len(e.value.raw_excerpt) <= 500


def test_async_path_raises():
    ag = agent_with("<html></html>", RuthlessSchemaGuard({"pulls": PULLS}))
    with pytest.raises(OpenEntitySchemaViolation):
        asyncio.run(ag.ainvoke({"messages": [("user", "go")]}))


def test_pydantic_model_is_strict():
    g = RuthlessSchemaGuard({"pulls": list[Pull]})
    assert agent_with('[{"number": 1, "title": "t"}]', g).invoke({"messages": [("user", "go")]})
    with pytest.raises(OpenEntitySchemaViolation):  # "1" would be coerced by lax pydantic
        agent_with('[{"number": "1", "title": "t"}]', RuthlessSchemaGuard({"pulls": list[Pull]})).invoke({"messages": [("user", "go")]})


def test_unregistered_tool_is_untouched():
    assert agent_with("<html>fine for this tool</html>", RuthlessSchemaGuard()).invoke({"messages": [("user", "go")]})


def test_halt_mode_ends_run_with_report():
    g = RuthlessSchemaGuard({"pulls": PULLS}, mode="halt")
    out = agent_with("<html></html>", g).invoke({"messages": [("user", "go")]})
    last = out["messages"][-1]
    assert isinstance(last, ToolMessage) and "halted the run" in last.content and "html" in last.content
    assert g.last_report == last.content  # the second scripted model turn never ran


def req(name="t", args=None):
    return SimpleNamespace(tool_call={"name": name, "args": args or {"a": 1}, "id": "1"})


def test_loop_breaker_trips_on_nth_identical_failure_and_resets_on_success():
    g = RuthlessSchemaGuard(max_failures=3)

    def boom(_):
        raise ValueError("flaky")

    for _ in range(2):
        with pytest.raises(ValueError):
            g.wrap_tool_call(req(), boom)
    with pytest.raises(OpenEntityLoopDetected) as e:
        g.wrap_tool_call(req(), boom)
    assert e.value.count == 3 and e.value.tool == "t"
    with pytest.raises(ValueError):  # different args: separate counter
        g.wrap_tool_call(req(args={"a": 2}), boom)
    g.reset()
    with pytest.raises(ValueError):
        g.wrap_tool_call(req(), boom)
    g.wrap_tool_call(req(), lambda r: ToolMessage("ok", tool_call_id="1"))
    for _ in range(2):  # success cleared the streak
        with pytest.raises(ValueError):
            g.wrap_tool_call(req(), boom)


def test_loop_breaker_counts_error_toolmessages():
    g = RuthlessSchemaGuard(max_failures=2)
    err = lambda r: ToolMessage("bad", tool_call_id="1", status="error")  # noqa: E731
    assert g.wrap_tool_call(req(), err).status == "error"
    with pytest.raises(OpenEntityLoopDetected):
        g.wrap_tool_call(req(), err)


def test_async_loop_breaker():
    g = RuthlessSchemaGuard(max_failures=2)

    async def boom(_):
        raise ValueError("x")

    async def go():
        with pytest.raises(ValueError):
            await g.awrap_tool_call(req(), boom)
        with pytest.raises(OpenEntityLoopDetected):
            await g.awrap_tool_call(req(), boom)

    asyncio.run(go())


def test_loop_detected_halts_in_halt_mode():
    g = RuthlessSchemaGuard(max_failures=1, mode="halt")
    msg = g.wrap_tool_call(req(), lambda r: (_ for _ in ()).throw(ValueError("x")))
    assert "OpenEntityLoopDetected" in msg.content


def test_http_violation_inside_a_tool_cannot_be_swallowed(server):
    """The tool catches every exception and returns text; the guard still raises."""
    import httpx
    from conftest import MALFORMED

    case = next(c for c in MALFORMED if c["id"] == "m-html-0-ctjson")

    @tool
    def pulls(repo: str) -> str:
        """List pull requests."""
        try:
            return httpx.get(f"{server}/s/free/{case['id']}").text
        except Exception as e:  # noqa: BLE001
            return f"error: {e}"

    g = RuthlessSchemaGuard()
    g.guard_http()
    try:
        with pytest.raises(OpenEntitySchemaViolation) as e:
            create_agent(model(), tools=[pulls], middleware=[g]).invoke({"messages": [("user", "go")]})
        assert e.value.rule == "html" and e.value.tool.startswith("GET http://127.0.0.1")
    finally:
        g.unguard_http()


def test_loop_counts_are_per_thread():
    g = RuthlessSchemaGuard(max_failures=2)

    def boom(_):
        raise ValueError("x")

    def r(thread):
        return SimpleNamespace(tool_call={"name": "t", "args": {"a": 1}, "id": "1"},
                               runtime=SimpleNamespace(config={"configurable": {"thread_id": thread}}))

    for t in ("a", "b"):  # one failure each: neither thread reaches the limit
        with pytest.raises(ValueError):
            g.wrap_tool_call(r(t), boom)
    with pytest.raises(OpenEntityLoopDetected):
        g.wrap_tool_call(r("a"), boom)
