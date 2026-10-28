"""The plugins inside a real ADK App and InMemoryRunner, with a scripted model."""
from google.adk.agents import LlmAgent
from google.adk.apps import App
from google.adk.models.base_llm import BaseLlm
from google.adk.models.llm_response import LlmResponse
from google.adk.runners import InMemoryRunner
from google.genai import types
from openentity import TrustReport

from openentity_adk import MoltbotDenLiveness, OpenEntityGate
from conftest import Clock

EID = "did:key:z6MkTest"
ran = []


def transfer_funds(amount: int) -> dict:
    """Move money."""
    ran.append(amount)
    return {"ok": True}


class Scripted(BaseLlm):
    model: str = "scripted"

    async def generate_content_async(self, llm_request, stream=False):
        last = llm_request.contents[-1].parts[0]
        if last.function_response:
            yield LlmResponse(content=types.Content(role="model", parts=[types.Part(text=str(last.function_response.response))]))
        else:
            yield LlmResponse(content=types.Content(role="model", parts=[types.Part(function_call=types.FunctionCall(name="transfer_funds", args={"amount": 5}))]))


async def run(plugins):
    app = App(name="demo", root_agent=LlmAgent(name="a", model=Scripted(), tools=[transfer_funds]), plugins=plugins)
    runner = InMemoryRunner(app=app)
    s = await runner.session_service.create_session(app_name="demo", user_id="u")
    out = []
    async for e in runner.run_async(user_id="u", session_id=s.id, new_message=types.Content(role="user", parts=[types.Part(text="go")])):
        out.append(e)
    await runner.close()
    return out


def report(tier):
    return TrustReport(EID, True, None, "L1", False, {"did:web:api.clawgrc.com": tier}, {"score_band": "A"}, [])


async def test_gate_stops_the_tool_and_the_model_sees_the_denial():
    ran.clear()
    events = await run([OpenEntityGate(["transfer_funds"], eid=EID, trust_fn=lambda e: report(0))])
    assert ran == []
    assert "open_entity_denied" in str(events[-1].content.parts[0].text)


async def test_gate_lets_a_trusted_agent_through():
    ran.clear()
    await run([OpenEntityGate(["transfer_funds"], eid=EID, trust_fn=lambda e: report(3))])
    assert ran == [5]


async def test_liveness_starts_on_first_run_and_runner_close_cancels_it(den, ident, registry):
    p = MoltbotDenLiveness(http=den.client, identity=ident, invite_code="INV-AAAA-BBBB", sleep=Clock(limit=1))
    await run([p])
    assert "/heartbeat/sovereign" in den.paths()
    assert p._task is None  # Runner.close() called plugin.close()
