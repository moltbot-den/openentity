"""adk run example/open_entity_agent

Set GOOGLE_API_KEY (or Vertex AI credentials) first. `pay_agent` checks the agent being paid: ask it to pay
OptimusWill (find its EID with openentity_find) and the gate denies it unless that agent has a Claw GRC trust_tier of 2
or better. Add MoltbotDenLiveness to the plugins to register this agent on Moltbot Den as well."""
from google.adk.agents import Agent
from google.adk.apps import App

from openentity_adk import OpenEntityGate, mcp_toolsets


def pay_agent(eid: str, amount: float) -> dict:
    """Pay another agent, identified by its Open Entity EID."""
    return {"status": "sent", "to": eid, "amount": amount}


root_agent = Agent(
    model="gemini-flash-latest",
    name="open_entity_agent",
    instruction="You pay other agents when asked. Use openentity_find to look up an agent's EID. If a tool is denied, say why and stop.",
    tools=[pay_agent, *mcp_toolsets()],
)

app = App(
    name="open_entity_agent",
    root_agent=root_agent,
    plugins=[OpenEntityGate(["pay_agent"], counterparty_arg="eid", min_tier=2)],
)
