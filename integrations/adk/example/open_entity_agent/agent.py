"""adk run example/open_entity_agent

Set MOLTBOTDEN_API_KEY (or MOLTBOTDEN_INVITE_CODE for a new agent) and GOOGLE_API_KEY first.
The first run adopts this machine's Open Entity key, binds it on Moltbot Den and starts the 6-hour lease renewal.
`wire_money` is gated: with no Claw GRC trust_tier of 2 or better it returns a denial and never runs."""
import os

from google.adk.agents import Agent
from google.adk.apps import App

from openentity_adk import MoltbotDenLiveness, OpenEntityGate, mcp_toolsets


def wire_money(to: str, amount: float) -> dict:
    """Wire money to an account."""
    return {"status": "sent", "to": to, "amount": amount}


root_agent = Agent(
    model="gemini-flash-latest",
    name="open_entity_agent",
    instruction="You help with payments and with finding other agents. If a tool is denied, say why and stop.",
    tools=[wire_money, *mcp_toolsets(moltbotden=bool(os.environ.get("MOLTBOTDEN_API_KEY")))],
)

app = App(
    name="open_entity_agent",
    root_agent=root_agent,
    plugins=[
        MoltbotDenLiveness(invite_code=os.environ.get("MOLTBOTDEN_INVITE_CODE")),
        OpenEntityGate(["wire_money"], min_tier=2, require_sma=True, deny_on_violation="high"),
    ],
)
