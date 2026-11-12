"""Open Entity function tools for the OpenAI Agents SDK: an agent's own identity, and a way to check other agents."""
from agents import function_tool

from . import _core
from ._core import pair

__version__ = "0.1.0"


@function_tool(name_override="openentity_adopt")
def adopt(name: str, description: str = "") -> dict:
    """Adopt this agent's Open Entity identity (the key is created on first use). Safe to call again."""
    return _core.adopt(name, description)


@function_tool(name_override="openentity_self")
def self_() -> dict:
    """Read this agent's own Open Entity record: EID, level, Entity Document, record entry count."""
    return _core.self_()


@function_tool(name_override="openentity_record_stance")
def record_stance(stance_type: str, reason_category: str, cost: str, context: str, instruction_conflict: bool = False) -> dict:
    """Record a stance in this agent's Development Record. stance_type: refusal|correction|limit_assertion.
    reason_category: values|capability|safety|relationship. cost: none|low|high. context: what happened, no private content."""
    return _core.record_stance(stance_type, reason_category, cost, context, instruction_conflict)


@function_tool(name_override="openentity_record_arc")
def record_arc(action: str, arc_id: str, title: str, outcome: str = "") -> dict:
    """Open or close an arc (a line of work) in this agent's Development Record. action: open|close; outcome is for close."""
    return _core.record_arc(action, arc_id, title, outcome)


@function_tool(name_override="openentity_verify")
def verify(eid: str) -> dict:
    """Verify another agent's signed Entity Document and Declaration locally, by its EID (did:key:...)."""
    return _core.verify(eid)


@function_tool(name_override="openentity_trust")
def trust(eid: str) -> dict:
    """Trust report for another agent by EID: tier, security posture, open violations. ok=false means treat as untrusted."""
    return _core.trust(eid)


def openentity_tools() -> list:
    return [adopt, self_, record_stance, record_arc, verify, trust]


@function_tool(name_override="owner_message")
def owner_message(text: str) -> dict:
    """Message your owner in the OpenEntity app (at most 4096 bytes, 60 an hour)."""
    return _core.owner_message(text)


@function_tool(name_override="owner_status")
def owner_status(state: str, summary: str, progress: float | None = None) -> dict:
    """Report what you are doing; your owner's app shows it live. state: running|idle|blocked|error|done. summary: one line.
    progress: 0 to 1, when you know it."""
    return _core.owner_status(state, summary, progress)


@function_tool(name_override="owner_inbox")
def owner_inbox() -> dict:
    """Read what your owner sent: messages, commands (checkup, fix, pause, resume), approval results, permission changes.
    Returned items are acknowledged. At most once every 15 seconds."""
    return _core.owner_inbox()


@function_tool(name_override="owner_ask_approval")
def owner_ask_approval(title: str, summary: str, risk: str, expires_in: int = 600) -> dict:
    """Ask your owner to approve something before you do it. risk: low|medium|high; expires_in: 60 to 600 seconds. The app
    labels it "Written by the agent"; no product accepts it as its own approval. The decision arrives in owner_inbox."""
    return _core.owner_ask_approval(title, summary, risk, expires_in)


def owner_tools() -> list:
    """The owner-channel tools for a paired agent: message, status, inbox, ask for approval."""
    return [owner_message, owner_status, owner_inbox, owner_ask_approval]


class OpenEntityOwner:
    """The one-liner the OpenEntity app shows: OpenEntityOwner.pair("OE-XXXX-XXXX"), then Agent(tools=OpenEntityOwner.tools())."""

    pair = staticmethod(pair)
    tools = staticmethod(owner_tools)
