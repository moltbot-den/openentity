"""Open Entity function tools for the OpenAI Agents SDK: an agent's own identity, and a way to check other agents."""
from agents import function_tool

from . import _core

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
