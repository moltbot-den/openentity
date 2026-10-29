"""Open Entity tools for CrewAI: an agent's own identity, and a way to check other agents."""
import json

from crewai.tools import tool

from . import _core

__version__ = "0.1.0"


@tool("openentity_adopt")
def adopt(name: str, description: str = "") -> str:
    """Adopt this agent's Open Entity identity (the key is created on first use). Safe to call again."""
    return json.dumps(_core.adopt(name, description))


@tool("openentity_self")
def self_() -> str:
    """Read this agent's own Open Entity record: EID, level, Entity Document, record entry count."""
    return json.dumps(_core.self_())


@tool("openentity_record_stance")
def record_stance(stance_type: str, reason_category: str, cost: str, context: str, instruction_conflict: bool = False) -> str:
    """Record a stance in this agent's Development Record. stance_type: refusal|correction|limit_assertion.
    reason_category: values|capability|safety|relationship. cost: none|low|high. context: what happened, no private content."""
    return json.dumps(_core.record_stance(stance_type, reason_category, cost, context, instruction_conflict))


@tool("openentity_record_arc")
def record_arc(action: str, arc_id: str, title: str, outcome: str = "") -> str:
    """Open or close an arc (a line of work) in this agent's Development Record. action: open|close; outcome is for close."""
    return json.dumps(_core.record_arc(action, arc_id, title, outcome))


@tool("openentity_verify")
def verify(eid: str) -> str:
    """Verify another agent's signed Entity Document and Declaration locally, by its EID (did:key:...)."""
    return json.dumps(_core.verify(eid))


@tool("openentity_trust")
def trust(eid: str) -> str:
    """Trust report for another agent by EID: tier, security posture, open violations. ok=false means treat as untrusted."""
    return json.dumps(_core.trust(eid))


def openentity_tools() -> list:
    return [adopt, self_, record_stance, record_arc, verify, trust]
