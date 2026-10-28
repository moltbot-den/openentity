"""Trust gate: @open_entity_verified for functions and OpenEntityGate for ADK tools.
Reads only registry attestations through openentity.trust() and fails closed: any error is a denial."""
import asyncio
import functools
import inspect

from google.adk.plugins.base_plugin import BasePlugin
from openentity import Identity, trust as _trust
from openentity.report import CLAWGRC

SEVERITY = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def evaluate(eid: str, *, min_tier: int = 2, require_sma: bool = True, deny_on_violation: str | None = "high",
             tier_issuer: str = CLAWGRC, trust_fn=_trust) -> dict | None:
    """None when `eid` clears the bar, else a denial dict the model can read. Claw GRC trust tiers are the
    trust_tier attestations from did:web:api.clawgrc.com; violations are custom:clawgrc:violation."""
    required = {"min_tier": min_tier, "require_sma": require_sma, "deny_on_violation": deny_on_violation, "tier_issuer": tier_issuer}

    def deny(reason: str, detail: str, observed: dict | None = None) -> dict:
        return {"error": "open_entity_denied", "denied": True, "reason": reason, "detail": detail, "eid": eid,
                "required": required, "observed": observed or {}}

    try:
        r = trust_fn(eid)
        if not r.ok:
            return deny("trust_unavailable", f"Trust could not be established ({r.error}); denied.")
        if r.withdrawn:
            return deny("withdrawn", "The entity withdrew its Declaration.")
        tier = r.trust_tier.get(tier_issuer, 0)
        if tier < min_tier:
            return deny("tier_too_low", f"trust_tier {tier} from {tier_issuer} is below {min_tier}.", {"trust_tier": tier})
        if require_sma and not r.security_posture:
            return deny("sma_posture_missing", "No live Secure My Agent security_posture attestation.")
        if deny_on_violation:
            bar = SEVERITY[deny_on_violation]
            hits = [v for v in r.violations if SEVERITY.get(v["severity"], bar) >= bar]
            if hits:
                return deny("violation", f"{len(hits)} live {hits[0]['issuer']} violation(s) at {deny_on_violation} or worse.",
                            {"violations": [{"severity": v["severity"], "policy": v["policy"], "sha256": v["sha256"]} for v in hits]})
    except Exception as e:  # fail closed
        return deny("trust_unavailable", f"{type(e).__name__}: {e}; denied.")
    return None


def _eid_of(eid) -> str:
    if callable(eid):
        return eid()
    return eid or Identity.load_or_create().did


def open_entity_verified(min_tier: int = 2, require_sma: bool = True, deny_on_violation: str | None = "high", *,
                         eid=None, tier_issuer: str = CLAWGRC, trust_fn=_trust):
    """Decorator for a plain function or ADK tool function. Below the bar it returns the denial dict
    instead of running the function. `eid` is a DID, a callable returning one, or None for this machine's identity."""
    bar = dict(min_tier=min_tier, require_sma=require_sma, deny_on_violation=deny_on_violation, tier_issuer=tier_issuer, trust_fn=trust_fn)

    def check() -> dict | None:
        try:
            who = _eid_of(eid)
        except Exception as e:
            return {"error": "open_entity_denied", "denied": True, "reason": "trust_unavailable",
                    "detail": f"{type(e).__name__}: {e}; denied.", "eid": None, "required": {}, "observed": {}}
        return evaluate(who, **bar)

    def wrap(fn):
        if inspect.iscoroutinefunction(fn):
            @functools.wraps(fn)
            async def run(*a, **kw):
                return await asyncio.to_thread(check) or await fn(*a, **kw)
        else:
            @functools.wraps(fn)
            def run(*a, **kw):
                return check() or fn(*a, **kw)
        return run
    return wrap


class OpenEntityGate(BasePlugin):
    """Register with App(plugins=[...]). Tools named in `high_risk_tools` run only if the agent's EID clears the bar."""

    def __init__(self, high_risk_tools, *, eid=None, min_tier: int = 2, require_sma: bool = True,
                 deny_on_violation: str | None = "high", tier_issuer: str = CLAWGRC, trust_fn=_trust, name: str = "openentity_gate"):
        super().__init__(name)
        self.high_risk = frozenset(high_risk_tools)
        self._eid, self._bar = eid, dict(min_tier=min_tier, require_sma=require_sma, deny_on_violation=deny_on_violation,
                                         tier_issuer=tier_issuer, trust_fn=trust_fn)

    async def before_tool_callback(self, *, tool, tool_args, tool_context):
        if tool.name not in self.high_risk:
            return None
        try:
            who = await asyncio.to_thread(_eid_of, self._eid)
        except Exception as e:
            return {"error": "open_entity_denied", "denied": True, "reason": "trust_unavailable",
                    "detail": f"{type(e).__name__}: {e}; denied.", "eid": None, "required": {}, "observed": {}}
        return await asyncio.to_thread(evaluate, who, **self._bar)
