"""Trust gate: @open_entity_verified for functions and OpenEntityGate for ADK tools.
It checks the counterparty named in a tool argument (counterparty_arg), or this agent's own EID (a kill switch Claw GRC
can pull). Reads only registry attestations through openentity.trust() and fails closed: any error is a denial."""
import asyncio
import functools
import inspect

from google.adk.plugins.base_plugin import BasePlugin
from openentity import Identity, trust as _trust
from openentity.report import CLAWGRC

SEVERITY = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _check_threshold(deny_on_violation: str | None) -> None:
    if deny_on_violation is not None and deny_on_violation not in SEVERITY:
        raise ValueError(f"deny_on_violation must be one of {list(SEVERITY)} or None, not {deny_on_violation!r}")


def _denial(eid, reason: str, detail: str, required: dict | None = None, observed: dict | None = None) -> dict:
    return {"error": "open_entity_denied", "denied": True, "reason": reason, "detail": detail, "eid": eid,
            "required": required or {}, "observed": observed or {}}


def evaluate(eid: str, *, min_tier: int = 2, require_sma: bool = True, deny_on_violation: str | None = "high",
             tier_issuer: str = CLAWGRC, trust_fn=_trust) -> dict | None:
    """None when `eid` clears the bar, else a denial dict the model can read. Claw GRC trust tiers are the
    trust_tier attestations from did:web:api.clawgrc.com; violations are custom:clawgrc:violation."""
    _check_threshold(deny_on_violation)
    required = {"min_tier": min_tier, "require_sma": require_sma, "deny_on_violation": deny_on_violation, "tier_issuer": tier_issuer}

    def deny(reason: str, detail: str, observed: dict | None = None) -> dict:
        return _denial(eid, reason, detail, required, observed)

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


def _check(eid, counterparty_arg: str | None, args: dict, bar: dict) -> dict | None:
    """Run the bar on the subject; a denial names whose record failed, so the model does not blame itself for the payee."""
    who, denied = _subject(eid, counterparty_arg, args)
    denied = denied or evaluate(who, **bar)
    if denied:
        denied["subject"] = "counterparty" if counterparty_arg else "self"
        denied["detail"] = ("The other agent" if counterparty_arg else "This agent") + f" was checked: {denied['detail']}"
    return denied


def _subject(eid, counterparty_arg: str | None, args: dict) -> tuple[str | None, dict | None]:
    """Whose trust to check: (eid, None), or (None, denial) when there is no one to check."""
    if counterparty_arg:
        who = args.get(counterparty_arg)
        if isinstance(who, str) and who.startswith("did:"):
            return who, None
        return None, _denial(None, "counterparty_missing",
                             f"Tool argument {counterparty_arg!r} must hold the other agent's EID (a DID); denied.")
    try:
        if callable(eid):
            return eid(), None
        if eid:
            return eid, None
        found = Identity.load()  # never creates a key
    except Exception as e:
        return None, _denial(None, "trust_unavailable", f"{type(e).__name__}: {e}; denied.")
    if found is None:
        return None, _denial(None, "no_identity", "This agent has no Open Entity identity yet; denied.")
    return found.did, None


def open_entity_verified(min_tier: int = 2, require_sma: bool = True, deny_on_violation: str | None = "high", *,
                         counterparty_arg: str | None = None, eid=None, tier_issuer: str = CLAWGRC, trust_fn=_trust):
    """Decorator for a plain function or ADK tool function. Below the bar it returns the denial dict instead of running
    the function. With `counterparty_arg`, the EID in that argument is checked; otherwise `eid` (a DID, a callable
    returning one, or None for this machine's existing identity)."""
    _check_threshold(deny_on_violation)
    bar = dict(min_tier=min_tier, require_sma=require_sma, deny_on_violation=deny_on_violation, tier_issuer=tier_issuer, trust_fn=trust_fn)

    def wrap(fn):
        sig = inspect.signature(fn)

        def check(a, kw) -> dict | None:
            try:
                args = sig.bind_partial(*a, **kw).arguments
            except TypeError:
                args = {}
            return _check(eid, counterparty_arg, args, bar)

        if inspect.iscoroutinefunction(fn):
            async def run(*a, **kw):
                return await asyncio.to_thread(check, a, kw) or await fn(*a, **kw)
        else:
            def run(*a, **kw):
                return check(a, kw) or fn(*a, **kw)
        return functools.wraps(fn)(run)
    return wrap


class OpenEntityGate(BasePlugin):
    """Register with App(plugins=[...]). Tools named in `high_risk_tools` run only if the subject clears the bar: the EID
    in the tool argument `counterparty_arg` when set, else `eid` or this machine's existing identity."""

    def __init__(self, high_risk_tools, *, counterparty_arg: str | None = None, eid=None, min_tier: int = 2,
                 require_sma: bool = True, deny_on_violation: str | None = "high", tier_issuer: str = CLAWGRC,
                 trust_fn=_trust, name: str = "openentity_gate"):
        super().__init__(name)
        _check_threshold(deny_on_violation)
        self.high_risk = frozenset(high_risk_tools)
        self.counterparty_arg, self._eid = counterparty_arg, eid
        self._bar = dict(min_tier=min_tier, require_sma=require_sma, deny_on_violation=deny_on_violation,
                         tier_issuer=tier_issuer, trust_fn=trust_fn)

    async def before_tool_callback(self, *, tool, tool_args, tool_context):
        if tool.name not in self.high_risk:
            return None

        return await asyncio.to_thread(_check, self._eid, self.counterparty_arg, tool_args or {}, self._bar)
