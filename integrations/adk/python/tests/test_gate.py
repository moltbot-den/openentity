import inspect

import pytest
from openentity import TrustReport, trust as real_trust

from openentity_adk import OpenEntityGate, evaluate, open_entity_verified
from openentity_adk.mcp import mcp_toolsets

EID = "did:key:z6MkTest"
CGRC = "did:web:api.clawgrc.com"
POSTURE = {"score_band": "A", "checks_passed": [], "scanner_version": "1", "evidence_hash": "00"}


def report(tier=3, posture=POSTURE, violations=(), ok=True, withdrawn=False):
    return TrustReport(EID, ok, None if ok else "boom", "L1", withdrawn, {CGRC: tier} if tier is not None else {}, posture, list(violations))


def viol(severity):
    return {"issuer": CGRC, "severity": severity, "policy": "p", "observed_at": "t", "sha256": "ab"}


def fn(r):
    return lambda eid: r


def test_clean_entity_passes():
    assert evaluate(EID, trust_fn=fn(report())) is None


@pytest.mark.parametrize("r,reason", [
    (report(tier=1), "tier_too_low"),
    (report(tier=None), "tier_too_low"),
    (report(posture=None), "sma_posture_missing"),
    (report(violations=[viol("high")]), "violation"),
    (report(violations=[viol("critical")]), "violation"),
    (report(withdrawn=True), "withdrawn"),
    (report(ok=False), "trust_unavailable"),
])
def test_below_the_bar_returns_a_structured_denial(r, reason):
    d = evaluate(EID, trust_fn=fn(r))
    assert d["error"] == "open_entity_denied" and d["denied"] is True and d["reason"] == reason
    assert d["eid"] == EID and set(d["required"]) == {"min_tier", "require_sma", "deny_on_violation", "tier_issuer"}
    assert isinstance(d["detail"], str) and isinstance(d["observed"], dict)


def test_violation_below_threshold_is_allowed_and_threshold_is_configurable():
    low = report(violations=[viol("medium")])
    assert evaluate(EID, trust_fn=fn(low)) is None
    assert evaluate(EID, deny_on_violation="low", trust_fn=fn(low))["reason"] == "violation"
    assert evaluate(EID, deny_on_violation=None, trust_fn=fn(report(violations=[viol("critical")]))) is None


def test_sma_can_be_waived():
    assert evaluate(EID, require_sma=False, trust_fn=fn(report(posture=None))) is None


def test_fails_closed_when_trust_raises():
    def boom(eid):
        raise RuntimeError("registry down")
    d = evaluate(EID, trust_fn=boom)
    assert d["reason"] == "trust_unavailable" and "registry down" in d["detail"]


def test_fails_closed_on_the_real_trust_with_an_unreachable_registry():
    def fetch(url, *a, **k):
        raise OSError("no network")
    d = evaluate(EID, trust_fn=lambda eid: real_trust(eid, "https://registry.invalid", fetch=fetch))
    assert d["reason"] == "trust_unavailable"


def test_decorator_blocks_sync_function_and_keeps_its_signature():
    calls = []

    @open_entity_verified(eid=EID, trust_fn=fn(report(tier=0)))
    def send(to: str, amount: int = 1) -> dict:
        """Send money."""
        calls.append(to)
        return {"sent": True}

    assert send("a")["reason"] == "tier_too_low" and calls == []
    assert list(inspect.signature(send).parameters) == ["to", "amount"] and send.__doc__ == "Send money."


def test_decorator_runs_function_when_clear():
    @open_entity_verified(eid=EID, trust_fn=fn(report()))
    def send(to):
        return {"sent": to}
    assert send("a") == {"sent": "a"}


async def test_decorator_on_async_function():
    @open_entity_verified(eid=lambda: EID, trust_fn=fn(report(posture=None)))
    async def send(to):
        return {"sent": to}
    assert (await send("a"))["reason"] == "sma_posture_missing"

    @open_entity_verified(eid=EID, trust_fn=fn(report()))
    async def ok(to):
        return {"sent": to}
    assert await ok("a") == {"sent": "a"}


def test_decorator_denies_when_no_identity_can_be_loaded():
    def no_id():
        raise OSError("keystore unreadable")

    @open_entity_verified(eid=no_id, trust_fn=fn(report()))
    def f():
        return "ran"
    assert f()["reason"] == "trust_unavailable"


async def test_gate_plugin_checks_only_listed_tools():
    seen = []

    def t(eid):
        seen.append(eid)
        return report(tier=0)

    gate = OpenEntityGate(["transfer_funds"], eid=EID, trust_fn=t)
    other = type("T", (), {"name": "search"})()
    risky = type("T", (), {"name": "transfer_funds"})()
    assert await gate.before_tool_callback(tool=other, tool_args={}, tool_context=None) is None and seen == []
    d = await gate.before_tool_callback(tool=risky, tool_args={}, tool_context=None)
    assert d["denied"] and d["reason"] == "tier_too_low" and seen == [EID]
    allowed = OpenEntityGate(["transfer_funds"], eid=EID, trust_fn=fn(report()))
    assert await allowed.before_tool_callback(tool=risky, tool_args={}, tool_context=None) is None


def test_mcp_toolsets_defaults_and_env_hooks(monkeypatch):
    assert len(mcp_toolsets()) == 2
    monkeypatch.setenv("AGENT_SECRET_STORE_MCP_URL", "https://ass.example/mcp")
    monkeypatch.setenv("CLAWGRC_MCP_URL", "https://grc.example/mcp")
    sets = mcp_toolsets()
    urls = [t._connection_params.url for t in sets]
    assert urls == ["https://api.moltbotden.com/mcp", "https://mcp.openentity.org/mcp", "https://ass.example/mcp", "https://grc.example/mcp"]
    assert len(mcp_toolsets(moltbotden=False, openentity=False)) == 2
