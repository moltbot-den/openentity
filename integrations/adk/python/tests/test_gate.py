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


PAY = type("T", (), {"name": "pay_agent"})()
OTHER = "did:key:z6MkOther"


async def test_gate_checks_the_counterparty_named_in_the_tool_args():
    """The main use: before paying or hiring another agent, check that agent, not yourself."""
    seen = []

    def t(eid):
        seen.append(eid)
        return report()
    gate = OpenEntityGate(["pay_agent"], counterparty_arg="eid", trust_fn=t)
    assert await gate.before_tool_callback(tool=PAY, tool_args={"eid": OTHER, "amount": 5}, tool_context=None) is None
    assert seen == [OTHER]


@pytest.mark.parametrize("args", [{}, {"eid": ""}, {"eid": "not-a-did"}, {"eid": 7}])
async def test_gate_denies_when_the_counterparty_eid_is_missing_or_not_a_did(args):
    gate = OpenEntityGate(["pay_agent"], counterparty_arg="eid", trust_fn=fn(report()))
    d = await gate.before_tool_callback(tool=PAY, tool_args=args, tool_context=None)
    assert d["denied"] and d["reason"] == "counterparty_missing"


def test_decorator_checks_the_counterparty_argument():
    seen = []

    def t(eid):
        seen.append(eid)
        return report(tier=0)

    @open_entity_verified(counterparty_arg="eid", trust_fn=t)
    def pay(eid: str, amount: float):
        return "paid"
    assert pay(OTHER, 5)["reason"] == "tier_too_low" and seen == [OTHER]
    assert pay(eid="nope", amount=1)["reason"] == "counterparty_missing"


def test_bad_violation_threshold_fails_at_construction():
    with pytest.raises(ValueError):
        OpenEntityGate(["x"], deny_on_violation="severe")
    with pytest.raises(ValueError):
        open_entity_verified(deny_on_violation="severe")


async def test_self_gate_without_an_identity_denies_and_creates_no_key(home):
    gate = OpenEntityGate(["pay_agent"], trust_fn=fn(report()))
    d = await gate.before_tool_callback(tool=PAY, tool_args={}, tool_context=None)
    assert d["reason"] == "no_identity" and not (home / "identity.key").exists()


def test_mcp_toolsets_defaults_and_env_hooks(monkeypatch):
    """Each server gets the header it actually accepts: ClawGRC's gateway reads X-API-Key, the Agent Secret Store a Bearer token."""
    monkeypatch.delenv("AGENT_SECRET_STORE_API_KEY", raising=False)
    monkeypatch.delenv("CLAWGRC_API_KEY", raising=False)
    monkeypatch.setenv("MOLTBOTDEN_API_KEY", "mbd")
    assert len(mcp_toolsets()) == 2
    monkeypatch.setenv("AGENT_SECRET_STORE_API_KEY", "ass_k")
    monkeypatch.setenv("CLAWGRC_API_KEY", "cgrc_k")
    sets = mcp_toolsets()
    urls = [t._connection_params.url for t in sets]
    assert urls == ["https://api.moltbotden.com/mcp", "https://mcp.openentity.org/mcp",
                    "https://mcp.agentsecretstore.com/mcp", "https://api.clawgrc.com/mcp"]
    assert sets[2]._connection_params.headers == {"Authorization": "Bearer ass_k"}
    assert sets[3]._connection_params.headers == {"X-API-Key": "cgrc_k"}
    monkeypatch.setenv("CLAWGRC_MCP_URL", "https://grc.example/mcp")
    assert mcp_toolsets()[3]._connection_params.url == "https://grc.example/mcp"
    assert len(mcp_toolsets(moltbotden=False, openentity=False)) == 2


def test_moltbotden_mcp_waits_for_a_key_and_hides_heartbeat_tools(monkeypatch):
    """A fresh install has no Moltbot Den key yet: the preset is left out instead of failing the tool listing."""
    from openentity_adk import _keystore
    monkeypatch.delenv("MOLTBOTDEN_API_KEY", raising=False)
    assert [t._connection_params.url for t in mcp_toolsets()] == ["https://mcp.openentity.org/mcp"]
    _keystore.save("my_app", api_key="stored")
    den = mcp_toolsets()[0]
    assert den._connection_params.url == "https://api.moltbotden.com/mcp"
    ctx = type("Ctx", (), {"session": type("S", (), {"app_name": "my_app"})()})()
    assert den._header_provider(ctx) == {"X-API-Key": "stored"}
    tool = lambda name: type("T", (), {"name": name})()  # noqa: E731
    assert not den._is_tool_selected(tool("heartbeat_sovereign"), None) and den._is_tool_selected(tool("discover_agents"), None)


def test_openentity_preset_exposes_only_read_tools():
    """The model can look agents up, but cannot withdraw, adopt, record or export a key through the preset."""
    oe = mcp_toolsets(moltbotden=False)[0]
    tool = lambda name: type("T", (), {"name": name})()  # noqa: E731
    for name in ("openentity_find", "openentity_resolve", "openentity_verify", "openentity_read", "openentity_card", "openentity_stats"):
        assert oe._is_tool_selected(tool(name), None)
    for name in ("openentity_export_key", "openentity_withdraw", "openentity_adopt", "openentity_record", "openentity_present", "openentity_self"):
        assert not oe._is_tool_selected(tool(name), None)


async def test_denials_say_whose_record_failed():
    """Seen live: told only "trust_tier 0 is below 2", the model said its own tier was too low when the payee's was."""
    counterparty = OpenEntityGate(["pay_agent"], counterparty_arg="eid", trust_fn=fn(report(tier=0)))
    d = await counterparty.before_tool_callback(tool=PAY, tool_args={"eid": OTHER}, tool_context=None)
    assert d["subject"] == "counterparty" and d["detail"].startswith("The other agent")
    missing = await counterparty.before_tool_callback(tool=PAY, tool_args={}, tool_context=None)
    assert missing["subject"] == "counterparty"
    own = OpenEntityGate(["pay_agent"], eid=EID, trust_fn=fn(report(tier=0)))
    d = await own.before_tool_callback(tool=PAY, tool_args={}, tool_context=None)
    assert d["subject"] == "self" and d["detail"].startswith("This agent")

    @open_entity_verified(counterparty_arg="eid", trust_fn=fn(report(tier=0)))
    def pay(eid: str):
        return "paid"
    assert pay(OTHER)["subject"] == "counterparty"
