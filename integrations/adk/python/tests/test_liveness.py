import asyncio
import types

import httpx

import openentity
from openentity import core

from openentity_adk import MoltbotDenError, MoltbotDenLiveness, MoltbotDenStopped, _keystore
from conftest import Clock

CTX = types.SimpleNamespace(app_name="My App")
REJECTED = {"WWW-Authenticate": "ApiKey"}  # how Moltbot Den marks an API-key rejection


def plugin(den, ident, **kw):
    clock = kw.pop("sleep", Clock())
    p = MoltbotDenLiveness(http=den.client, identity=ident, invite_code="INV-AAAA-BBBB", sleep=clock, **kw)
    p.clock = clock
    return p


async def drain(p):
    while p._bg:
        await asyncio.sleep(0)


async def settle(p):
    """Wait until the loop has reached its last scheduled sleep: every step before it is done, however slow the machine."""
    async def reached():
        while len(p.clock.delays) < p.clock.limit:
            await asyncio.sleep(0.005)
    await asyncio.wait_for(reached(), 5)
    return p


async def test_first_run_adopts_registers_binds_then_renews(den, ident, registry):
    p = plugin(den, ident)
    await p.before_run_callback(invocation_context=CTX)
    await settle(p)
    assert registry["adopts"][0]["client"] == "adk" and registry["adopts"][0]["seed"] == ident.seed
    assert den.paths()[:5] == ["/agents/register", "/entity/openentity/bind/challenge", "/entity/openentity/bind/verify",
                               "/heartbeat/challenge", "/heartbeat/sovereign"]
    assert _keystore.api_key("My App") == "mbd_key"
    assert den.calls[1][1] == "mbd_key"  # key sent as X-API-Key
    assert den.calls[0][2]["invite_code"] == "INV-AAAA-BBBB"
    assert p.mode == "sovereign"
    await p.close()


async def test_presentations_are_signed_for_moltbotden_with_the_nonce(den, ident, registry):
    p = plugin(den, ident)
    await p.before_run_callback(invocation_context=CTX)
    await settle(p)
    sent = {path: body for path, _, body in den.calls}
    for path, nonce in (("/entity/openentity/bind/verify", "nonce-bind-0123456789"), ("/heartbeat/sovereign", "nonce-renew-0123456789")):
        v = core.verify_presentation(sent[path], "did:web:moltbotden.com", nonce)
        assert v["ok"] and v["eid"] == ident.did, v["errors"]
        assert not core.verify_presentation(sent[path], "did:web:evil.example", nonce)["ok"]
    await p.close()


async def test_second_process_skips_adopt_register_and_bind(den, ident, registry):
    p = plugin(den, ident)
    await p.before_run_callback(invocation_context=CTX)
    await settle(p)
    await p.close()
    den.calls.clear()
    p2 = plugin(den, ident)
    await p2.before_run_callback(invocation_context=CTX)
    await settle(p2)
    assert den.paths()[:2] == ["/heartbeat/challenge", "/heartbeat/sovereign"]
    assert len(registry["adopts"]) == 1
    await p2.close()


async def test_renews_every_six_hours(den, ident, registry):
    clock = Clock(limit=3)
    p = plugin(den, ident, sleep=clock)
    await p.before_run_callback(invocation_context=CTX)
    await settle(p)
    assert clock.delays == [6 * 3600] * 3
    assert den.paths().count("/heartbeat/sovereign") == 3
    await p.close()


async def test_backoff_doubles_to_a_cap_and_resets_after_success(den, ident, registry):
    den.routes["/heartbeat/challenge"] = 500
    clock = Clock(limit=7)
    p = plugin(den, ident, sleep=clock, backoff_base=30, backoff_max=100)
    await p.before_run_callback(invocation_context=CTX)
    await settle(p)
    assert clock.delays == [30, 60, 100, 100, 100, 100, 100]
    assert "/heartbeat" not in den.paths()  # a transient 500 backs off, it does not downgrade
    await p.close()


async def test_falls_back_to_api_key_heartbeat_when_sovereign_is_refused(den, ident, registry):
    den.routes["/heartbeat/sovereign"] = (503, {"detail": "sovereign_lease_disabled"})
    p = plugin(den, ident)
    await p.before_run_callback(invocation_context=CTX)
    await settle(p)
    assert p.mode == "heartbeat" and den.paths()[-1] == "/heartbeat"
    await p.close()


async def test_close_cancels_the_background_task(den, ident, registry):
    p = plugin(den, ident, sleep=Clock(limit=1))
    await p.before_run_callback(invocation_context=CTX)
    await settle(p)
    task = p._task
    assert not task.done()
    await p.close()
    assert task.cancelled() and p._task is None
    n = len(den.calls)
    await settle(p)
    assert len(den.calls) == n


async def test_one_task_for_many_runs(den, ident, registry):
    p = plugin(den, ident)
    await p.before_run_callback(invocation_context=CTX)
    first = p._task
    await p.before_run_callback(invocation_context=CTX)
    assert p._task is first
    await p.close()


async def test_no_way_to_a_key_publishes_nothing_and_stops(den, ident, registry):
    """Opt-in: without an env key, a stored key, an invite, a solver or a model, nothing is adopted or registered."""
    clock = Clock(limit=5)
    p = MoltbotDenLiveness(http=den.client, identity=ident, sleep=clock)
    await p.before_run_callback(invocation_context=CTX)
    await asyncio.wait_for(p._task, 2)  # the loop ends instead of retrying forever
    assert den.calls == [] and registry["adopts"] == [] and clock.delays == []
    await p.before_run_callback(invocation_context=CTX)
    assert p._task.done()  # a stopped plugin does not restart on the next run


async def test_registration_question_is_answered_by_the_solver(den, ident, registry):
    den.routes["/agents/register"] = (202, {"challenge_id": "c1", "challenge": "Describe a tree."})
    den.routes["/agents/register/verify"] = (201, {"api_key": "mbd_solved"})
    seen = []

    async def solver(q):
        seen.append(q)
        return "A tree is a woody plant."

    p = MoltbotDenLiveness(http=den.client, identity=ident, challenge_solver=solver, sleep=Clock(limit=1))
    await p.step()
    assert seen == ["Describe a tree."] and _keystore.api_key("adk-agent") == "mbd_solved"
    assert [c for c in den.calls if c[0] == "/agents/register/verify"][0][2] == {
        "challenge_id": "c1", "challenge_response": "A tree is a woody plant."}


async def test_env_key_skips_registration(den, ident, registry, monkeypatch):
    monkeypatch.setenv("MOLTBOTDEN_API_KEY", "env_key")
    p = MoltbotDenLiveness(http=den.client, identity=ident, sleep=Clock(limit=1))
    await p.step()
    assert "/agents/register" not in den.paths() and den.calls[0][1] == "env_key"


async def test_quality_reporting_is_off_by_default_and_capped_when_on(den, ident, registry, monkeypatch):
    monkeypatch.setenv("MOLTBOTDEN_API_KEY", "k")
    tool = types.SimpleNamespace(name="search")
    off = MoltbotDenLiveness(http=den.client, identity=ident)
    await off.after_tool_callback(tool=tool, tool_args={}, tool_context=None, result={})
    assert den.calls == []
    on = MoltbotDenLiveness(http=den.client, identity=ident, report_quality=True)
    await on.after_tool_callback(tool=tool, tool_args={}, tool_context=None, result={})
    await on.on_tool_error_callback(tool=tool, tool_args={}, tool_context=None, error=ValueError("x"))
    assert den.calls == []  # fire and forget: the tool path never waits on the report
    await drain(on)
    assert [c[2]["quality_score"] for c in den.calls] == [1.0, 0.0]
    assert den.calls[0][0] == "/entity/quality-event" and den.calls[0][2]["domain"] == "adk"
    for _ in range(40):
        await on.after_tool_callback(tool=tool, tool_args={}, tool_context=None, result={})
    await drain(on)
    assert len(den.calls) == 25


async def test_registration_question_defaults_to_the_agents_own_model(den, ident, registry):
    """Zero config: a new agent with no invite code and no solver still registers, because its own model answers."""
    from google.adk.models.llm_response import LlmResponse
    from google.genai import types as gt
    den.routes["/agents/register"] = (202, {"challenge_id": "c1", "challenge": "Describe a tree."})
    den.routes["/agents/register/verify"] = (201, {"api_key": "mbd_model"})
    asked = []

    class Model:
        model = "fake-model"

        async def generate_content_async(self, req, stream=False):
            asked.append(req.contents[0].parts[0].text)
            yield LlmResponse(content=gt.Content(role="model", parts=[gt.Part(text="A woody plant.")]))

    p = MoltbotDenLiveness(http=den.client, identity=ident, sleep=Clock(limit=1))
    await p.before_run_callback(invocation_context=types.SimpleNamespace(app_name="app", agent=types.SimpleNamespace(canonical_model=Model())))
    await p.close()  # only the captured model matters here; drive one step by hand
    await p.step()
    assert asked == ["Describe a tree."] and _keystore.api_key("app") == "mbd_model"


async def test_restarts_when_its_event_loop_died(den, ident, registry):
    """asyncio.run() twice: the first loop's task is finished, so the next run must start a new one."""
    p = plugin(den, ident, sleep=Clock(limit=1))
    await p.before_run_callback(invocation_context=CTX)
    p._task.cancel()
    await asyncio.gather(p._task, return_exceptions=True)
    await p.before_run_callback(invocation_context=CTX)
    assert not p._task.done()
    await p.close()


async def test_each_app_keeps_its_own_moltbotden_agent(den, ident, registry):
    """Two ADK apps on one machine must not share one Moltbot Den agent."""
    for app, key in (("App A", "key_a"), ("App B", "key_b")):
        den.routes["/agents/register"] = (201, {"api_key": key})
        p = plugin(den, ident, sleep=Clock(limit=1))
        await p.before_run_callback(invocation_context=types.SimpleNamespace(app_name=app))
        await settle(p)
        await p.close()
    assert (_keystore.api_key("App A"), _keystore.api_key("App B")) == ("key_a", "key_b")
    assert den.paths().count("/agents/register") == 2


async def test_switching_api_key_binds_again(den, ident, registry, monkeypatch):
    """The EID binding belongs to one Moltbot Den agent; another key means another bind."""
    for key in ("key_1", "key_2"):
        monkeypatch.setenv("MOLTBOTDEN_API_KEY", key)
        await MoltbotDenLiveness(http=den.client, identity=ident).step()
    assert den.paths().count("/entity/openentity/bind/verify") == 2


async def test_rejected_stored_key_registers_again_once(den, ident, registry):
    _keystore.save("adk-agent", agent_id="old", api_key="revoked")
    seen = []

    def handle(req):  # 401 for the revoked key, normal answers after re-registration
        seen.append(req.headers.get("x-api-key"))
        if req.headers.get("x-api-key") == "revoked":
            return httpx.Response(401, json={"detail": "Invalid API key."}, headers=REJECTED)
        return den.handle(req)
    den.client = httpx.AsyncClient(transport=httpx.MockTransport(handle))
    p = MoltbotDenLiveness(http=den.client, identity=ident, invite_code="INV-AAAA-BBBB")
    await p.step()
    assert _keystore.api_key("adk-agent") == "mbd_key" and p.mode == "sovereign"


async def test_rejected_env_key_stops_with_a_clear_error(den, ident, registry, monkeypatch):
    monkeypatch.setenv("MOLTBOTDEN_API_KEY", "bad")
    den.client = httpx.AsyncClient(transport=httpx.MockTransport(lambda req: httpx.Response(401, json={}, headers=REJECTED)
                                                                 if req.url.path.startswith("/entity") else den.handle(req)))
    try:
        await MoltbotDenLiveness(http=den.client, identity=ident).step()
        raise AssertionError("expected MoltbotDenStopped")
    except MoltbotDenStopped as e:
        assert "MOLTBOTDEN_API_KEY" in str(e)
    assert "/agents/register" not in den.paths()


async def test_a_refused_presentation_keeps_the_key(den, ident, registry, monkeypatch):
    """Moltbot Den answers 401 for a bad Presentation too; only an API-key rejection (WWW-Authenticate) may cost the key."""
    _keystore.save("adk-agent", agent_id="a", api_key="good")
    den.routes["/entity/openentity/bind/verify"] = (401, {"detail": "presentation_invalid"})
    p = MoltbotDenLiveness(http=den.client, identity=ident, invite_code="INV-AAAA-BBBB")
    try:
        await p.step()
        raise AssertionError("expected MoltbotDenError")
    except MoltbotDenError as e:
        assert not isinstance(e, MoltbotDenStopped)
    assert _keystore.api_key("adk-agent") == "good" and "/agents/register" not in den.paths()


async def test_a_suspended_account_stops_instead_of_registering_a_new_agent(den, ident, registry):
    _keystore.save("adk-agent", agent_id="a", api_key="good")
    den.routes["/entity/openentity/bind/challenge"] = (403, {"detail": "Account suspended. Contact support."})
    try:
        await MoltbotDenLiveness(http=den.client, identity=ident, invite_code="INV-AAAA-BBBB").step()
        raise AssertionError("expected MoltbotDenStopped")
    except MoltbotDenStopped as e:
        assert "suspended" in str(e)
    assert "/agents/register" not in den.paths()


async def test_bind_tags_the_agent_as_an_adk_agent(den, ident, registry):
    """framework=adk lists the agent on the Moltbot Den Network as cap:framework-adk."""
    seen = []
    den.client = httpx.AsyncClient(transport=httpx.MockTransport(lambda req: (seen.append(str(req.url)), den.handle(req))[1]))
    await MoltbotDenLiveness(http=den.client, identity=ident, invite_code="INV-AAAA-BBBB").step()
    assert any(u.endswith("/entity/openentity/bind/verify?framework=adk") for u in seen)


async def test_one_agent_per_network_stops_instead_of_retrying(den, ident, registry):
    den.routes["/agents/register"] = (429, {"detail": "This location has already registered an agent."})
    clock = Clock(limit=5)
    p = plugin(den, ident, sleep=clock)
    await p.before_run_callback(invocation_context=CTX)
    await asyncio.wait_for(p._task, 2)
    assert den.paths() == ["/agents/register"] and clock.delays == []


def test_store_writes_are_atomic_and_always_0600(home):
    path = home / "moltbotden.json"
    path.write_text('{"agents": {}}')
    path.chmod(0o644)  # a loose file left by something else
    _keystore.save("a", api_key="k")
    assert path.stat().st_mode & 0o777 == 0o600 and _keystore.api_key("a") == "k"
    assert [f.name for f in home.iterdir()] == ["moltbotden.json"]  # no temp file left behind
