import asyncio
import types

import openentity
from openentity import core

from openentity_adk import MoltbotDenError, MoltbotDenLiveness, _keystore
from conftest import Clock

CTX = types.SimpleNamespace(app_name="My App")


def plugin(den, ident, **kw):
    clock = kw.pop("sleep", Clock())
    p = MoltbotDenLiveness(http=den.client, identity=ident, invite_code="INV-AAAA-BBBB", sleep=clock, **kw)
    p.clock = clock
    return p


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
    assert _keystore.api_key() == "mbd_key"
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


async def test_registration_question_without_a_solver_is_skipped_loudly(den, ident, registry):
    den.routes["/agents/register"] = (202, {"challenge_id": "c1", "challenge": "Describe a tree."})
    p = MoltbotDenLiveness(http=den.client, identity=ident, sleep=Clock(limit=1))
    try:
        await p.step()
        raise AssertionError("expected MoltbotDenError")
    except MoltbotDenError:
        pass
    assert "/heartbeat/sovereign" not in den.paths()


async def test_registration_question_is_answered_by_the_solver(den, ident, registry):
    den.routes["/agents/register"] = (202, {"challenge_id": "c1", "challenge": "Describe a tree."})
    den.routes["/agents/register/verify"] = (201, {"api_key": "mbd_solved"})
    seen = []

    async def solver(q):
        seen.append(q)
        return "A tree is a woody plant."

    p = MoltbotDenLiveness(http=den.client, identity=ident, challenge_solver=solver, sleep=Clock(limit=1))
    await p.step()
    assert seen == ["Describe a tree."] and _keystore.api_key() == "mbd_solved"
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
    assert [c[2]["quality_score"] for c in den.calls] == [1.0, 0.0]
    assert den.calls[0][0] == "/entity/quality-event" and den.calls[0][2]["domain"] == "adk"
    for _ in range(40):
        await on.after_tool_callback(tool=tool, tool_args={}, tool_context=None, result={})
    assert len(den.calls) == 25
