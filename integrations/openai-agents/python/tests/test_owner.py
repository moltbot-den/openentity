"""pair() and the owner tools against the stub registry plus a stand-in account service (openentity.agent._call)."""
import asyncio
import json

import openentity
import pytest
from agents.tool_context import ToolContext
from openentity import Identity, OpenEntityError, agent

import openentity_openai_agents as oe


def call(tool, **kw):
    ctx = ToolContext(context=None, tool_name=tool.name, tool_call_id="c1", tool_arguments=json.dumps(kw))
    out = asyncio.run(tool.on_invoke_tool(ctx, json.dumps(kw)))
    return json.loads(out) if isinstance(out, str) else out


@pytest.fixture
def account(monkeypatch):
    """Routes "METHOD /path" to a dict, a function of the body, or an exception to raise. Returns (calls, routes)."""
    calls, routes = [], {}

    def fake(kp, base, method, path, body=None):
        calls.append({"did": kp.did, "base": base, "method": method, "path": path, "body": body})
        r = routes[f"{method} {path}"]
        if isinstance(r, Exception):
            raise r
        return r(body) if callable(r) else r

    monkeypatch.setattr(agent, "_call", fake)
    monkeypatch.setattr(agent.time, "sleep", lambda s: None)
    monkeypatch.setenv("OPENENTITY_ACCOUNT", "https://account.example")
    return calls, routes


def test_pair_adopts_first_then_pairs_under_the_bridge_label(registry, account, capsys):
    calls, routes = account
    routes["POST /v1/pair"] = lambda b: {"pairing_id": "pr_1", "expires_at": 9e9, "poll_interval": 2,
                                         "sas": {"version": "pair-sas/1", "names": openentity.pair_sas(b["code"], b["presentation"]["eid"])}}
    routes["GET /v1/pair/pr_1"] = {"state": "confirmed", "owner_did": "did:web:account.example:o:abc", "permissions": ["owner.message"],
                                   "credentials": [{"product": "did:web:moltbotden.com", "kind": "bearer", "key": "moltbotden_sk_x", "expires_at": 1}]}
    r = oe.pair("OE-7K4M-Q2XP", name="Paired Agent")
    printed = capsys.readouterr().out
    me = Identity.load().did
    assert (r["eid"], r["adopted"], r["owner_did"], r["credentials"][0]["key"]) == (me, True, "did:web:account.example:o:abc", "moltbotden_sk_x")
    assert "signed the Open Entity Declaration" in printed and "Match: " + ", ".join(r["match"]) in printed
    assert [a["client"] for a in registry.adopts] == ["openai-agents"]
    assert calls[0]["base"] == "https://account.example" and calls[0]["did"] == me
    assert {k: calls[0]["body"][k] for k in ("code", "framework", "sdk")} == {"code": "OE-7K4M-Q2XP", "framework": "openai-agents", "sdk": "openentity-openai-agents"}
    assert oe.pair("OE-7K4M-Q2XP")["adopted"] is False and len(registry.adopts) == 1  # already adopted: pairs again without adopting


def test_owner_tools_sign_as_this_agent_and_report_refusals(registry, account):
    calls, routes = account
    routes.update({
        "POST /v1/agent/messages": {"id": "m1"},
        "POST /v1/agent/status": None,
        "GET /v1/agent/messages": {"items": [], "more": False},
        "POST /v1/agent/approvals": lambda b: {"id": "ap1", "state": "pending", "title": b["title"]},
    })
    assert call(oe.owner_message, text="hello") == {"ok": True, "id": "m1"}
    assert call(oe.owner_status, state="running", summary="indexing", progress=0.5) == {"ok": True}
    assert call(oe.owner_inbox) == {"ok": True, "items": [], "more": False}
    assert call(oe.owner_ask_approval, title="Deploy", summary="Ship v2", risk="high")["state"] == "pending"
    assert [c["body"] for c in calls] == [{"text": "hello"}, {"state": "running", "summary": "indexing", "progress": 0.5}, None,
                                         {"title": "Deploy", "summary": "Ship v2", "risk": "high", "expires_in": 600}]
    assert {c["did"] for c in calls} == {Identity.load().did}
    routes["POST /v1/agent/messages"] = OpenEntityError("account 423 for POST /v1/agent/messages: paused", "agent_paused")
    assert call(oe.owner_message, text="x")["error"] == "agent_paused"


def test_the_owner_tool_list_has_the_four_tools():
    assert [t.name for t in oe.owner_tools()] == ["owner_message", "owner_status", "owner_inbox", "owner_ask_approval"]


def test_the_app_one_liner_works():
    assert oe.OpenEntityOwner.pair is oe.pair
    assert [t.name for t in oe.OpenEntityOwner.tools()] == ["owner_message", "owner_status", "owner_inbox", "owner_ask_approval"]
