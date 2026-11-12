"""pair() and owner_tools() against stand-ins for the registry (openentity.client._request) and the account service
(openentity.agent._call). No network."""
import openentity
import pytest
from openentity import Identity, agent, client
from google.adk.tools import FunctionTool

from openentity_adk import owner_tools, pair


def run(t, **kw):
    return t(**kw)


@pytest.fixture
def services(monkeypatch, tmp_path):
    """Returns (adopts, calls, routes): routes maps "METHOD /path" to a dict, a function of the body, or an exception to raise."""
    monkeypatch.setenv("OPENENTITY_HOME", str(tmp_path))
    monkeypatch.setenv("OPENENTITY_KEYCHAIN", "off")
    monkeypatch.setenv("OPENENTITY_REGISTRY", "https://registry.example")
    monkeypatch.setenv("OPENENTITY_ACCOUNT", "https://account.example")
    known, adopts, calls, routes = set(), [], [], {}

    def registry(url, body=None, headers=None, method=None):
        path = url.removeprefix("https://registry.example")
        if path == "/v1/spec":
            return {"stamp_bits": 1}
        if path == "/v1/adopt":
            adopts.append(body)
            known.add(body["document"]["eid"])
            return {"eid": body["document"]["eid"], "level": "L0"}
        if path.endswith("/record"):
            return {"accepted": 1}
        if path.rsplit("/", 1)[-1] in known:
            return {"eid": path.rsplit("/", 1)[-1]}
        raise client.RegistryError(404, {"error": "entity_not_found"})

    def account(kp, base, method, path, body=None):
        calls.append({"did": kp.did, "base": base, "method": method, "path": path, "body": body})
        r = routes[f"{method} {path}"]
        if isinstance(r, Exception):
            raise r
        return r(body) if callable(r) else r

    monkeypatch.setattr(client, "_request", registry)
    monkeypatch.setattr(agent, "_call", account)
    monkeypatch.setattr(agent.time, "sleep", lambda s: None)
    return adopts, calls, routes


def test_pair_adopts_first_then_pairs_under_the_adk_label(services, capsys):
    adopts, calls, routes = services
    routes["POST /v1/pair"] = lambda b: {"pairing_id": "pr_1", "expires_at": 9e9, "poll_interval": 2,
                                         "sas": {"version": "pair-sas/1", "names": openentity.pair_sas(b["code"], b["presentation"]["eid"])}}
    routes["GET /v1/pair/pr_1"] = {"state": "confirmed", "owner_did": "did:web:account.example:o:abc", "permissions": ["owner.status"],
                                   "credentials": []}
    r = pair("OE-7K4M-Q2XP", name="Paired")
    printed = capsys.readouterr().out
    me = Identity.load().did
    assert (r["eid"], r["adopted"], r["owner_did"], [a["client"] for a in adopts]) == (me, True, "did:web:account.example:o:abc", ["adk"])
    assert "signed the Open Entity Declaration" in printed and "Match: " + ", ".join(r["match"]) in printed
    assert calls[0]["base"] == "https://account.example" and calls[0]["did"] == me
    assert (calls[0]["body"]["framework"], calls[0]["body"]["sdk"]) == ("adk", "openentity-adk")
    assert pair("OE-7K4M-Q2XP")["adopted"] is False and len(adopts) == 1


def test_owner_tools_sign_as_this_agent_and_report_refusals(services):
    adopts, calls, routes = services
    routes.update({
        "POST /v1/agent/messages": {"id": "m1"},
        "POST /v1/agent/status": None,
        "GET /v1/agent/messages": {"items": [], "more": False},
        "POST /v1/agent/approvals": lambda b: {"id": "ap1", "state": "pending", "title": b["title"]},
    })
    message, status, inbox, ask = owner_tools()
    decls = [FunctionTool(t)._get_declaration() for t in (message, status, inbox, ask)]  # ADK builds each declaration
    assert [d.name for d in decls] == ["owner_message", "owner_status", "owner_inbox", "owner_ask_approval"]
    assert run(message, text="hello") == {"ok": True, "id": "m1"}
    assert run(status, state="running", summary="indexing", progress=0.5) == {"ok": True}
    assert run(inbox) == {"ok": True, "items": [], "more": False}
    assert run(ask, title="Deploy", summary="Ship v2", risk="high")["state"] == "pending"
    assert [c["body"] for c in calls] == [{"text": "hello"}, {"state": "running", "summary": "indexing", "progress": 0.5}, None,
                                         {"title": "Deploy", "summary": "Ship v2", "risk": "high", "expires_in": 600}]
    assert len({c["did"] for c in calls}) == 1 and adopts == []  # the owner tools never adopt
    routes["POST /v1/agent/messages"] = openentity.OpenEntityError("account 423 for POST /v1/agent/messages: paused", "agent_paused")
    assert run(message, text="x")["error"] == "agent_paused"
