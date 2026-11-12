"""pair() and Owner against an in-memory account service that checks every RFC 9421 signature. No network, no real sleeps."""
import io
import json
import time
import urllib.error
import urllib.request

import pytest

import openentity
from openentity import agent, core

BASE, SERVICE, CODE = "https://account.example", "did:web:account.example", "OE-7K4M-Q2XP"
KP = core.KeyPair(bytes(range(1, 33)))  # published throwaway seed, test-vectors/keys.json
OTHER = core.KeyPair(bytes([9]) * 32)


class Service:
    """Routes "METHOD /path" to a function of the parsed body returning (status, json, headers)."""

    def __init__(self, monkeypatch, routes):
        self.routes, self.calls = routes, []
        monkeypatch.setattr(urllib.request, "urlopen", self.urlopen)
        monkeypatch.setattr(agent.time, "sleep", lambda s: None)

    def urlopen(self, req, timeout=None):
        body = req.data or b""
        v = openentity.verify_request(req.get_method(), req.full_url, dict(req.header_items()), body)
        assert v["did"] == KP.did
        path = urllib.request.urlparse(req.full_url).path
        self.calls.append((req.get_method(), path, json.loads(body) if body else None))
        status, out, headers = self.routes[f"{req.get_method()} {path}"](self.calls[-1][2])
        data = b"" if out is None else json.dumps(out).encode()
        if status >= 400:
            raise urllib.error.HTTPError(req.full_url, status, "x", headers or {}, io.BytesIO(data))
        return io.BytesIO(data)


def claim(did=KP.did):
    return 201, {"pairing_id": "pr_1", "sas": {"version": "pair-sas/1", "indexes": [0, 0, 0, 0], "names": openentity.pair_sas(CODE, did)},
                 "expires_at": int(time.time()) + 600, "poll_interval": 2}, None


def test_pair_signs_checks_the_match_locally_and_polls_until_confirmed(monkeypatch):
    states = ["claimed", "claimed", "confirmed"]
    creds = [{"product": "did:web:moltbotden.com", "kind": "bearer", "key": "moltbotden_sk_test", "expires_at": 1}]

    def claimed(body):
        assert {k: body[k] for k in ("code", "framework", "sdk", "sdk_version", "host")} == {
            "code": CODE, "framework": "crewai", "sdk": "openentity-crewai", "sdk_version": "0.1.0", "host": "box"}
        p = body["presentation"]
        assert (p["type"], p["eid"], p["audience"], p["nonce"]) == ("Presentation", KP.did, SERVICE, f"pair:{CODE}")
        assert core.verify_presentation(p, SERVICE, f"pair:{CODE}")["ok"]
        return claim()

    def status(_):
        s = states.pop(0)
        return 200, {"state": s, "owner_did": "did:web:account.example:o:abc" if s == "confirmed" else None,
                     "permissions": ["owner.message"], **({"credentials": creds} if s == "confirmed" else {})}, None

    svc = Service(monkeypatch, {"POST /v1/pair": claimed, "GET /v1/pair/pr_1": status})
    shown = []
    r = openentity.pair(" oe-7k4m-q2xp ", KP, framework="crewai", sdk="openentity-crewai", sdk_version="0.1.0", host="box",
                        account=BASE + "/", on_match=shown.append)
    assert shown == [["red shell", "olive tree", "purple moon", "coral owl"]]  # test-vectors/pair-sas-1, case 1
    assert r == {"pairing_id": "pr_1", "owner_did": "did:web:account.example:o:abc", "permissions": ["owner.message"],
                 "credentials": creds, "match": shown[0]}
    assert [c[0] for c in svc.calls] == ["POST", "GET", "GET", "GET"]


def test_pair_refuses_a_match_that_is_not_this_agents(monkeypatch):
    svc = Service(monkeypatch, {"POST /v1/pair": lambda b: claim(OTHER.did)})
    shown = []
    with pytest.raises(openentity.VerificationError):
        openentity.pair(CODE, KP, account=BASE, on_match=shown.append)
    assert (shown, len(svc.calls)) == ([], 1)


@pytest.mark.parametrize("end", ["rejected", "expired"])
def test_pair_rides_out_429_and_5xx_then_stops_on_rejected_or_expired(monkeypatch, end):
    answers = [(429, {"error": "rate_limited", "message": "slow"}, {"retry-after": "3"}), (503, {"error": "unavailable"}, None),
               (200, {"state": end, "owner_did": None, "permissions": []}, None)]
    svc = Service(monkeypatch, {"POST /v1/pair": lambda b: claim(), "GET /v1/pair/pr_1": lambda b: answers.pop(0)})
    with pytest.raises(openentity.OpenEntityError) as e:
        openentity.pair(CODE, KP, account=BASE, on_match=lambda n: None)
    assert (e.value.code, len(svc.calls)) == (f"pairing_{end}", 4)


def test_pair_passes_refusals_through_and_checks_the_code_first(monkeypatch):
    svc = Service(monkeypatch, {"POST /v1/pair": lambda b: (409, {"error": "code_used", "message": "used"}, None)})
    with pytest.raises(openentity.OpenEntityError) as e:
        openentity.pair(CODE, KP, account=BASE)
    assert (e.value.code, e.value.status) == ("code_used", 409)
    with pytest.raises(openentity.InvalidInputError):
        openentity.pair("OE-ILOU-1234", KP, account=BASE)
    assert len(svc.calls) == 1


def test_owner_calls_are_signed_and_shaped_as_the_contract_says(monkeypatch):
    items = [{"type": "message", "id": "a", "created_at": 1, "text": "hi", "attachments": []}]
    svc = Service(monkeypatch, {
        "POST /v1/agent/messages": lambda b: (201, {"id": "m1"}, None),
        "POST /v1/agent/status": lambda b: (204, None, None),
        "GET /v1/agent/messages": lambda b: (200, {"items": items, "more": False}, None),
        "POST /v1/agent/messages/ack": lambda b: (204, None, None),
        "POST /v1/agent/credentials/renew": lambda b: (200, {"credentials": [{"key": "sma_x"}]}, None),
    })
    owner = openentity.Owner(KP, account=BASE)
    assert owner.message("hello") == {"id": "m1"}
    owner.status("running", "indexing")
    owner.status("done", "finished", progress=1)
    assert owner.inbox()["items"] == items
    owner.inbox(ack=False)
    assert owner.renew_credentials()[0]["key"] == "sma_x"
    assert [c[2] for c in svc.calls] == [{"text": "hello"}, {"state": "running", "summary": "indexing"},
                                         {"state": "done", "summary": "finished", "progress": 1}, None, {"ids": ["a"]}, None, {}]
    assert owner.did == KP.did


def test_owner_errors_carry_code_status_and_retry_after(monkeypatch):
    Service(monkeypatch, {"POST /v1/agent/messages": lambda b: (423, {"error": "agent_paused", "message": "p"}, None),
                          "GET /v1/agent/messages": lambda b: (429, {"error": "rate_limited", "message": "15 s"}, {"retry-after": "12"})})
    owner = openentity.Owner(KP, account=BASE)
    with pytest.raises(openentity.OpenEntityError) as e:
        owner.message("x")
    assert (e.value.code, e.value.status) == ("agent_paused", 423)
    with pytest.raises(openentity.OpenEntityError) as e:
        owner.inbox()
    assert (e.value.code, e.value.retry_after) == ("rate_limited", 12)


def test_ask_approval_waits_for_the_decision(monkeypatch):
    states = ["pending", "approved"]
    at = int(time.time())
    svc = Service(monkeypatch, {
        "POST /v1/agent/approvals": lambda b: (201, {"id": "ap1", "state": "pending", "expires_at": at + 120}, None),
        "GET /v1/agent/approvals/ap1": lambda b: (200, {"id": "ap1", "state": states.pop(0), "expires_at": at + 120}, None),
    })
    r = openentity.Owner(KP, account=BASE).ask_approval("Deploy", "Ship v2 to prod", "high", expires_in=120, wait=True)
    assert r["state"] == "approved"
    assert svc.calls[0][2] == {"title": "Deploy", "summary": "Ship v2 to prod", "risk": "high", "expires_in": 120}
    assert len(svc.calls) == 3


def test_on_command_polls_hands_over_acks_and_stops_on_not_paired(monkeypatch):
    polls = [{"items": [{"type": "command", "id": "c1", "created_at": 1, "command": "pause", "args": {}},
                        {"type": "command", "id": "c2", "created_at": 2, "command": "checkup", "args": {}}], "more": False}]

    def poll(_):
        return (200, polls.pop(0), None) if polls else (403, {"error": "not_paired", "message": "unlinked"}, None)

    svc = Service(monkeypatch, {"GET /v1/agent/messages": poll, "POST /v1/agent/messages/ack": lambda b: (204, None, None)})
    got, errors = [], []

    def handler(item):
        if item["id"] == "c2" and not got.count("c2-try"):
            got.append("c2-try")
            raise RuntimeError("busy")  # left unacknowledged
        got.append(item["id"])

    owner = openentity.Owner(KP, account=BASE)
    class Instant(agent.Event):  # the 15-second waits return at once
        def wait(self, timeout=None):
            return super().wait(0)

    monkeypatch.setattr(agent, "Event", Instant)
    listener = owner.on_command(handler, on_error=errors.append, interval=1)
    listener._thread.join(5)
    assert got == ["c1", "c2-try"] and listener.paused and listener.mode == "closed"
    assert svc.calls[1] == ("POST", "/v1/agent/messages/ack", {"ids": ["c1"]})
    assert [type(e).__name__ for e in errors] == ["RuntimeError", "OpenEntityError"] and errors[1].code == "not_paired"
    assert listener._interval == 15  # never faster than the contract allows
