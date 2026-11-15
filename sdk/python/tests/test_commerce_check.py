"""Agent Commerce Check middleware: the FastAPI and Django example apps, driven by signed agent requests.

The hosted call is replaced by `verify_agent_for_checkout`, the library the hosted endpoint runs, fed with the checkout-1 vectors
(owner key log, mandate, registry facts, clock), so each app really returns allow, step_up and deny."""
import base64
import json
import pathlib
import sys

import pytest

import openentity as oe
from openentity import commerce_check

DIR = pathlib.Path(__file__).parents[3] / "test-vectors"
load = lambda p: json.loads((DIR / p).read_text())
STATES = load("approval-2.0/vectors.json")["key_states"]
CASES = {c["name"]: c for c in load("checkout-1/vectors.json")["cases"]}
AGENT = oe.key_pair_from_seed(bytes.fromhex(load("keys.json")["entity"]["seed"]))
sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "examples"))


def hosted_for(case):
    """A `post` that answers like POST /v1/commerce/check would for this vector case."""
    i, calls = case["input"], []

    def post(endpoint, payload):
        calls.append(payload)
        h = payload["request"]["headers"]
        mandate = json.loads(base64.urlsafe_b64decode(h["oe-mandate"] + "===")) if "oe-mandate" in h else None
        r = oe.verify_agent_for_checkout(request={k: payload["request"][k] for k in ("method", "url", "headers")}, cart=payload["cart"], merchant_policy=payload["policy"],
                                         agent=i.get("agent"), mandate=mandate, key_log=STATES[i["key_state"]], status=i.get("status"), now=i["now"])
        return {"decision": r["decision"], "reasons": r["reasons"], "evidence_id": "ev_" + "a" * 26, **({"cart": payload["cart"], "cart_digest": oe.cart_digest(payload["cart"])} if r["decision"] == "step_up" else {}),
                "agent_did": r["evidence"].get("agent_did")}

    post.calls = calls
    return post


def agent_headers(case, url, mandate=True):
    i = case["input"]
    h = oe.sign_request("POST", url, b"", AGENT, AGENT.did, created=i["now"])
    if mandate and i.get("mandate"):
        h["OE-Mandate"] = base64.urlsafe_b64encode(json.dumps(i["mandate"]).encode()).decode().rstrip("=")
    return h


SCENARIOS = [("allow-mandate-covers", 200), ("step-up-over-threshold", 428), ("deny-mandate-required", 403)]


@pytest.mark.parametrize("name,status", SCENARIOS)
def test_fastapi_example(name, status):
    from starlette.testclient import TestClient

    import commerce_check_fastapi as ex

    c = CASES[name]["input"]
    post = hosted_for(CASES[name])
    client = TestClient(ex.make_app(cart=lambda req, did: c["cart"], policy=c["merchant_policy"], post=post))
    r = client.post("/buy", headers=agent_headers(CASES[name], "http://testserver/buy"))
    assert r.status_code == status, r.text
    assert r.json()["evidence_id"] == "ev_" + "a" * 26
    if status == 200:
        assert r.json()["bought"] and r.json()["agent"] == AGENT.did
    else:
        assert r.json()["decision"] == CASES[name]["expect"]["decision"] and r.json()["reasons"] == CASES[name]["expect"]["reasons"]
    if status == 428:
        assert r.json()["cart_digest"] == oe.cart_digest(c["cart"])
    assert post.calls[0]["request"]["url"] == "http://testserver/buy"  # the URL the agent signed


def test_fastapi_unsigned_is_denied_other_paths_are_untouched_and_a_down_check_fails_closed():
    from starlette.testclient import TestClient

    import commerce_check_fastapi as ex

    case = CASES["allow-mandate-covers"]
    c = case["input"]
    ok = TestClient(ex.make_app(cart=lambda req, did: c["cart"], policy=c["merchant_policy"], post=hosted_for(case)))
    assert ok.post("/buy").json()["reasons"] == ["request_unverified"]
    assert ok.post("/buy").status_code == 403

    def down(endpoint, payload):
        raise OSError("unreachable")

    closed = TestClient(ex.make_app(cart=lambda req, did: c["cart"], post=down))
    assert closed.post("/buy", headers=agent_headers(case, "http://testserver/buy")).status_code == 503
    observing = TestClient(ex.make_app(cart=lambda req, did: c["cart"], post=down, enforce=False))
    assert observing.post("/buy", headers=agent_headers(case, "http://testserver/buy")).status_code == 200  # observe mode: the check could not run, the purchase goes on


def test_observe_mode_attaches_the_decision_and_never_blocks():
    from starlette.testclient import TestClient

    import commerce_check_fastapi as ex

    case = CASES["deny-mandate-required"]
    c = case["input"]
    seen = []
    client = TestClient(ex.make_app(cart=lambda req, did: c["cart"], policy=c["merchant_policy"], post=hosted_for(case), enforce=False, on_decision=lambda d, req: seen.append(d["decision"])))
    r = client.post("/buy", headers=agent_headers(case, "http://testserver/buy"))
    assert r.status_code == 200 and seen == ["deny"]


@pytest.mark.parametrize("name,status", SCENARIOS)
def test_django_example(name, status):
    import django
    from django.conf import settings

    if not settings.configured:
        settings.configure(ALLOWED_HOSTS=["testserver"], DEFAULT_CHARSET="utf-8", SECRET_KEY="x", USE_TZ=True)
        django.setup()
    from django.test import RequestFactory

    import commerce_check_django as ex

    case = CASES[name]
    c = case["input"]
    h = agent_headers(case, "http://testserver/buy")
    request = RequestFactory().post("/buy", **{"HTTP_" + k.upper().replace("-", "_"): v for k, v in h.items()})
    post = hosted_for(case)
    r = ex.make_middleware(cart=lambda req, did: c["cart"], policy=c["merchant_policy"], post=post)(ex.buy)(request)
    assert r.status_code == status, r.content
    body = json.loads(r.content)
    assert body["evidence_id"] == "ev_" + "a" * 26
    assert (body["bought"] if status == 200 else body["decision"] == case["expect"]["decision"])
    assert post.calls[0]["request"]["url"] == "http://testserver/buy"


def test_agent_did_of_reads_the_keyid_and_commerce_exports_the_middleware():
    h = {k.lower(): v for k, v in oe.sign_request("POST", "https://shop.example/", b"", AGENT, AGENT.did).items()}
    assert commerce_check.agent_did_of(h) == AGENT.did
    assert oe.commerce.CommerceCheckMiddleware is commerce_check.CommerceCheckMiddleware and oe.commerce.django_middleware
