import json
import time

import pytest
from conftest import SCHEMAS, load
from openentity.core import KeyPair, verify_object

from langchain_openentity import LedgerReporter, OpenEntitySchemaViolation, RuthlessSchemaGuard
from langchain_openentity.core import Routes, compile_schema, path_template

KP = KeyPair(bytes(range(32)))  # published throwaway seed, test only


def reporter(posts, **kw):
    return LedgerReporter(url="https://ledger.test/v1", keypair=KP, interval=0.01, post=lambda u, b: posts.append((u, json.loads(b))), **kw)


def violate(g, body="<html>token=supersecretvalue</html>"):
    with pytest.raises(OpenEntitySchemaViolation):
        g._check("GET", "https://api.test/repos/42/pulls?token=abc", 200, "application/json", "", lambda: body.encode())


def test_report_is_signed_scrubbed_and_complete():
    posts = []
    r = reporter(posts)
    g = RuthlessSchemaGuard(ledger=r)
    g.register("GET https://api.test/repos/*/pulls", SCHEMAS["pull_list"])
    violate(g)
    r.flush()
    (url, rep), = posts
    assert url == "https://ledger.test/v1" and verify_object(rep)[0]
    assert rep["host"] == "api.test" and rep["method"] == "GET" and rep["path_template"] == "/repos/*/pulls"
    assert rep["status"] == 200 and rep["framework"] == "langchain" and rep["reporter_eid"] == KP.did
    assert rep["expected_schema_hash"] == compile_schema(SCHEMAS["pull_list"]).hash and len(rep["body_sha256"]) == 64
    assert "supersecretvalue" not in rep["sample"] and len(rep["sample"]) <= 2048


def test_unregistered_route_gets_id_template_and_dedupes():
    posts = []
    r = reporter(posts)
    g = RuthlessSchemaGuard(ledger=r)
    violate(g)
    violate(g)
    r.flush()
    time.sleep(0.05)
    assert [p[1]["path_template"] for p in posts] == ["/repos/{id}/pulls"]


def test_ledger_is_off_unless_configured_and_honors_opt_out(monkeypatch):
    monkeypatch.delenv("OPENENTITY_LEDGER_URL", raising=False)
    assert LedgerReporter(keypair=KP).enabled is False
    monkeypatch.setenv("OPENENTITY_LEDGER_URL", "1")
    assert LedgerReporter(keypair=KP).url == "https://api.clawgrc.com/v1/ledger/schema-violations"
    monkeypatch.setenv("OPENENTITY_LEDGER_OPTOUT", "1")
    assert LedgerReporter(keypair=KP).enabled is False
    monkeypatch.delenv("OPENENTITY_LEDGER_OPTOUT")
    assert LedgerReporter(keypair=KP, enabled=False).enabled is False
    assert RuthlessSchemaGuard(ledger=False).ledger.enabled is False


def test_ledger_needs_a_key(monkeypatch):
    monkeypatch.delenv("OPENENTITY_SEED_HEX", raising=False)
    assert LedgerReporter(url="https://x.test").enabled is False
    monkeypatch.setenv("OPENENTITY_SEED_HEX", "01" * 32)
    assert LedgerReporter(url="https://x.test").enabled is True


def test_a_failing_ledger_never_breaks_the_agent():
    def down(u, b):
        raise OSError("down")

    r = LedgerReporter(url="https://x.test", keypair=KP, interval=0.01, post=down)
    violate(RuthlessSchemaGuard(ledger=r))  # still the violation, not the OSError
    r.flush()


def test_route_patterns():
    rt = Routes()
    s = compile_schema({"type": "object"})
    rt.add("GET https://api.github.com/repos/*/pulls", s)
    rt.add("* https://x.test/files/**", s)
    rt.add("POST https://x.test/items/{id}", s)
    assert rt.match("get", "https://api.github.com/repos/a/pulls?state=open")
    assert not rt.match("GET", "https://api.github.com/repos/a/b/pulls")
    assert not rt.match("POST", "https://api.github.com/repos/a/pulls")
    assert rt.match("PUT", "https://x.test/files/a/b/c") and rt.match("POST", "https://x.test/items/9/")
    assert path_template("https://h/a/12345/b/0f8fad5b-d9cb-469f-a165-70867728950e") == "/a/{id}/b/{id}"


SPEC = {
    "openapi": "3.0.3", "servers": [{"url": "https://api.test/v1"}],
    "paths": {
        "/pets/{id}": {"get": {"responses": {"200": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/Pet"}}}},
                                              "404": {"content": {"application/json": {"schema": {"type": "object"}}}}}}},
        "/pets": {"get": {"responses": {"200": {"content": {"application/json": {"schema": {"type": "array", "items": {"$ref": "#/components/schemas/Pet"}}}}}}},
                  "delete": {"responses": {"204": {"description": "gone"}}}},
    },
    "components": {"schemas": {"Pet": {"type": "object", "required": ["id", "name"], "properties": {
        "id": {"type": "integer"}, "name": {"type": "string"}, "tag": {"type": "string", "nullable": True}}}}},
}


def test_from_openapi_registers_json_2xx_routes_only():
    g = RuthlessSchemaGuard().from_openapi(SPEC)
    ok = lambda m, u, body: g._check(m, u, 200, "application/json", "", lambda: body.encode())  # noqa: E731
    ok("GET", "https://api.test/v1/pets/7", '{"id": 7, "name": "rex", "tag": null}')
    ok("GET", "https://api.test/v1/pets", '[{"id": 1, "name": "a"}]')
    for u, body in (("pets/7", '{"id": "7", "name": "rex"}'), ("pets", '[{"id": 1}]'), ("pets", '{"id": 1, "name": "a"}')):
        with pytest.raises(OpenEntitySchemaViolation):
            ok("GET", f"https://api.test/v1/{u}", body)
    assert len(g.routes._routes) == 2
    with pytest.raises(ValueError):
        RuthlessSchemaGuard().from_openapi({"paths": {}})
