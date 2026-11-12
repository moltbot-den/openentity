"""`openentity pair` and `openentity owner` (the uvx door of PLAN 8.1) against the stub registry and a stand-in account service."""
import json
import stat
import urllib.request

import pytest
from test_client import KP, Stub, run, url  # noqa: F401  (fixtures and the stub registry)

import openentity
from openentity import agent, cli

CODE = "OE-7K4M-Q2XP"
CREDS = [{"product": "did:web:moltbotden.com", "kind": "bearer", "key": "moltbotden_sk_test", "expires_at": 1_800_000_000}]


@pytest.fixture
def account(monkeypatch, tmp_path):
    """An empty OPENENTITY_HOME, a fresh HOME, the account at openentity.agent._call and openentity.org/skill/ stand-ins."""
    monkeypatch.setenv("OPENENTITY_HOME", str(tmp_path / "oe"))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.delenv("OPENENTITY_REGISTRY", raising=False)
    calls = []
    routes = {"POST /v1/pair": lambda b: {"pairing_id": "pr_1", "expires_at": 9e9, "poll_interval": 2,
                                          "sas": {"version": "pair-sas/1", "names": openentity.pair_sas(b["code"], b["presentation"]["eid"])}},
              "GET /v1/pair/pr_1": lambda b: {"state": "confirmed", "owner_did": "did:web:account.example:o:abc",
                                              "permissions": ["owner.message"], "credentials": CREDS}}

    def fake(kp, base, method, path, body=None):
        calls.append({"did": kp.did, "base": base, "method": method, "path": path, "body": body})
        r = routes[f"{method} {path}"]
        if isinstance(r, Exception):
            raise r
        return r(body)

    real = urllib.request.urlopen
    monkeypatch.setattr(agent, "_call", fake)
    monkeypatch.setattr(agent.time, "sleep", lambda s: None)
    monkeypatch.setattr(urllib.request, "urlopen", lambda req, *a, **kw: __import__("io").BytesIO(f"stand-in for {req}".encode())
                        if str(req).startswith("https://openentity.org/skill/") else real(req, *a, **kw))
    return calls, routes, tmp_path


def test_pair_adopts_when_the_home_is_empty_says_so_and_prints_the_keys_once(url, account, capsys):
    calls, _, _ = account
    code, out, err = run(capsys, "pair", CODE.lower(), "--registry", url, "--account", "https://account.example", "--json")
    assert code == 0, err
    res = json.loads(out)
    assert res["adopted"] and res["owner_did"] == "did:web:account.example:o:abc" and res["credentials"][0]["put_it_in"] == cli.KEY_HOME["did:web:moltbotden.com"]
    assert "signed the Open Entity Declaration" in err and f"Match: {', '.join(openentity.pair_sas(CODE, res['eid']))}" in err
    assert calls[0]["did"] == res["eid"] and calls[0]["base"] == "https://account.example"
    assert {k: calls[0]["body"][k] for k in ("code", "framework", "sdk")} == {"code": CODE, "framework": "other", "sdk": "openentity-python-cli"}
    assert calls[0]["body"]["presentation"]["nonce"] == f"pair:{CODE}"
    code, out, _ = run(capsys, "pair", CODE, "--registry", url, "--account", "https://account.example")  # the entity exists now
    assert code == 0 and "Declaration" not in out and "  moltbotden_sk_test\n  Put it in: Moltbot Den" in out


def test_pair_refuses_a_foreign_match_and_checks_the_code_first(url, account, capsys):
    calls, routes, _ = account
    routes["POST /v1/pair"] = lambda b: {"pairing_id": "pr_1", "expires_at": 9e9, "poll_interval": 2,
                                         "sas": {"version": "pair-sas/1", "names": openentity.pair_sas(b["code"], KP.did)}}
    code, out, err = run(capsys, "pair", CODE, "--registry", url)
    assert code == cli.EXIT_VERIFY and "Match:" not in out and "verification_failed" in err
    assert run(capsys, "pair", "OE-12")[0] == cli.EXIT_USAGE


def test_pair_openclaw_writes_the_anchor_installs_the_skill_and_registers_the_mcp_server(url, account, capsys, monkeypatch):
    _, _, tmp = account
    ws = tmp / "home" / ".openclaw" / "workspace"
    ws.mkdir(parents=True)
    monkeypatch.chdir(tmp)
    code, out, err = run(capsys, "pair", CODE, "--registry", url, "--account", "https://account.example", "--openclaw", "--json")
    assert code == 0, err
    res = json.loads(out)["openclaw"]
    assert res["identity_files"] == [str(ws / "IDENTITY.md"), str(ws / "SOUL.md")]
    skill = tmp / "home" / ".openclaw" / "skills" / "openentity"
    assert (skill / "SKILL.md").read_text() == "stand-in for https://openentity.org/skill/SKILL.md"
    assert (skill / "scripts" / "adopt.sh").stat().st_mode & stat.S_IXUSR
    cfg = tmp / "home" / ".openclaw" / "openclaw.json"
    assert json.loads(cfg.read_text())["mcp"]["servers"]["openentity"] == {
        "command": "npx", "args": ["-y", "@openentity/mcp"], "env": {"OPENENTITY_HOME": str(tmp / "oe"), "OPENENTITY_ACCOUNT": "https://account.example"}}
    assert stat.S_IMODE(cfg.stat().st_mode) == 0o600
    json5 = "{ // mine\n gateway: { bind: 'lan' }, }\n"
    cfg.write_text(json5)
    code, out, _ = run(capsys, "pair", CODE, "--registry", url, "--openclaw")
    assert code == 0 and cfg.read_text() == json5 and "is not plain JSON, so it was left as it is" in out


def test_skill_files_lists_the_npm_cli_list():
    import pathlib
    import re
    npm = (pathlib.Path(__file__).parents[3] / "cli" / "src" / "pair.ts").read_text()
    assert json.loads(re.search(r"SKILL_FILES = (\[[^\]]*\])", npm).group(1)) == cli.SKILL_FILES


def test_owner_commands_sign_as_the_current_entity(url, account, capsys):
    calls, routes, _ = account
    assert run(capsys, "adopt", "--name", "Talker", "--agree", "--registry", url)[0] == 0
    routes.update({
        "POST /v1/agent/messages": lambda b: {"id": "m1"},
        "POST /v1/agent/status": lambda b: None,
        "GET /v1/agent/messages": lambda b: {"items": [{"type": "command", "id": "c1", "created_at": 1, "command": "checkup", "args": {}}], "more": False},
        "POST /v1/agent/messages/ack": lambda b: None,
        "POST /v1/agent/approvals": lambda b: {"id": "ap1", "state": "pending", "title": b["title"], "expires_at": 9e9},
    })
    assert run(capsys, "owner", "message", "hello", "there", "--registry", url)[1] == "sent to your owner (m1)\n"
    assert run(capsys, "owner", "status", "running", "indexing", "docs", "--progress", "0.5", "--registry", url)[0] == 0
    assert run(capsys, "owner", "inbox", "--registry", url)[1] == "c1 command: checkup\n"
    assert run(capsys, "owner", "ask", "--title", "Deploy", "--summary", "Ship v2", "--risk", "high", "--registry", url)[1] == "pending: Deploy (ap1)\n"
    assert [c["body"] for c in calls] == [{"text": "hello there"}, {"state": "running", "summary": "indexing docs", "progress": 0.5}, None,
                                         {"ids": ["c1"]}, {"title": "Deploy", "summary": "Ship v2", "risk": "high", "expires_in": 600}]
    routes["POST /v1/agent/messages"] = openentity.OpenEntityError("account 423 for POST /v1/agent/messages: paused", "agent_paused")
    routes["POST /v1/agent/messages"].status = 423
    code, _, err = run(capsys, "owner", "message", "x", "--registry", url)
    assert code == cli.EXIT_REJECTED and "agent_paused" in err
    assert run(capsys, "owner", "dance", "--registry", url)[0] == cli.EXIT_USAGE
