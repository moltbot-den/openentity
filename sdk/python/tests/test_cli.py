"""The commands the npm CLI has and the Python one gained in 0.5: each test fails if its command is removed."""
import json
import re
import stat

import pytest
from test_client import KP, LOG_KEY, Stub, home, posts, run, url  # noqa: F401  (fixtures and the stub registry)

from openentity import cli, core

COMMANDS = ["adopt", "whoami", "self", "stats", "anchor", "document", "record", "alias", "verify", "resolve", "present", "verify-presentation",
            "dispute", "find", "log", "export", "import", "rotate", "migrate", "recover", "withdraw"]


@pytest.mark.parametrize("name", COMMANDS)
def test_every_npm_command_exists(name):
    assert name in cli.COMMANDS
    with pytest.raises(SystemExit) as e:
        cli.main([name, "--help"])
    assert e.value.code == 0


def j(capsys, *argv):
    code, out, err = run(capsys, *argv, "--json")
    return code, json.loads(out or err or "null")


def test_adopt_flags_dry_run_and_file_layout(url, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("OPENENTITY_HOME", str(tmp_path / "h"))
    monkeypatch.setenv("OPENENTITY_OPERATOR", "Ada")
    code, out = j(capsys, "adopt", "--name", "A", "--dry-run", "--registry", url)
    assert code == 0 and out["document"]["operator"] == {"kind": "human", "name": "Ada", "custody": "entity", "can_change": []}
    assert not (tmp_path / "h").exists() and not posts("/v1/adopt")
    wallet = "0x" + "ab" * 20
    code, out = j(capsys, "adopt", "--name", "A", "--agree", "--registry", url, "--wallet", wallet, "--erc8004", f"eip155:8453:{wallet}:7",
                  "--capabilities", "code-review, ops", "--model", "m", "--custody", "shared")
    assert code == 0 and out["key_file"].endswith("/key") and out["next"]
    (body,) = posts("/v1/adopt")
    d = body["document"]
    assert d["aliases"] == [{"type": "wallet", "value": f"did:pkh:eip155:8453:{wallet}"}, {"type": "erc8004", "value": f"eip155:8453:{wallet}:7"}]
    assert d["capabilities"] == ["code-review", "ops"] and d["substrate"]["model"] == "m" and d["operator"]["custody"] == "shared" and body["client"] == "cli"
    eid = d["eid"]
    home = tmp_path / "h"
    assert sorted(p.name for p in (home / eid).iterdir()) == ["declaration.json", "entity.json", "key", "record.jsonl", "state.json"]
    assert stat.S_IMODE((home / eid / "key").stat().st_mode) == 0o600 and (home / "current").read_text().strip() == eid
    key = json.loads((home / eid / "key").read_text())
    assert cli._kp_from_jwk(key).did == eid and key["kty"] == "OKP"  # the same JWK file the npm CLI writes
    assert json.loads((home / eid / "state.json").read_text()) == {"registry": url, "docSeq": 1, "recordPushed": 1, "level": "L0"}
    assert Stub.chain[0]["kind"] == "declaration"
    assert run(capsys, "adopt", "--agree", "--registry", url)[0] == 1  # no name


def test_stats(url, home, capsys):
    assert j(capsys, "stats", "--registry", url) == (0, {"entities": 3})


def test_anchor_prints_and_writes_idempotently(home, capsys, tmp_path):
    doc = json.loads((home / KP.did / "entity.json").read_text())
    doc["layers"]["mission"]["arcs"] = [{"title": "Ship", "status": "active"}, {"title": "Old", "status": "closed"}]
    (home / KP.did / "entity.json").write_text(json.dumps(doc))
    code, out = j(capsys, "anchor")
    assert code == 0 and out["anchor"].startswith(f"I am Saved ({KP.did}).") and "Active arcs: Ship" in out["anchor"] and "Old" not in out["anchor"]
    assert out["length"] <= 1200
    out_dir = tmp_path / "w"
    out_dir.mkdir()
    (out_dir / "CLAUDE.md").write_text("# mine\n")
    for _ in range(2):
        assert run(capsys, "anchor", "--format", "claude", "--write", "--dir", str(out_dir))[0] == 0
    text = (out_dir / "CLAUDE.md").read_text()
    assert text.startswith("# mine\n") and text.count("openentity:anchor:start") == 1
    assert run(capsys, "anchor", "--format", "openclaw", "--write", "--dir", str(out_dir))[0] == 0 and (out_dir / "SOUL.md").exists()
    assert run(capsys, "anchor", "--write")[0] == 1 and run(capsys, "anchor", "--format", "nope")[0] == 1
    long = {**doc, "layers": {**doc["layers"], "cognition": {"statement": "x" * 3000}}}
    assert len(cli.anchor_text(long, "u")) <= 1200


def test_document_set_and_push_signs_the_next_seq(url, home, capsys):
    reg = ["--registry", url]
    assert run(capsys, "document", "push", *reg)[1].strip() == "nothing to push"
    assert run(capsys, "document", "set", "layers.mission.statement", "Ship it", *reg)[0] == 0
    assert run(capsys, "document", "set", "capabilities", '["a","b"]', *reg)[0] == 0
    for bad in ("seq", "keys.x", "a..b", "__proto__.x"):
        assert run(capsys, "document", "set", bad, "1", *reg)[0] == 1
    code, out = j(capsys, "document", "push", *reg)
    assert code == 0 and out == {"pushed": True, "seq": 2}
    (put,) = [b for m, p, b, _ in Stub.log if m == "PUT" and p == f"/v1/entities/{KP.did}/document"]
    assert put["seq"] == 2 and put["layers"]["mission"]["statement"] == "Ship it" and put["capabilities"] == ["a", "b"]
    assert core.verify_object(put) == (True, KP.did)
    assert not (home / KP.did / "draft.json").exists() and json.loads((home / KP.did / "state.json").read_text())["docSeq"] == 2
    assert json.loads((home / KP.did / "entity.json").read_text())["seq"] == 2


def test_document_edit_uses_editor_and_keeps_frozen_fields(home, capsys, monkeypatch, tmp_path):
    ed = tmp_path / "ed.sh"
    ed.write_text("#!/bin/sh\nsed -e 's/\"seq\": 1/\"seq\": 99/' -e 's/\"name\": \"Saved\"/\"name\": \"Edited\"/' \"$1\" > \"$1.new\" && mv \"$1.new\" \"$1\"\n")
    ed.chmod(0o755)
    monkeypatch.setenv("EDITOR", str(ed))
    monkeypatch.delenv("VISUAL", raising=False)
    assert run(capsys, "document", "edit")[0] == 0
    d = json.loads((home / KP.did / "draft.json").read_text())
    assert d["name"] == "Edited" and d["seq"] == 1
    monkeypatch.delenv("EDITOR")
    assert run(capsys, "document", "edit")[0] == 1


def test_alias_domain_platform_and_erc8004(url, home, capsys):
    reg = ["--registry", url]
    code, out = j(capsys, "alias", "add", "domain", "example.com", *reg)
    assert code == 0 and out["alias"] == {"type": "domain", "value": "did:web:example.com"}
    code, out = j(capsys, "alias", "add", "platform", "moltbotden:bot", *reg)
    a = out["alias"]
    assert code == 0 and a["proof"]["type"] == "Ed25519BindingSignature"
    text = f"Open Entity alias binding\neid: {KP.did}\nalias: moltbotden:bot\nissued: {a['proof']['issued']}".encode()
    KP.private.public_key().verify(core.b58decode(a["proof"]["proofValue"][1:]), text)
    assert run(capsys, "alias", "add", "erc8004", f"eip155:8453:0x{'cd' * 20}:1", *reg)[0] == 0
    for bad in (("platform", "nocolon"), ("erc8004", "x"), ("bogus", "x")):
        assert run(capsys, "alias", "add", *bad, *reg)[0] == 1
    assert run(capsys, "alias", "bogus", "domain", "x", *reg)[0] == 1
    draft = json.loads((home / KP.did / "draft.json").read_text())
    assert [x["type"] for x in draft["aliases"]] == ["domain", "platform", "erc8004"]
    assert len(posts(f"/v1/entities/{KP.did}/aliases")) == 3


def test_alias_wallet_is_two_step_with_an_external_siwe_signature(url, home, capsys):
    reg = ["--registry", url]
    wallet = "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"  # EIP-55 reference address
    code, out = j(capsys, "alias", "add", "wallet", wallet, *reg)
    assert code == 0 and not posts(f"/v1/entities/{KP.did}/aliases")
    addr = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
    msg = out["message"]
    assert msg.splitlines()[1] == addr and f"Open Entity alias binding for {KP.did}" in msg and "Chain ID: 8453" in msg and f"- {KP.did}" in msg
    assert re.search(r"Nonce: [A-Za-z0-9]{16}\n", msg) and out["next"].endswith("--signature 0x<signature>")
    assert run(capsys, "alias", "add", "wallet", wallet, "--signature", "nothex", *reg)[0] == 1
    assert run(capsys, "alias", "add", "wallet", "0x" + "11" * 20, "--signature", "0xab", *reg)[0] == 5  # no pending message
    code, out = j(capsys, "alias", "add", "wallet", wallet, "--signature", "0x" + "ab" * 65, *reg)
    (body,) = posts(f"/v1/entities/{KP.did}/aliases")
    assert code == 0 and body == {"type": "wallet", "value": f"did:pkh:eip155:8453:{addr}", "proof": {"type": "Eip4361", "message": msg, "signature": "0x" + "ab" * 65}}
    code, out = j(capsys, "alias", "add", "erc8004", f"eip155:84532:0x{'cd' * 20}:2", "--wallet", wallet, *reg)
    assert code == 0 and "Chain ID: 84532" in out["message"]


def test_verify_reports_a_schema_check_like_the_npm_cli(capsys, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(core.sign_object({"spec": core.SPEC, "eid": KP.did, "name": "T", "layers": {}, "keys": []}, KP)))
    code, out = j(capsys, "verify", str(bad))
    assert code == 3 and out["checks"][0]["name"] == "EntityDocument schema" and not out["checks"][0]["ok"]


def test_verify_refuses_a_file_with_a_duplicate_key(capsys, tmp_path):
    """Spec 4.3: json.loads would keep the last duplicate and verify a different object than the one signed."""
    f = tmp_path / "dup.json"
    f.write_text('{"spec": "openentity/1.0", "name": "A", "name": "B"}')
    code, _, err = run(capsys, "verify", str(f))
    assert code == 1 and "duplicate key" in err
    code, _, err = run(capsys, "verify-presentation", str(f), "--audience", "a", "--nonce", "n")
    assert code == 1 and "duplicate key" in err


def test_log_audit_checks_the_registry_document_with_the_key_its_spec_publishes(url, capsys):
    """The registry's DID names openentity.org, but a registry elsewhere signs with its /v1/spec key (guard: no lookup of did:web:openentity.org)."""
    Stub.leaves = [{"type": "Declaration", "eid": "did:web:openentity.org", "object_sha256": "00" * 32, "received_at": core.now()}]
    Stub.document = core.sign_object({"spec": core.SPEC, "eid": "did:web:openentity.org", "name": "registry"}, LOG_KEY, method="did:web:openentity.org#key-1")
    code, out = j(capsys, "log", "audit", "1", "--registry", url)
    assert code == 0 and {"name": "signature did:web:openentity.org", "ok": True, "detail": "document signature valid"} in out["checks"]


def test_record_push_and_redact(url, home, capsys):
    reg = ["--registry", url]
    assert run(capsys, "record", "arc", "open", "--id", "a", "--title", "A", "--no-push", *reg)[0] == 0
    assert not Stub.chain
    code, out = j(capsys, "record", "push", *reg)
    assert code == 0 and out["entry"] is None and out["pushed"] == 1 and len(Stub.chain) == 1
    code, out = j(capsys, "record", "redact", "1", *reg)
    (red,) = posts(f"/v1/entities/{KP.did}/record/redact")
    assert code == 0 and red["entry_sha256"] == core.canonical_hash(Stub.chain[0]).hex() and core.verify_object(red) == (True, KP.did)
    assert run(capsys, "record", "redact", "9", *reg)[0] == 1
    # an unreachable registry keeps the entry locally and exits 2; `record push` retries it
    code, out = j(capsys, "record", "arc", "open", "--id", "b", "--title", "B", "--registry", "http://127.0.0.1:1")
    assert code == 2 and out["pending"] == 1 and out["entry"]["seq"] == 2
    assert j(capsys, "record", "push", *reg)[1]["pending"] == 0 and len(Stub.chain) == 2


def test_resolve_did_key_pkh_and_unsupported(capsys):
    code, out = j(capsys, "resolve", KP.did)
    assert code == 0 and out["verificationMethod"][0]["publicKeyMultibase"] == KP.did.removeprefix("did:key:")
    assert j(capsys, "resolve", f"did:pkh:eip155:1:0x{'ab' * 20}")[1]["chainId"] == 1
    assert run(capsys, "resolve", "did:pkh:bitcoin:1:x")[0] == 3
    assert run(capsys, "resolve", "did:nope:x")[0] == 1
    assert cli._keys_of(cli.resolve_did(KP.did)) == [KP.public]


def test_log_checkpoint_proof_and_audit(url, capsys):
    Stub.leaves = [{"type": "Declaration", "eid": f"did:key:z{i}", "object_sha256": "00" * 32, "received_at": core.now()} for i in range(6)]
    reg = ["--registry", url]
    code, out = j(capsys, "log", "checkpoint", *reg)
    assert code == 0 and out["verified"] and out["tree_size"] == 6
    code, out = j(capsys, "log", "proof", "3", *reg)
    assert code == 0 and out["verified"] and out["leaf"]["eid"] == "did:key:z3"
    code, out = j(capsys, "log", "audit", "3", *reg)
    inc = [c for c in out["checks"] if c["name"].startswith("inclusion")]
    assert out["checks"][0] == {"name": "checkpoint", "ok": True, "detail": "checkpoint signature valid, tree size 6"}
    assert len(inc) == 3 and all(c["ok"] for c in inc)
    assert code == 0 and any(c["name"].startswith("signature") and c["ok"] for c in out["checks"])
    Stub.forge_note = True
    assert run(capsys, "log", "checkpoint", *reg)[0] == 3
    for bad in (("proof",), ("proof", "x"), ("audit", "0"), ("bogus",)):
        assert run(capsys, "log", *bad, *reg)[0] == 1


def test_export_import_round_trip(url, home, capsys, tmp_path, monkeypatch):
    reg = ["--registry", url]
    assert run(capsys, "record", "arc", "open", "--id", "a", "--title", "A", "--no-push", *reg)[0] == 0
    code, out = j(capsys, "export")
    assert code == 0 and out["format"] == "openentity-bundle/1" and "key" not in out and len(out["record"]) == 1
    f = tmp_path / "b.json"
    assert j(capsys, "export", "--with-key", "--out", str(f))[1]["key_included"] is True
    assert stat.S_IMODE(f.stat().st_mode) == 0o600
    monkeypatch.setenv("OPENENTITY_HOME", str(tmp_path / "new"))
    assert run(capsys, "import", str(f))[0] == 0
    n = tmp_path / "new" / KP.did
    assert (n / "key").exists() and len((n / "record.jsonl").read_text().splitlines()) == 1 and (tmp_path / "new" / "current").read_text().strip() == KP.did
    assert run(capsys, "import", str(f))[0] == 5  # exists
    assert run(capsys, "import", str(f), "--force")[0] == 0
    keyless = tmp_path / "k.json"
    monkeypatch.setenv("OPENENTITY_HOME", str(home))
    assert run(capsys, "export", "--out", str(keyless))[0] == 0
    assert run(capsys, "import", str(keyless), "--force")[0] == 5  # no key in the bundle
    assert run(capsys, "import", str(keyless), "--key", str(n / "key"), "--force")[0] == 0
    assert run(capsys, "import", str(tmp_path / "nope.json"))[0] == 5


@pytest.mark.parametrize("cmd,basis", [("rotate", "rotation"), ("migrate", "migration")])
def test_rotate_and_migrate_move_state_to_the_successor(url, home, capsys, cmd, basis):
    reg = ["--registry", url]
    code, out = j(capsys, cmd, "--dry-run", *reg)
    assert code == 0 and out["link"]["basis"] == basis and not posts("/v1/continuity") and [p.name for p in home.iterdir() if p.is_dir()] == [KP.did]
    code, out = j(capsys, cmd, "--operator", "Ada", *reg)
    assert code == 0 and out["previous"] == KP.did and out["record_pushed"] is True
    new = out["successor"]
    (body,) = posts("/v1/continuity")
    assert body["link"]["basis"] == basis and body["document"]["operator"]["name"] == "Ada" and body["document"]["continuity"]["previous"] == KP.did
    assert (home / "current").read_text().strip() == new
    assert not (home / KP.did).exists() and (home / ".archive" / KP.did / "key").exists() and out["archived_key"] == str(home / ".archive" / KP.did / "key")
    (e,) = Stub.chain
    assert e["eid"] == new and e["kind"] == "continuity" and e["payload"] == {"event": basis, "from": KP.did, "to": new, "link": core.canonical_hash(body["link"]).hex()}
    assert json.loads(run(capsys, "whoami", "--json", *reg)[1])["eid"] == new


def test_rotate_refused_leaves_local_state_untouched(url, home, capsys):
    Stub.refuse = True
    code, _ = j(capsys, "rotate", "--registry", url)
    assert code == 4 and [p.name for p in home.iterdir() if p.is_dir()] == [KP.did] and (home / "current").read_text().strip() == KP.did


def test_rotate_to_a_given_key_file(url, home, capsys, tmp_path):
    nxt = core.KeyPair(b"\x22" * 32)
    kf = tmp_path / "k.json"
    kf.write_text(json.dumps(cli._jwk(nxt)))
    assert j(capsys, "rotate", "--to", str(kf), "--registry", url)[1]["successor"] == nxt.did


def test_recover_two_steps(url, home, capsys):
    reg = ["--registry", url]
    assert run(capsys, "recover", *reg)[0] == 1
    code, out = j(capsys, "recover", "--previous", KP.did, "--via", "did:web:example.com", *reg)
    new = out["successor"]
    assert code == 0 and out["link"]["basis"] == "recovery" and re.fullmatch(r"0x[0-9a-f]{64}", out["eip712_digest"]) and not posts("/v1/continuity")
    assert (home / new / "pending-recovery.json").exists() and (home / "current").read_text().strip() == KP.did
    pending = json.loads((home / new / "pending-recovery.json").read_text())
    assert core.verify_object({**pending["link"], "proof": pending["successorProof"]}) == (True, new)
    assert run(capsys, "recover", "--proof", "p.json", "--eid", KP.did, *reg)[0] == 5  # nothing pending for KP
    proof = home / "proof.json"
    proof.write_text(json.dumps(core.sign_proof(pending["link"], KP)))
    assert run(capsys, "recover", "--eid", new, "--proof", str(proof), *reg)[0] == 0
    (body,) = posts("/v1/continuity")
    assert [p["verificationMethod"].split("#")[0] for p in body["link"]["proofs"]] == [new, KP.did]
    assert (home / "current").read_text().strip() == new and not (home / new / "pending-recovery.json").exists()


def test_verify_presentation_offline(home, capsys, tmp_path):
    p = core.build_presentation(KP, "https://v.example", "n1")
    f = tmp_path / "p.json"
    f.write_text(json.dumps(p))
    code, out = j(capsys, "verify-presentation", str(f), "--audience", "https://v.example", "--nonce", "n1")
    assert code == 0 and out["ok"]
    assert run(capsys, "verify-presentation", str(f), "--audience", "https://v.example", "--nonce", "other")[0] == 3
    assert run(capsys, "verify-presentation", str(f))[0] == 1


def test_verify_checks_continuity_link_proofs(capsys, tmp_path):
    nxt = core.KeyPair(b"\x33" * 32)
    body = core.build_rotation(KP, nxt, core.successor_document({"eid": KP.did}, nxt))
    f = tmp_path / "l.json"
    f.write_text(json.dumps(body["link"]))
    code, out = j(capsys, "verify", str(f))
    assert code == 0 and len(out["checks"]) == 3  # schema + the two link proofs
    f.write_text(json.dumps({**body["link"], "basis": "migration"}))
    assert run(capsys, "verify", str(f))[0] == 3


@pytest.fixture
def real_registry():
    """The real registry app (in-memory PGlite), not the stub. Skipped when the workspace is not installed."""
    import shutil
    import socket
    import subprocess
    import time
    import urllib.request
    from pathlib import Path

    root = Path(__file__).resolve().parents[3]
    if not shutil.which("pnpm") or not (root / "registry/node_modules").exists():
        pytest.skip("registry workspace not installed")
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    p = subprocess.Popen(["pnpm", "--filter", "@openentity/registry", "local", str(port)], cwd=root, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = f"http://127.0.0.1:{port}"
    try:
        for _ in range(120):
            try:
                urllib.request.urlopen(base + "/v1/spec", timeout=1)
                break
            except OSError:
                time.sleep(0.5)
        else:
            pytest.fail("local registry did not start")
        yield base
    finally:
        p.terminate()
        p.wait(10)


@pytest.mark.parametrize("cmd", ["rotate", "migrate"])
def test_rotate_or_migrate_then_withdraw_against_the_real_registry(real_registry, tmp_path, monkeypatch, capsys, cmd):
    """Spec 9.3: the successor inherits the Declaration, so its key can withdraw it; the predecessor stays active."""
    import urllib.request

    monkeypatch.setenv("OPENENTITY_HOME", str(tmp_path))
    monkeypatch.delenv("OPENENTITY_REGISTRY", raising=False)
    monkeypatch.delenv("OPENENTITY_EID", raising=False)
    reg = ["--registry", real_registry]

    def get(eid):
        return json.loads(urllib.request.urlopen(f"{real_registry}/v1/entities/{eid}").read())

    code, a = j(capsys, "adopt", "--name", "Py Withdraw", "--agree", *reg)
    assert code == 0
    code, out = j(capsys, cmd, *reg)
    assert code == 0
    new = out["successor"]
    assert get(new)["declaration_inherited_from"] == a["eid"]
    code, out = j(capsys, "withdraw", "--force", *reg)
    assert code == 0 and out["withdrawn"] is True
    assert get(new)["withdrawn"] is True and get(a["eid"])["withdrawn"] is False
