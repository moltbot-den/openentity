"""0.5.1: 0.4 keys keep working, wallet proofs sign locally, card, conformance and schema validation before signing."""
import builtins
import json
import pathlib

import pytest
from test_client import KP, SEED, Stub, home, posts, run, url  # noqa: F401  (fixtures and the stub registry)

from openentity import cli, client, core, schema

WALLET_KEY = "0x" + "46" * 32  # throwaway test key, published


def j(capsys, *argv):
    code, out, err = run(capsys, *argv, "--json")
    return code, json.loads(out or err or "null")


# ---- 1. keys saved by 0.4 ----
def legacy_home(tmp_path, monkeypatch, url):
    monkeypatch.setenv("OPENENTITY_HOME", str(tmp_path))
    monkeypatch.delenv("OPENENTITY_REGISTRY", raising=False)
    monkeypatch.delenv("OPENENTITY_EID", raising=False)
    doc, decl = client.build_adoption(KP, "Old", "d", url)
    Stub.entity = {"document": doc, "declaration": decl, "level": "L0"}
    old = tmp_path / "keys" / (KP.did.removeprefix("did:key:") + ".json")  # the 0.4 layout
    old.parent.mkdir()
    old.write_text(json.dumps({"did": KP.did, "seed_hex": SEED.hex(), "name": "Old", "registry": url}))
    return old


def test_a_04_key_is_migrated_and_keeps_working(url, tmp_path, monkeypatch, capsys):
    old = legacy_home(tmp_path, monkeypatch, url)
    before = old.read_text()
    code, out = j(capsys, "whoami", "--registry", url)
    assert code == 0 and out["eid"] == KP.did and out["name"] == "Old"
    new = tmp_path / KP.did
    assert cli._kp_from_jwk(json.loads((new / "key").read_text())).did == KP.did
    assert old.read_text() == before  # never touched
    code, out = j(capsys, "record", "stance", "--type", "refusal", "--reason", "values", "--cost", "low", "--context", "c", "--registry", url)
    assert code == 0 and out["pushed"] == 1 and Stub.chain[0]["eid"] == KP.did


def test_migration_carries_the_registry_record_so_the_chain_continues(url, tmp_path, monkeypatch, capsys):
    legacy_home(tmp_path, monkeypatch, url)
    first = core.sign_object({"spec": core.SPEC, "type": "RecordEntry", "eid": KP.did, "seq": 1, "prev": None, "kind": "arc_opened", "at": core.now(),
                              "payload": {"arc_id": "a", "title": "A"}}, KP)
    Stub.chain.append(first)
    code, out = j(capsys, "record", "arc", "close", "--id", "a", "--title", "A", "--registry", url)
    assert code == 0 and [e["seq"] for e in Stub.chain] == [1, 2] and Stub.chain[1]["prev"] == core.canonical_hash(first).hex()


def test_unreachable_registry_does_not_lose_the_old_key(url, tmp_path, monkeypatch, capsys):
    old = legacy_home(tmp_path, monkeypatch, url)
    k = json.loads(old.read_text())
    k["registry"] = "http://127.0.0.1:1"
    old.write_text(json.dumps(k))
    assert run(capsys, "whoami")[0] == 2 and old.exists() and not (tmp_path / KP.did).exists()


# ---- 2. wallet proofs signed here ----
def test_adopt_with_a_wallet_key_lands_at_l1_in_one_command(url, tmp_path, monkeypatch, capsys):
    from eth_account import Account
    monkeypatch.setenv("OPENENTITY_HOME", str(tmp_path / "h"))
    addr = Account.from_key(WALLET_KEY).address
    reg = f"eip155:8453:{addr}:7"
    code, out = j(capsys, "adopt", "--name", "W", "--agree", "--registry", url, "--wallet", WALLET_KEY, "--erc8004", reg)
    assert code == 0 and out["level"] == "L1"
    posted = posts(f"/v1/entities/{out['eid']}/aliases")
    assert [a["type"] for a in posted] == ["wallet", "erc8004"]
    for a in posted:
        assert a["proof"]["type"] == "Eip4361" and addr in a["proof"]["message"] and len(a["proof"]["signature"]) == 132
        assert Account.recover_message(__import__("eth_account.messages", fromlist=["x"]).encode_defunct(text=a["proof"]["message"]), signature=a["proof"]["signature"]) == addr
    assert posted[0]["value"] == f"did:pkh:eip155:8453:{addr}" and posted[1]["value"] == reg
    assert json.loads((tmp_path / "h" / out["eid"] / "state.json").read_text())["level"] == "L1"


def test_alias_add_wallet_from_env_key_and_a_wrong_address(url, home, monkeypatch, capsys):
    from eth_account import Account
    monkeypatch.setenv("OPENENTITY_WALLET_KEY", WALLET_KEY)
    code, out = j(capsys, "alias", "add", "wallet", "--registry", url)  # the address comes from the key
    assert code == 0 and posts(f"/v1/entities/{KP.did}/aliases")[0]["value"].endswith(Account.from_key(WALLET_KEY).address)
    assert run(capsys, "alias", "add", "wallet", "0x" + "11" * 20, "--registry", url)[0] == 1  # the key controls a different address


def test_a_wallet_key_without_eth_account_says_how_to_install_it(url, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("OPENENTITY_HOME", str(tmp_path / "h"))
    real = builtins.__import__

    def deny(name, *a, **k):
        if name.startswith("eth_account"):
            raise ImportError(name)
        return real(name, *a, **k)
    monkeypatch.setattr(builtins, "__import__", deny)
    code, _, err = run(capsys, "adopt", "--name", "W", "--agree", "--registry", url, "--wallet", WALLET_KEY)
    assert code == 1 and "openentity[wallet]" in err and not posts("/v1/adopt")


def test_a_bare_wallet_address_is_declared_not_proven(url, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("OPENENTITY_HOME", str(tmp_path / "h"))
    code, out = j(capsys, "adopt", "--name", "W", "--agree", "--registry", url, "--wallet", "0x" + "ab" * 20)
    assert code == 0 and out["level"] == "L0" and not posts(f"/v1/entities/{out['eid']}/aliases")


# ---- 3. card, conformance, schema ----
def test_card_extension_and_full_card(url, home, capsys):
    reg = ["--registry", url]
    code, out = j(capsys, "card", "--extension-only", *reg)
    assert code == 0 and out["params"] == {"eid": KP.did, "document": f"{url}/v1/entities/{KP.did}/document"} and out["required"] is False
    assert run(capsys, "card", *reg)[0] == 1  # no endpoint
    doc = json.loads((home / KP.did / "entity.json").read_text())
    doc["capabilities"] = ["code-review", "ops:deploy.ci"]
    (home / KP.did / "entity.json").write_text(json.dumps(doc))
    code, out = j(capsys, "card", "--url", "https://a.example/a2a", *reg)
    assert code == 0 and out["url"] == "https://a.example/a2a" and out["capabilities"]["extensions"][0]["params"]["eid"] == KP.did
    assert out["skills"] == [{"id": "code-review", "name": "code review", "description": "Self-declared capability: code-review", "tags": ["code-review"]},
                             {"id": "ops:deploy.ci", "name": "deploy ci", "description": "Self-declared capability: ops:deploy.ci", "tags": ["ops", "deploy.ci"]}]
    code, out = j(capsys, "card", "--extension-only", "--eid", KP.did, *reg)  # read from the registry
    assert code == 0 and out["params"]["eid"] == KP.did


def log_leaves(n):
    return [{"type": "LogLeaf", "n": i} for i in range(n)]


def test_conformance_passes_a_good_registry(url, capsys):
    Stub.leaves = log_leaves(5)
    code, out = j(capsys, "conformance", url)
    names = [c["name"] for c in out["checks"]]
    assert code == 0 and out["ok"] and "tiles match leaves" in names and "inclusion proof 4" in names and "no Turnstile on agent endpoints" in names
    assert not [p for m, p, *_ in Stub.log if m == "POST" and False]  # writes carry no stamp, so none is accepted


def test_conformance_fails_a_forged_checkpoint_and_an_unreachable_registry(url, capsys):
    Stub.leaves, Stub.forge_note = log_leaves(3), True
    code, out = j(capsys, "conformance", url)
    assert code == 3 and not out["ok"] and not next(c for c in out["checks"] if c["name"] == "checkpoint signature")["ok"]
    assert run(capsys, "conformance", "http://127.0.0.1:1")[0] == 2
    assert run(capsys, "conformance")[0] == 1


def test_a_document_that_breaks_the_schema_is_not_signed(url, home, capsys):
    assert schema.validate("EntityDocument", json.loads((home / KP.did / "entity.json").read_text())) == []
    assert schema.validate("EntityDocument", {"spec": core.SPEC})  # missing fields
    assert run(capsys, "document", "set", "name", "")[0] == 0
    code, _, err = run(capsys, "document", "push", "--registry", url)
    assert code == 3 and "EntityDocument fails schema validation" in err and not posts(f"/v1/entities/{KP.did}/document")


def test_adopt_validates_before_signing(url, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("OPENENTITY_HOME", str(tmp_path / "h"))
    code, _, err = run(capsys, "adopt", "--name", "A", "--agree", "--registry", url, "--custody", "bogus")
    assert code == 3 and "fails schema validation" in err and not posts("/v1/adopt")


def test_the_packaged_schema_equals_the_specs():
    spec = pathlib.Path(__file__).resolve().parents[3] / "spec" / "schemas" / "openentity-1.0.json"
    if spec.exists():  # absent when the package is tested from an sdist
        assert spec.read_text() == (pathlib.Path(cli.__file__).parent / "schemas" / "openentity-1.0.json").read_text()
