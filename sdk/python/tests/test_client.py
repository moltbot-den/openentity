"""withdraw, record, dispute, find, present against a stub registry (same pattern as test_core.py)."""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

from openentity import cli, client, core

SEED = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")  # RFC 8032 test 1, public
SUBJECT = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
BITS = 8


class Stub(BaseHTTPRequestHandler):
    log: list = []
    chain: list = []  # accepted record entries
    attestations: list = []
    entity: dict | None = None  # overrides GET /v1/entities/<eid>
    refuse = None  # set to refuse every continuity link

    def log_message(self, *a):
        pass

    def _send(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        u = urlparse(self.path)
        Stub.log.append(("GET", self.path, None, None))
        if u.path == "/v1/spec":
            return self._send(200, {"spec": core.SPEC, "stamp_bits": BITS})
        if u.path == "/v1/entities":
            return self._send(200, {"entities": [{"eid": SUBJECT, "name": "N", "level": "L0"}], "page": 0, "next_page": None})
        if u.path.endswith("/record"):
            last = Stub.chain[-1] if Stub.chain else None
            head = {"seq": last["seq"], "hash": core.canonical_hash(last).hex()} if last else None
            after = int(parse_qs(u.query).get("after", ["0"])[0])
            return self._send(200, {"head": head, "entries": [e for e in Stub.chain if e["seq"] > after]})
        if u.path.endswith("/attestations"):
            return self._send(200, {"attestations": Stub.attestations})
        if u.path.endswith("/document"):
            return self._send(200, client.build_adoption(core.KeyPair(SEED), "Tester", "d", "http://x")[0])
        if u.path.startswith("/v1/entities/"):
            return self._send(200, Stub.entity or {"document": {"name": "Tester"}, "level": "L0"})
        self._send(404, {"error": "not_found", "message": u.path})

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["content-length"])))
        stamp = self.headers.get("x-oe-stamp")
        Stub.log.append(("POST", self.path, body, stamp))
        eid = body.get("eid") or body.get("issuer") or body.get("link", {}).get("successor")
        if not stamp or core.check_stamp(stamp, BITS, eid or self.path.split("/")[3]):
            return self._send(400, {"error": "stamp_required", "message": "stamp"})
        if self.path.endswith("/record"):
            for e in body["entries"]:
                last = Stub.chain[-1] if Stub.chain else None
                ok = e["seq"] == (last["seq"] + 1 if last else 1) and e["prev"] == (core.canonical_hash(last).hex() if last else None)
                if not ok or not core.verify_object(e)[0]:
                    return self._send(409, {"error": "bad_chain", "message": "chain"})
                Stub.chain.append(e)
            return self._send(200, {"accepted": len(body["entries"])})
        if self.path == "/v1/continuity":
            link = body["link"]
            ok = Stub.refuse is None and all(core.verify_object({**link, "proof": p}) == (True, d) for p, d in zip(link["proofs"], (link["previous"], link["successor"])))
            if not ok or core.verify_object(body["document"])[1] != link["successor"]:
                return self._send(422, {"error": "continuity_proof_missing", "message": "no"})
            return self._send(201, {"previous": link["previous"], "successor": link["successor"], "basis": link["basis"]})
        if not core.verify_object(body)[0]:
            return self._send(422, {"error": "bad_signature", "message": "sig"})
        if self.path == "/v1/withdraw":
            return self._send(201, {"eid": body["eid"], "withdrawn": True, "log_index": 7})
        if self.path == "/v1/disputes":
            return self._send(201, {"subject": body["subject"], "answer_by": "2026-11-01T00:00:00Z", "log_index": 8})
        self._send(404, {"error": "not_found", "message": self.path})


@pytest.fixture
def url():
    Stub.log, Stub.chain, Stub.attestations, Stub.entity, Stub.refuse = [], [], [], None, None
    srv = HTTPServer(("127.0.0.1", 0), Stub)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


KP = core.KeyPair(SEED)


def posts(path):
    return [b for m, p, b, _ in Stub.log if m == "POST" and p == path]


def test_withdraw_signs_a_withdrawal_for_the_registry_name(url):
    res = client.withdraw(SEED, registry=url)
    (w,) = posts("/v1/withdraw")
    assert w["type"] == "Withdrawal" and w["eid"] == KP.did and w["name"] == "Tester" and w["declaration_version"] == "1.0"
    assert "text_sha256" not in w and core.verify_object(w) == (True, KP.did)
    assert res["withdrawn"] is True


def test_record_chains_seq_and_prev_from_the_registry_head(url):
    first = client.record(SEED, [("stance", {"stance_type": "refusal", "reason_category": "values", "instruction_conflict": False, "cost": "low", "context": "c"})], registry=url)
    second = client.record(SEED, [("belief_update", {"topic": "t", "from_summary": "a", "to_summary": "b"}),
                                  ("arc_opened", {"arc_id": "x", "title": "X"})], registry=url)
    assert [e["seq"] for e in Stub.chain] == [1, 2, 3]
    assert Stub.chain[0]["prev"] is None and Stub.chain[1]["prev"] == core.canonical_hash(Stub.chain[0]).hex()
    assert Stub.chain[2]["prev"] == core.canonical_hash(Stub.chain[1]).hex()
    assert first["accepted"] == 1 and second["accepted"] == 2
    assert all(core.verify_object(e) == (True, KP.did) for e in Stub.chain)


def test_record_pushes_in_batches_of_100(url):
    client.record(SEED, [("arc_opened", {"arc_id": str(i), "title": "t"}) for i in range(104)], registry=url)
    assert [len(b["entries"]) for b in posts(f"/v1/entities/{KP.did}/record")] == [100, 4]
    assert len(Stub.chain) == 104


def test_dispute_signs_and_posts_with_a_stamp(url):
    obj = "ab" * 32
    res = client.dispute(SEED, SUBJECT, "inaccurate", "This is wrong.", object_sha256=obj, registry=url)
    (d,) = posts("/v1/disputes")
    assert (d["type"], d["issuer"], d["subject"], d["object_sha256"], d["reason"]) == ("Dispute", KP.did, SUBJECT, obj, "inaccurate")
    assert core.verify_object(d) == (True, KP.did) and res["answer_by"]
    client.dispute(SEED, SUBJECT, "other", "x", registry=url)
    assert "object_sha256" not in posts("/v1/disputes")[1]
    with pytest.raises(ValueError):
        client.dispute(SEED, SUBJECT, "spite", "x", registry=url)
    with pytest.raises(ValueError):
        client.dispute(SEED, SUBJECT, "other", "x", object_sha256="nothex", registry=url)


def test_find_passes_the_filters(url):
    res = client.find(url, capability="code-review", q="N", alias_type="domain", level="L1")
    assert res["entities"][0]["eid"] == SUBJECT
    assert Stub.log[-1][1] == "/v1/entities?capability=code-review&q=N&alias_type=domain&level=L1"


def test_present_carries_only_current_attestations(url):
    issuer = core.KeyPair()
    att = lambda exp: core.sign_object({"spec": core.SPEC, "type": "Attestation", "issuer": issuer.did, "subject": KP.did,
                                        "claim_type": "trust_tier", "claim": {"tier": 2, "platform": "x"}, "created": core.now(), "expires": exp}, issuer)
    live = att("2099-01-01T00:00:00Z")
    Stub.attestations = [{"attestation": live, "expired": False, "revoked_at": None, "inherited_from": None},
                         {"attestation": att("2020-01-01T00:00:00Z"), "expired": True, "revoked_at": None, "inherited_from": None},
                         {"attestation": att("2099-01-01T00:00:00Z"), "expired": False, "revoked_at": "2026-10-01T00:00:00Z", "inherited_from": None}]
    nonce = core.nonce()
    p = client.present(SEED, "https://v.example", nonce, registry=url)
    assert p["attestations"] == [live] and core.verify_presentation(p, "https://v.example", nonce)["ok"]
    bare = client.present(SEED, "https://v.example", nonce)  # no registry: no attestations
    assert "attestations" not in bare and core.verify_presentation(bare, "https://v.example", nonce)["ok"]


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENENTITY_HOME", str(tmp_path))
    monkeypatch.delenv("OPENENTITY_REGISTRY", raising=False)
    monkeypatch.delenv("OPENENTITY_EID", raising=False)
    (tmp_path / "keys").mkdir()
    (tmp_path / "keys" / "k.json").write_text(json.dumps({"did": KP.did, "seed_hex": SEED.hex(), "name": "Saved"}))
    return tmp_path


def run(capsys, *argv):
    code = cli.main(list(argv))
    out = capsys.readouterr()
    return code, out.out, out.err


def test_cli_record_from_flags_and_raw_payload(url, home, capsys):
    reg = ["--registry", url]
    code, out, _ = run(capsys, "record", "stance", "--type", "refusal", "--reason", "values", "--cost", "low", "--context", "c", "--conflict", "--json", *reg)
    res = json.loads(out)
    assert code == 0 and res["pushed"] == 1 and res["pending"] == 0 and res["entry"]["seq"] == 1
    assert Stub.chain[0]["payload"] == {"stance_type": "refusal", "reason_category": "values", "instruction_conflict": True, "cost": "low", "context": "c"}
    assert run(capsys, "record", "arc", "open", "--id", "a", "--title", "A", *reg)[0] == 0
    assert run(capsys, "record", "update", "--topic", "t", "--from", "x", "--to", "y", *reg)[0] == 0
    assert run(capsys, "record", "collab", "--with", "w", "--role", "r", "--outcome", "o", *reg)[0] == 0
    assert run(capsys, "record", "continuity", "--event", "rotation", "--from", "a", "--to", "b", *reg)[0] == 0
    assert run(capsys, "record", "arc_closed", "--payload", '{"arc_id":"a","title":"A"}', *reg)[0] == 0
    assert [e["kind"] for e in Stub.chain] == ["stance", "arc_opened", "belief_update", "collaboration", "continuity", "arc_closed"]
    assert all(core.verify_object(e) == (True, KP.did) for e in Stub.chain)
    n = len(Stub.chain)
    for bad in (("record", "stance", "--type", "refusal"), ("record", "stance", "--type", "nope", "--reason", "values", "--cost", "low", "--context", "c"),
                ("record", "arc"), ("record", "bogus"), ("record", "stance", "--payload", "{nope")):
        assert run(capsys, *bad, *reg)[0] == 1
    assert len(Stub.chain) == n


def test_cli_whoami_and_self(url, home, capsys):
    reg = ["--registry", url]
    code, out, _ = run(capsys, "whoami", "--json", *reg)
    assert code == 0 and json.loads(out) == {"eid": KP.did, "name": "Tester", "level": "L0", "registry": url, "home": str(home)}
    assert "name: Tester" in run(capsys, "whoami", *reg)[1]
    code, out, _ = run(capsys, "whoami", "--json", "--registry", "http://127.0.0.1:1")  # offline: falls back to the key file
    assert code == 0 and json.loads(out)["name"] == "Saved" and json.loads(out)["level"] is None
    for i in range(3):
        client.record(SEED, [("arc_opened", {"arc_id": str(i), "title": "t"})], registry=url)
    code, out, _ = run(capsys, "self", "--entries", "2", "--json", *reg)
    res = json.loads(out)
    assert code == 0 and res["document"]["name"] == "Tester" and [e["seq"] for e in res["entries"]] == [2, 3]
    assert json.loads(run(capsys, "self", "--entries", "0", "--json", *reg)[1])["entries"] == []
    assert "last 3 record entries" in run(capsys, "self", *reg)[1]
    assert run(capsys, "self", "--entries", "-1", *reg)[0] == 1


def test_cli_verify_entity_file_and_failures(url, home, capsys, tmp_path):
    reg = ["--registry", url]
    decl = core.sign_object({"spec": core.SPEC, "type": "Declaration", "eid": KP.did, "declaration_version": "1.0",
                             "text_sha256": core.DECLARATION_SHA256, "name": "T", "created": core.now(), "nonce": core.nonce()}, KP)
    doc = core.sign_object({"spec": core.SPEC, "eid": KP.did, "name": "T", "layers": {}, "keys": []}, KP)
    Stub.entity = {"document": doc, "declaration": decl}
    client.record(SEED, [("arc_opened", {"arc_id": "a", "title": "A"}), ("arc_opened", {"arc_id": "b", "title": "B"})], registry=url)
    code, out, _ = run(capsys, "verify", KP.did, "--json", *reg)
    res = json.loads(out)
    assert code == 0 and res["ok"] and "record chain (2 entries)" in [c["name"] for c in res["checks"]]
    assert "VERIFIED" in run(capsys, "verify", KP.did, *reg)[1]
    f = tmp_path / "decl.json"
    f.write_text(json.dumps(decl))
    assert run(capsys, "verify", str(f))[0] == 0
    f.write_text(json.dumps({**decl, "name": "tampered"}))
    code, out, _ = run(capsys, "verify", str(f))
    assert code == 3 and "VERIFICATION FAILED" in out
    f.write_text(json.dumps(core.sign_object({**{k: v for k, v in decl.items() if k != "proof"}, "text_sha256": "00" * 32}, KP)))
    assert run(capsys, "verify", str(f))[0] == 3  # signed, but not the Declaration text
    Stub.chain[1] = {**Stub.chain[1], "prev": "00" * 32}  # broken chain
    assert run(capsys, "verify", KP.did, *reg)[0] == 3
    assert run(capsys, "verify", str(tmp_path / "missing.json"))[0] == 1


def test_cli_exit_codes(url, home, capsys, monkeypatch):
    reg = ["--registry", url]
    assert run(capsys, "withdraw", *reg)[0] == 1 and posts("/v1/withdraw") == []  # needs --force, nothing sent
    code, out, _ = run(capsys, "withdraw", "--force", "--json", *reg)
    assert code == 0 and json.loads(out)["withdrawn"] is True and len(posts("/v1/withdraw")) == 1
    assert "withdrawn: " in run(capsys, "withdraw", "--force", *reg)[1]
    code, _, err = run(capsys, "dispute", "--subject", SUBJECT, "--reason", "spite", "--statement", "x", "--json", *reg)
    assert code == 1 and json.loads(err)["code"] == 1
    assert run(capsys, "dispute", "--subject", SUBJECT, "--reason", "other", "--statement", "x", *reg)[0] == 0
    assert run(capsys, "present", "--audience", "https://v.example", "--nonce", "n1", *reg)[0] == 0
    assert json.loads(run(capsys, "present", "--audience", "a", "--nonce", "n", "--no-attestations", *reg)[1])["type"] == "Presentation"
    assert SUBJECT in run(capsys, "find", "--capability", "code-review", *reg)[1]
    assert run(capsys, "find", "--registry", "http://127.0.0.1:1")[0] == 2  # unreachable
    for bad in ("bogus", "record"):  # argparse usage errors exit 1, not argparse's 2
        with pytest.raises(SystemExit) as e:
            run(capsys, bad)
        assert e.value.code == 1
    # local state: two keys and no --eid is 5, and --eid or OPENENTITY_EID picks one
    (home / "keys" / "k2.json").write_text(json.dumps({"did": core.KeyPair().did, "seed_hex": "11" * 32}))
    assert run(capsys, "withdraw", "--force", *reg)[0] == 5
    assert run(capsys, "withdraw", "--force", "--eid", KP.did, *reg)[0] == 0
    monkeypatch.setenv("OPENENTITY_EID", KP.did)
    assert run(capsys, "withdraw", "--force", *reg)[0] == 0


@pytest.mark.parametrize("status,code", [(409, 4), (503, 2)])
def test_cli_registry_status_maps_to_exit_code(url, home, capsys, monkeypatch, status, code):
    def boom(*a, **k):
        raise client.RegistryError(status, "x")
    monkeypatch.setattr(client, "_request", boom)
    assert run(capsys, "record", "arc", "open", "--id", "a", "--title", "A", "--registry", url)[0] == code


def test_cli_registry_comes_from_the_flag_env_or_the_saved_key(url, home, capsys, monkeypatch):
    (home / "keys" / "k.json").write_text(json.dumps({"did": KP.did, "seed_hex": SEED.hex(), "registry": url}))
    assert json.loads(run(capsys, "whoami", "--json")[1])["registry"] == url
    monkeypatch.setenv("OPENENTITY_REGISTRY", "http://127.0.0.1:1")
    assert json.loads(run(capsys, "whoami", "--json")[1])["registry"] == "http://127.0.0.1:1"
    assert json.loads(run(capsys, "whoami", "--json", "--registry", url)[1])["registry"] == url


    assert cli.main(["record", "arc_opened", "--payload", '{"arc_id":"a","title":"A"}', *reg]) == 0
    assert [e["kind"] for e in Stub.chain] == ["arc_opened"]
    assert cli.main(["dispute", "--subject", SUBJECT, "--reason", "other", "--statement", "x", *reg]) == 0
    assert cli.main(["dispute", "--subject", SUBJECT, "--reason", "spite", "--statement", "x", *reg]) == 1
    capsys.readouterr()
    assert cli.main(["find", "--capability", "code-review", *reg]) == 0
    assert SUBJECT in capsys.readouterr().out
    assert cli.main(["present", "--audience", "https://v.example", "--nonce", "n1", *reg]) == 0
    assert json.loads(capsys.readouterr().out)["type"] == "Presentation"
    assert cli.main(["withdraw", *reg]) == 2  # needs --force, nothing sent
    assert posts("/v1/withdraw") == []
    assert cli.main(["withdraw", "--force", *reg]) == 0 and len(posts("/v1/withdraw")) == 1
    (keys / "k2.json").write_text(json.dumps({"did": core.KeyPair().did, "seed_hex": "11" * 32}))
    assert cli.main(["withdraw", "--force", *reg]) == 1  # two keys, no --eid: ambiguous
    assert cli.main(["withdraw", "--force", "--eid", KP.did, *reg]) == 0


def test_rotate_signs_with_both_keys_stamps_for_the_successor_and_returns_the_new_seed(url):
    out = client.rotate(SEED, registry=url)
    (body,) = posts("/v1/continuity")
    new = core.KeyPair(bytes.fromhex(out["seed_hex"]))
    link = body["link"]
    assert (link["previous"], link["successor"], link["basis"]) == (KP.did, new.did, "rotation") and out["did"] == new.did
    assert [p["verificationMethod"].split("#")[0] for p in link["proofs"]] == [KP.did, new.did]
    assert body["document"]["eid"] == new.did and body["document"]["seq"] == 1 and body["document"]["continuity"]["previous"] == KP.did
    assert core.check_stamp([s for m, p, _, s in Stub.log if p == "/v1/continuity"][0], BITS, new.did) is None


def test_rotate_the_registry_refuses_raises_and_returns_nothing(url):
    Stub.refuse = True
    with pytest.raises(client.RegistryError) as e:
        client.rotate(SEED, registry=url)
    assert e.value.status == 422
