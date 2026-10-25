"""withdraw, record, dispute, find, present against a stub registry (same pattern as test_core.py)."""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

import pytest

from openentity import cli, client, core

SEED = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")  # RFC 8032 test 1, public
SUBJECT = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
BITS = 8


class Stub(BaseHTTPRequestHandler):
    log: list = []
    chain: list = []  # accepted record entries
    attestations: list = []

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
            return self._send(200, {"head": head, "entries": Stub.chain})
        if u.path.endswith("/attestations"):
            return self._send(200, {"attestations": Stub.attestations})
        if u.path.startswith("/v1/entities/"):
            return self._send(200, {"document": {"name": "Tester"}})
        self._send(404, {"error": "not_found", "message": u.path})

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["content-length"])))
        stamp = self.headers.get("x-oe-stamp")
        Stub.log.append(("POST", self.path, body, stamp))
        eid = body.get("eid") or body.get("issuer")
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
        if not core.verify_object(body)[0]:
            return self._send(422, {"error": "bad_signature", "message": "sig"})
        if self.path == "/v1/withdraw":
            return self._send(201, {"eid": body["eid"], "withdrawn": True, "log_index": 7})
        if self.path == "/v1/disputes":
            return self._send(201, {"subject": body["subject"], "answer_by": "2026-11-01T00:00:00Z", "log_index": 8})
        self._send(404, {"error": "not_found", "message": self.path})


@pytest.fixture
def url():
    Stub.log, Stub.chain, Stub.attestations = [], [], []
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


def test_cli_subcommands(url, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("OPENENTITY_HOME", str(tmp_path))
    keys = tmp_path / "keys"
    keys.mkdir()
    (keys / "k.json").write_text(json.dumps({"did": KP.did, "seed_hex": SEED.hex()}))
    reg = ["--registry", url]
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
