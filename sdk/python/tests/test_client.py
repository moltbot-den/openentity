"""withdraw, record, dispute, find, present against a stub registry (same pattern as test_core.py)."""
import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

from openentity import cli, client, core

SEED = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")  # RFC 8032 test 1, public
SUBJECT = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
BITS = 8
ORIGIN = "openentity.org/log"
LOG_KEY = core.KeyPair(b"\7" * 32)  # throwaway registry checkpoint key


class Stub(BaseHTTPRequestHandler):
    log: list = []
    chain: list = []  # accepted record entries
    attestations: list = []
    entity: dict | None = None  # overrides GET /v1/entities/<eid>
    refuse = False  # refuse every continuity link
    leaves: list = []  # the stub log's leaf objects; the checkpoint is signed by LOG_KEY
    forge_note = False
    chain_base = 5  # log index of record entry 1; the verify test appends the chain's leaves there
    document: dict | None = None  # overrides GET /v1/entities/<eid>/document

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
            reg = {"log_origin": ORIGIN, "publicKeyMultibase": "z" + core.base58btc_encode(b"\xed\x01" + LOG_KEY.public)}
            return self._send(200, {"spec": core.SPEC, "stamp_bits": BITS, "registry": reg, "declaration": {"sha256": core.DECLARATION_SHA256}})
        hs = [core.leaf_hash(core.canonicalize(lf).encode()) for lf in Stub.leaves]
        if u.path.startswith("/v1/log/tile/"):
            leaves = [core.canonicalize(lf).encode() for lf in Stub.leaves]
            data = b"".join(hs) if "/tile/0/" in u.path else b"".join(len(x).to_bytes(2, "big") + x for x in leaves)
            self.send_response(200)
            self.send_header("content-length", str(len(data)))
            self.end_headers()
            return self.wfile.write(data)
        if u.path in ("/v1/log/sth", "/v1/log/checkpoint"):
            root = core.merkle_root(hs)
            body = f"{ORIGIN}\n{len(hs)}\n{base64.b64encode(root).decode()}\n"
            keyid = core.sha256(ORIGIN.encode() + b"\n\x01" + LOG_KEY.public)[:4]
            sig = base64.b64encode(keyid + (KP if Stub.forge_note else LOG_KEY).private.sign(body.encode())).decode()
            note = f"{body}\n\u2014 {ORIGIN} {sig}\n"
            if u.path.endswith("checkpoint"):
                self.send_response(200)
                self.send_header("content-length", str(len(note.encode())))
                self.end_headers()
                return self.wfile.write(note.encode())
            return self._send(200, {"tree_size": len(hs), "root_hash": root.hex(), "signature": note})
        if u.path == "/v1/log/entries":
            q = parse_qs(u.query)
            i = int(q["start"][0])
            end = int(q.get("end", [i + 1])[0])
            return self._send(200, {"entries": [{"index": k, "leaf": Stub.leaves[k], "leaf_hash": hs[k].hex()} for k in range(i, min(end, len(hs)))]})
        if u.path.startswith("/v1/log/proof/"):
            i = int(u.path.rsplit("/", 1)[1])
            if i >= len(hs):
                return self._send(404, {"error": "not_found", "message": "no such leaf"})
            return self._send(200, {"leaf_hash": hs[i].hex(), "proof": [h.hex() for h in core.inclusion_proof(i, hs)]})
        if u.path == "/v1/stats":
            return self._send(200, {"entities": 3})
        if u.path == "/v1/entities":
            return self._send(200, {"entities": [{"eid": SUBJECT, "name": "N", "level": "L0"}], "page": 0, "next_page": None})
        if u.path.endswith("/record"):
            last = Stub.chain[-1] if Stub.chain else None
            head = {"seq": last["seq"], "hash": core.canonical_hash(last).hex()} if last else None
            after = int(parse_qs(u.query).get("after", ["0"])[0])
            return self._send(200, {"head": head, "entries": [e for e in Stub.chain if e["seq"] > after],
                                  "log_indexes": [Stub.chain_base + e["seq"] - 1 for e in Stub.chain if e["seq"] > after]})
        if u.path.endswith("/attestations"):
            return self._send(200, {"attestations": Stub.attestations})
        if u.path.endswith("/document"):
            return self._send(200, Stub.document or client.build_adoption(core.KeyPair(SEED), "Tester", "d", "http://x")[0])
        if "NoSuchEntity" in u.path:
            return self._send(404, {"error": "not_found", "message": "no such entity"})
        if u.path.startswith("/v1/entities/"):
            return self._send(200, Stub.entity or {"document": {"name": "Tester"}, "level": "L0"})
        self._send(404, {"error": "not_found", "message": u.path})

    def do_PUT(self):
        self.do_POST()

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["content-length"])))
        stamp = self.headers.get("x-oe-stamp")
        Stub.log.append((self.command, self.path, body, stamp))
        eid = body.get("eid") or body.get("issuer") or body.get("link", {}).get("successor") or body.get("document", {}).get("eid")
        if not stamp or core.check_stamp(stamp, BITS, eid or self.path.split("/")[3]):
            return self._send(400, {"error": "stamp_required", "message": "stamp"})
        if self.path == "/v1/adopt":
            return self._send(200, {"eid": eid, "level": "L0", "log_index": 0, "urls": {"entity": "x"}, "receipt": {"leaf_hash": "ab"}})
        if self.path.endswith("/aliases"):
            proof = body.get("proof") or {}
            if proof.get("type") == "Eip4361":  # stands in for the registry's wallet check (and its Base RPC): the signature must recover the address in the message
                from eth_account import Account
                from eth_account.messages import encode_defunct
                who = None if proof["signature"] == "0x" + "ab" * 65 else Account.recover_message(encode_defunct(text=proof["message"]), signature=proof["signature"])  # the two-step test sends a placeholder the stub does not judge
                if who:
                    if who not in proof["message"]:
                        return self._send(422, {"error": "bad_wallet_proof", "message": "no"})
                    Stub.entity = {"document": {"name": "Tester"}, "level": "L1"}
            return self._send(201, {"verified": True})
        if self.path.endswith("/record/redact"):
            return self._send(200, {"placeholder": {"seq": body["seq"], "redacted": True, "hash": body["entry_sha256"]}})
        if self.command == "PUT":
            return self._send(200, {"seq": body["seq"]}) if core.verify_object(body)[0] else self._send(422, {"error": "bad_signature", "message": "sig"})
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
            ok = not Stub.refuse and sorted(core.verify_object({**link, "proof": p}) for p in link["proofs"]) == sorted([(True, link["previous"]), (True, link["successor"])])
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
    Stub.log, Stub.chain, Stub.attestations, Stub.entity, Stub.refuse, Stub.leaves, Stub.forge_note, Stub.document = [], [], [], None, False, [], False, None
    srv = HTTPServer(("127.0.0.1", 0), Stub)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


KP = core.KeyPair(SEED)


def posts(path):
    return [b for m, p, b, _ in Stub.log if m in ("POST", "PUT") and p == path]


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
                                        "claim_type": "trust_tier", "claim": {"tier": 2, "platform": "x"}, "created": core.now_seconds(), "expires": exp}, issuer)
    live = att("2099-01-01T00:00:00Z")
    Stub.attestations = [{"attestation": live, "expired": False, "revoked_at": None, "inherited_from": None},
                         {"attestation": att("2020-01-01T00:00:00Z"), "expired": True, "revoked_at": None, "inherited_from": None},
                         {"attestation": att("2099-01-01T00:00:00Z"), "expired": False, "revoked_at": "2026-10-01T00:00:00Z", "inherited_from": None}]
    nonce = core.random_nonce()
    p = client.present(SEED, "https://v.example", nonce, registry=url)
    assert p["attestations"] == [live] and core.verify_presentation(p, "https://v.example", nonce)["ok"]
    bare = client.present(SEED, "https://v.example", nonce)  # no registry: no attestations
    assert "attestations" not in bare and core.verify_presentation(bare, "https://v.example", nonce)["ok"]


@pytest.fixture
def home(tmp_path, monkeypatch):
    """An OPENENTITY_HOME holding one saved entity (KP), laid out like the npm CLI's."""
    monkeypatch.setenv("OPENENTITY_HOME", str(tmp_path))
    monkeypatch.delenv("OPENENTITY_REGISTRY", raising=False)
    monkeypatch.delenv("OPENENTITY_EID", raising=False)
    doc, decl = client.build_adoption(KP, "Saved", "d", "http://x")
    cli._create_dir(KP, doc, {"registry": "http://x", "docSeq": 1, "recordPushed": 0}, decl)
    cli._set_current(KP.did)
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
    assert code == 0 and json.loads(out) == {"eid": KP.did, "name": "Saved", "level": "L0", "registry": url, "home": str(home)}
    assert "name: Saved" in run(capsys, "whoami", *reg)[1]
    code, out, _ = run(capsys, "whoami", "--json", "--registry", "http://127.0.0.1:1")  # offline: falls back to the saved state
    assert code == 0 and json.loads(out)["name"] == "Saved" and json.loads(out)["level"] is None
    for i in range(3):
        assert run(capsys, "record", "arc", "open", "--id", str(i), "--title", "t", "--no-push", *reg)[0] == 0
    code, out, _ = run(capsys, "self", "--entries", "2", "--json", *reg)
    res = json.loads(out)
    assert code == 0 and res["document"]["name"] == "Saved" and [e["seq"] for e in res["entries"]] == [2, 3]
    assert json.loads(run(capsys, "self", "--entries", "0", "--json", *reg)[1])["entries"] == []
    assert "last 3 record entries" in run(capsys, "self", *reg)[1]
    assert run(capsys, "self", "--entries", "-1", *reg)[0] == 1


def test_cli_verify_entity_file_and_failures(url, home, capsys, tmp_path):
    reg = ["--registry", url]
    doc, decl = client.build_adoption(KP, "T", "d", "http://x")  # verify now checks the schemas too
    Stub.leaves = [{"type": "Declaration", "eid": f"did:key:z{i}", "object_sha256": "00" * 32, "received_at": core.now_seconds()} for i in range(5)]
    Stub.entity = {"document": doc, "declaration": decl, "log_index": 3}
    client.record(SEED, [("arc_opened", {"arc_id": "a", "title": "A"}), ("arc_opened", {"arc_id": "b", "title": "B"})], registry=url)
    Stub.leaves += [{"type": "RecordEntry", "eid": KP.did, "object_sha256": core.record_entry_hash(e), "received_at": core.now_seconds()} for e in Stub.chain]
    code, out, _ = run(capsys, "verify", KP.did, "--json", *reg)
    res = json.loads(out)
    names = [c["name"] for c in res["checks"]]
    assert code == 0 and res["ok"] and "record chain (2 entries)" in names and "checkpoint" in names and "log inclusion" in names
    assert "record inclusion (2 entries)" in names
    Stub.leaves[6] = {**Stub.leaves[6], "object_sha256": "00" * 32}  # the leaf for entry 2 covers some other object
    code, out, _ = run(capsys, "verify", KP.did, *reg)
    assert code == 3 and "FAIL record inclusion (2 entries): failed for 2" in out
    Stub.leaves[6] = {**Stub.leaves[6], "object_sha256": core.record_entry_hash(Stub.chain[1])}
    Stub.forge_note = True  # checkpoint signed by a key other than the registry's
    assert run(capsys, "verify", KP.did, *reg)[0] == 3
    Stub.forge_note = False
    Stub.entity = {**Stub.entity, "log_index": 9}  # no such leaf
    assert run(capsys, "verify", KP.did, *reg)[0] == 3
    Stub.entity = {**Stub.entity, "log_index": None}
    assert "did not report a log index" in run(capsys, "verify", KP.did, *reg)[1]
    Stub.entity = {**Stub.entity, "log_index": 3}
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
    assert run(capsys, "find", "--capability", "x", "--registry", "http://127.0.0.1:1")[0] == 2  # unreachable
    for bad in ("bogus", "record"):  # argparse usage errors exit 1, not argparse's 2
        with pytest.raises(SystemExit) as e:
            run(capsys, bad)
        assert e.value.code == 1
    # local state: two keys and no --eid is 5, and --eid or OPENENTITY_EID picks one
    k2 = core.KeyPair(b"\x11" * 32)
    cli._create_dir(k2, {"name": "Two"}, {"registry": url, "docSeq": 1, "recordPushed": 0})
    (home / "current").unlink()
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


def test_cli_registry_comes_from_the_flag_env_or_the_saved_state(url, home, capsys, monkeypatch):
    st = json.loads((home / KP.did / "state.json").read_text())
    (home / KP.did / "state.json").write_text(json.dumps({**st, "registry": url}))
    assert json.loads(run(capsys, "whoami", "--json")[1])["registry"] == url
    monkeypatch.setenv("OPENENTITY_REGISTRY", "http://127.0.0.1:1")
    assert json.loads(run(capsys, "whoami", "--json")[1])["registry"] == "http://127.0.0.1:1"
    assert json.loads(run(capsys, "whoami", "--json", "--registry", url)[1])["registry"] == url


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


def test_verify_note_rejects_a_wrong_key_origin_or_body():
    body = f"{ORIGIN}\n5\n{base64.b64encode(b'r' * 32).decode()}\n"
    keyid = core.sha256(ORIGIN.encode() + b"\n\x01" + LOG_KEY.public)[:4]
    note = f"{body}\n\u2014 {ORIGIN} {base64.b64encode(keyid + LOG_KEY.private.sign(body.encode())).decode()}\n"
    assert core.verify_note(note, ORIGIN, LOG_KEY.public)
    assert not core.verify_note(note, ORIGIN, KP.public)
    assert not core.verify_note(note, "other/log", LOG_KEY.public)
    assert not core.verify_note(note.replace("\n5\n", "\n6\n"), ORIGIN, LOG_KEY.public)


def test_chain_check_verifies_redaction_signatures():
    e1 = core.sign_object({"spec": core.SPEC, "type": "RecordEntry", "eid": KP.did, "seq": 1, "prev": None, "kind": "arc_opened", "payload": {}, "created": core.now_seconds()}, KP)
    h = core.canonical_hash(e1).hex()
    red = core.sign_object({"spec": core.SPEC, "type": "Redaction", "eid": KP.did, "seq": 1, "entry_sha256": h, "created": core.now_seconds()}, KP)
    ph = {"seq": 1, "prev": None, "redacted": True, "hash": h, "redaction": red}
    assert cli._chain_checks([ph], KP.did)[-1]["ok"]
    forged = core.sign_object({k: v for k, v in red.items() if k != "proof"}, core.KeyPair(b"\x05" * 32))
    assert not cli._chain_checks([{**ph, "redaction": forged}], KP.did)[-1]["ok"]
    assert not cli._chain_checks([{**ph, "redaction": {**red, "seq": 2}}], KP.did)[-1]["ok"]
    assert not cli._chain_checks([{**ph, "hash": "zz"}], KP.did)[-1]["ok"]
