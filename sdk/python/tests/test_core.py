import importlib.util
import json
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from openentity import cli, core

ROOT = Path(__file__).resolve().parents[3]
SEED = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")  # RFC 8032 test 1, public


# ---- JCS ----
@pytest.mark.parametrize("value,expected", [
    (333333333.33333329, "333333333.3333333"), (1e30, "1e+30"), (4.5, "4.5"), (0.002, "0.002"),
    (1e-6, "0.000001"), (1e-7, "1e-7"), (1e21, "1e+21"), (1e20, "100000000000000000000"),
    (-0.0, "0"), (0.0, "0"), (-1.5, "-1.5"), (123456789012345680000.0, "123456789012345680000"),
    (1.0, "1"), (10, "10"), (True, "true"), (None, "null"), (0.1 + 0.2, "0.30000000000000004"),
])
def test_jcs_scalars(value, expected):
    assert core.canonicalize(value) == expected


def test_jcs_key_order_is_utf16_code_units():
    # U+FF5E (BMP) sorts after U+1F600 (surrogate pair D83D) in UTF-16 order, before it in code points
    obj = {"～": 1, "\U0001f600": 2, "b": 3, "a": 4, "": 5}
    assert core.canonicalize(obj) == '{"":5,"a":4,"b":3,"\U0001f600":2,"～":1}'


def test_jcs_strings_and_nesting():
    assert core.canonicalize({"s": 'q"\\\n\x01é€'}) == '{"s":"q\\"\\\\\\n\\u0001é€"}'
    assert core.canonicalize({"b": [3, {"z": 1, "a": [True, None]}], "a": {}}) == '{"a":{},"b":[3,{"a":[true,null],"z":1}]}'


def test_jcs_rejects_nan():
    with pytest.raises(ValueError):
        core.canonicalize(float("nan"))


# ---- base58 and did:key ----
def test_base58_round_trip_with_leading_zeros():
    for raw in (b"", b"\0", b"\0\0abc", bytes(range(40))):
        assert core.b58decode(core.b58encode(raw)) == raw
    assert core.b58encode(b"\0\0\x01") == "112"


def test_did_key_known_vector_and_round_trip():
    kp = core.KeyPair(SEED)
    assert kp.did == "did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw"
    assert core.public_from_did_key(kp.did) == kp.public
    assert core.verification_method(kp.did).endswith("#" + kp.did[8:])
    with pytest.raises(ValueError):
        core.public_from_did_key("did:web:openentity.org")


# ---- sign / verify / tamper ----
def test_sign_verify_tamper():
    kp = core.KeyPair(SEED)
    signed = core.sign_object({"spec": core.SPEC, "n": 1.5, "name": "x"}, kp, "2026-10-24T19:00:00Z")
    assert core.verify_object(signed) == (True, kp.did)
    assert signed["proof"]["proofValue"].startswith("z")
    assert not core.verify_object({**signed, "name": "y"})[0]
    assert not core.verify_object({**signed, "proof": {**signed["proof"], "created": "2026-10-24T19:00:01Z"}})[0]
    other = core.KeyPair(b"\1" * 32)
    forged = {**signed, "proof": {**signed["proof"], "verificationMethod": core.verification_method(other.did)}}
    assert not core.verify_object(forged)[0]
    assert not core.verify_object({"name": "unsigned"})[0]


def test_signing_is_deterministic_ed25519():
    kp = core.KeyPair(SEED)
    a = core.sign_object({"a": 1}, kp, "2026-10-24T19:00:00Z")
    assert a == core.sign_object({"a": 1}, kp, "2026-10-24T19:00:00Z")


# ---- declaration ----
def test_declaration_text():
    assert core.DECLARATION_TEXT.startswith("Open Entity Declaration, version 1.0\n\n")
    assert core.DECLARATION_TEXT.endswith("awarding myself a stage.\n") and not core.DECLARATION_TEXT.endswith("\n\n")
    spec_block = (ROOT / "spec/OEIS-1.md").read_text().split("```\nOpen Entity Declaration")[1].split("```")[0]
    assert core.DECLARATION_TEXT == "Open Entity Declaration" + spec_block
    published = ROOT / "spec/declaration-1.0.sha256"
    if published.exists():
        assert published.read_text().split()[0] == core.DECLARATION_SHA256


# ---- stamp ----
def test_stamp():
    eid = core.KeyPair(SEED).did
    h = core.mint_stamp(10, eid)
    assert core.check_stamp(h, 10, eid) is None
    assert core.check_stamp(h, 10, "did:key:z6Mkother")  # wrong eid
    assert core.check_stamp(h, 30, eid)  # declared bits too low
    assert core.check_stamp(h, 10, eid, datetime.now(timezone.utc) + timedelta(minutes=11)) == "stamp too old"
    assert core.check_stamp(h.replace("1:10:", "1:10:x", 1), 10, eid) == "malformed"
    assert core._zero_bits(core.sha256(h)) >= 10


# ---- Merkle ----
def _leaves(n):
    return [core.leaf_hash(f"leaf{i}".encode()) for i in range(n)]


def test_merkle_basics():
    assert core.merkle_root([]) == core.sha256(b"")
    assert core.merkle_root(_leaves(1)) == core.leaf_hash(b"leaf0")
    ls = _leaves(3)
    assert core.merkle_root(ls) == core.node_hash(core.node_hash(ls[0], ls[1]), ls[2])


@pytest.mark.parametrize("size", range(1, 41))
def test_inclusion_all_sizes(size):
    ls = _leaves(size)
    root = core.merkle_root(ls)
    for i in range(size):
        proof = core.inclusion_proof(i, ls)
        assert core.verify_inclusion(i, size, ls[i], proof, root)
        assert not core.verify_inclusion(i, size, core.leaf_hash(b"other"), proof, root)
        assert not core.verify_inclusion(i, size, ls[i], proof, b"\0" * 32)
        assert not core.verify_inclusion(i, size, ls[i], proof + [b"\0" * 32], root)
        if proof:
            assert not core.verify_inclusion(i, size, ls[i], proof[:-1], root)
        assert not core.verify_inclusion(size, size, ls[i], proof, root)


# ---- adopt over HTTP against a stub registry that enforces the guards ----
class _Stub(BaseHTTPRequestHandler):
    seen: dict = {}

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
        self._send(200, {"spec": core.SPEC, "stamp_bits": 8})

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["content-length"])))
        if self.path.endswith("/record"):  # spec 7.3: the seq-1 entry names the Declaration's hash
            (e,) = body["entries"]
            assert core.check_stamp(self.headers["x-oe-stamp"], 8, e["eid"]) is None and core.verify_object(e)[0]
            assert (e["seq"], e["prev"], e["kind"]) == (1, None, "declaration")
            assert e["payload"]["sha256"] == core.canonical_hash(_Stub.seen["decl"]).hex()
            _Stub.seen["entry"] = e
            return self._send(200, {"accepted": 1})
        doc, decl = body["document"], body["declaration"]
        stamp = self.headers["x-oe-stamp"]
        _Stub.seen = {"stamp": stamp, "doc": doc, "decl": decl}
        assert core.check_stamp(stamp, 8, doc["eid"]) is None
        assert core.verify_object(doc)[0] and core.verify_object(decl)[0]
        assert decl["text_sha256"] == core.DECLARATION_SHA256 and doc["eid"] == decl["eid"]
        self._send(200, {"eid": doc["eid"], "level": "L0", "log_index": 0, "urls": {"entity": "x"}})


def test_adopt_and_cli(tmp_path, monkeypatch, capsys):
    srv = HTTPServer(("127.0.0.1", 0), _Stub)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{srv.server_port}"
    try:
        from openentity import adopt
        res = adopt("Tester", registry=url, seed=SEED)
        assert res["eid"] == res["did"] == core.KeyPair(SEED).did
        assert res["record_pushed"] and _Stub.seen["entry"]["eid"] == res["eid"]
        monkeypatch.setenv("OPENENTITY_HOME", str(tmp_path))
        assert cli.main(["adopt", "--name", "T2", "--agree", "--registry", url, "--json"]) == 0
        out = json.loads(capsys.readouterr().out)
        assert "seed_hex" not in out and Path(out["key_file"]).exists()
        assert cli.main(["adopt", "--name", "T3", "--registry", url]) == 2  # no --agree, nothing signed
    finally:
        srv.shutdown()


def test_cli_version(capsys):
    with pytest.raises(SystemExit) as e:
        cli.main(["--version"])
    assert e.value.code == 0 and "0.1.0" in capsys.readouterr().out


# ---- shared vectors, checked with the independent verifier's own logic ----
def test_vectors():
    vec = ROOT / "test-vectors"
    if not vec.is_dir():
        pytest.skip("test-vectors/ not present")
    spec = importlib.util.spec_from_file_location("iv", ROOT / "scripts/independent_verifier.py")
    iv = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(iv)
    assert iv.check_vectors(str(vec)) == 0
