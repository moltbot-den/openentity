"""Runs scripts/independent_verifier.py against a stub registry built with this SDK."""
import base64
import importlib.util
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

from openentity import client, core

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location("iv", ROOT / "scripts/independent_verifier.py")
iv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(iv)
spec = importlib.util.spec_from_file_location("rc", ROOT / "scripts/rebuild_check.py")
rc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rc)
ORIGIN = "openentity.org/log"


def _registry(n=37, tamper_root=False, tamper_object=False, seed=b"\7" * 32):
    reg = core.KeyPair(seed)
    ents, leaves = {}, []
    for i in range(n):
        kp = core.KeyPair(bytes([i + 1]) * 32)
        doc, decl = client.build_adoption(kp, f"E{i}", "d", "http://x")
        if tamper_object and i % 5 == 0:
            doc["name"] = "forged"
        ents[kp.did] = {"document": doc, "declaration": decl}
        leaves.append(core.log_leaf("Declaration", kp.did, core.canonical_hash(decl).hex(), core.now()))
    hashes = [core.leaf_hash(core.canonicalize(lf).encode()) for lf in leaves]
    root = b"\0" * 32 if tamper_root else core.merkle_root(hashes)
    body = f"{ORIGIN}\n{n}\n{base64.b64encode(root).decode()}\n"
    keyid = core.sha256(ORIGIN.encode() + b"\n\x01" + reg.public)[:4]
    sig = base64.b64encode(keyid + reg.private.sign(body.encode())).decode()
    notekey = f"{ORIGIN}+{keyid.hex()}+" + base64.b64encode(b"\x01" + reg.public).decode()
    entries = [{"index": i, "leaf": lf, "leaf_hash": hashes[i].hex()} for i, lf in enumerate(leaves)]
    note = f"{body}\n\u2014 {ORIGIN} {sig}\n"

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            u = urlparse(self.path)
            q = {k: v[0] for k, v in parse_qs(u.query).items()}
            parts = u.path.split("/")
            if u.path.endswith("/checkpoint"):
                out = note.encode()
            elif u.path.endswith("/spec"):
                out = json.dumps({"stamp_bits": 8, "registry": {"note_key": notekey}}).encode()
            elif u.path.endswith("/log/entries"):
                s = int(q["start"])
                out = json.dumps({"entries": entries[s:int(q["end"])]}).encode()
            elif "/log/proof/" in u.path:
                out = json.dumps({"proof": [h.hex() for h in core.inclusion_proof(int(parts[-1]), hashes)]}).encode()
            else:
                out = json.dumps(ents[parts[-1]]).encode()
            self.send_response(200)
            self.send_header("content-length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _run(monkeypatch, capsys, **kw):
    srv = _registry(**kw)
    try:
        monkeypatch.setattr("sys.argv", ["iv", f"http://127.0.0.1:{srv.server_port}"])
        return iv.main(), capsys.readouterr().out
    finally:
        srv.shutdown()


def test_verifier_passes_honest_registry(monkeypatch, capsys):
    code, out = _run(monkeypatch, capsys)
    assert code == 0 and "inclusion proofs checked: 37" in out and "RESULT: PASS" in out


def test_verifier_reads_a_registry_key_whose_base64_contains_plus(monkeypatch, capsys):
    # note_key is origin+keyid+base64(key); the base64 may hold "+", so only the first two "+" separate the parts.
    seed = next(bytes([i]) * 32 for i in range(1, 255) if "+" in base64.b64encode(b"\x01" + core.KeyPair(bytes([i]) * 32).public).decode())
    code, out = _run(monkeypatch, capsys, n=3, seed=seed)
    assert code == 0 and "RESULT: PASS" in out


def test_verifier_catches_bad_root(monkeypatch, capsys):
    code, out = _run(monkeypatch, capsys, tamper_root=True)
    assert code == 1 and "RESULT: FAIL" in out


def test_verifier_catches_forged_objects(monkeypatch, capsys):
    code, out = _run(monkeypatch, capsys, tamper_object=True)
    assert code == 1 and "InvalidSignature" in out


def test_verifier_jcs_and_sig_agree_with_sdk():
    kp = core.KeyPair(b"\3" * 32)
    obj = core.sign_object({"a": [1.5, 1e21, "é"], "b": {"z": 1, "a": 2}}, kp)
    assert iv.jcs(obj) == core.canonicalize(obj)
    iv.verify_sig(obj)
    with pytest.raises(Exception):
        iv.verify_sig({**obj, "a": []})


def test_vector_format(tmp_path):
    kp = core.KeyPair(b"\3" * 32)
    obj = core.sign_object({"a": 1.5, "b": "x"}, kp, "2026-10-24T19:00:00Z")
    vec = {"description": "d", "object": obj, "canonical": core.canonicalize(obj),
           "sha256": core.canonical_hash(obj).hex(),
           "unsigned_canonical": core.canonicalize({k: v for k, v in obj.items() if k != "proof"})}
    (tmp_path / "keys.json").write_text(json.dumps({"seed_hex": "00"}))
    (tmp_path / "v.json").write_text(json.dumps(vec))
    assert iv.check_vectors(str(tmp_path)) == 0
    (tmp_path / "v.json").write_text(json.dumps({**vec, "sha256": "0" * 64}))
    assert iv.check_vectors(str(tmp_path)) == 1


def _bucket(tmp_path, n=5, tamper=False):
    kps = [core.KeyPair(bytes([i + 1]) * 32) for i in range(n)]
    leaves = [core.log_leaf("Declaration", k.did, "ab" * 32, "2026-10-25T00:00:00Z") for k in kps]
    hs = [core.leaf_hash(core.canonicalize(lf).encode()) for lf in leaves]
    root = core.merkle_root(hs)
    (tmp_path / "snapshots").mkdir(); (tmp_path / "tile/0/000.p").mkdir(parents=True); (tmp_path / "tile/entries/000.p").mkdir(parents=True)
    rows = [json.dumps({"index": i, "leaf": lf, "leaf_hash": hs[i].hex()}) for i, lf in enumerate(leaves)]
    cp = json.dumps({"checkpoint": {"tree_size": n, "root_hash": root.hex()}})
    (tmp_path / "snapshots/2026-10-25.jsonl").write_text("\n".join(rows + [cp]) + "\n")
    (tmp_path / f"tile/0/000.p/{n}").write_bytes(b"".join(hs))
    ent = b"".join(len(b).to_bytes(2, "big") + b for b in (core.canonicalize(lf).encode() for lf in leaves))
    (tmp_path / f"tile/entries/000.p/{n}").write_bytes(ent[:-1] + b"x" if tamper else ent)
    return n, root


def test_rebuild_matches_checkpoint(tmp_path):
    n, root = _bucket(tmp_path)
    ok, lines = rc.rebuild(tmp_path, (n, root))
    assert ok, lines
    assert rc.tile_path(1234067) == "x001/x234/067"


def test_rebuild_catches_wrong_root_missing_leaf_and_bad_tile(tmp_path):
    n, root = _bucket(tmp_path)
    assert not rc.rebuild(tmp_path, (n, b"\0" * 32))[0]
    assert not rc.rebuild(tmp_path, (n + 1, root))[0]
    t = tmp_path / "t"; t.mkdir()
    n, root = _bucket(t, tamper=True)
    assert not rc.rebuild(t, (n, root))[0]


def test_rebuild_checks_objects_against_leaves(tmp_path):
    n, root = _bucket(tmp_path)
    obj = {"type": "Declaration", "eid": "did:key:z1", "n": 1}
    sha = core.canonical_hash(obj).hex()
    leaf = core.log_leaf("Declaration", "did:key:z1", sha, "2026-10-25T00:00:00Z")
    # replace leaf 0 of the bucket with one that commits to obj
    snap = tmp_path / "snapshots/2026-10-25.jsonl"; rows = snap.read_text().splitlines()
    leaves = [json.loads(r)["leaf"] for r in rows[:-1]]; leaves[0] = leaf
    hs = [core.leaf_hash(core.canonicalize(lf).encode()) for lf in leaves]; root = core.merkle_root(hs)
    snap.write_text("\n".join([json.dumps({"index": i, "leaf": lf, "leaf_hash": hs[i].hex()}) for i, lf in enumerate(leaves)]
                              + [json.dumps({"checkpoint": {"tree_size": n, "root_hash": root.hex()}})]) + "\n")
    (tmp_path / "tile/0/000.p" / str(n)).write_bytes(b"".join(hs))
    (tmp_path / "tile/entries/000.p" / str(n)).write_bytes(b"".join(len(b).to_bytes(2, "big") + b for b in (core.canonicalize(lf).encode() for lf in leaves)))
    (tmp_path / "objects").mkdir()
    line = {"idx": 0, "type": "Declaration", "eid": "did:key:z1", "object_sha256": sha, "object": obj}
    (tmp_path / "objects/2026-10-25.jsonl").write_text(json.dumps(line) + "\n")
    ok, lines = rc.rebuild(tmp_path, (n, root))
    assert ok and any("objects: 1 of" in x for x in lines), lines
    (tmp_path / "objects/2026-10-25.jsonl").write_text(json.dumps({**line, "object": {**obj, "n": 2}}) + "\n")
    assert not rc.rebuild(tmp_path, (n, root))[0]
    red = {"seq": 2, "redacted": True, "hash": sha, "redaction": {}}
    (tmp_path / "objects/2026-10-25.jsonl").write_text(json.dumps({**line, "object": red}) + "\n")
    assert rc.rebuild(tmp_path, (n, root))[0]

