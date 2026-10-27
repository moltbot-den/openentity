#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = ["cryptography"]
# ///
"""Open Entity independent verifier. Read-only. Written from spec/OEIS-1.md; shares no code with any SDK.
  uv run scripts/independent_verifier.py https://openentity.org [--samples 100]
  uv run scripts/independent_verifier.py --vectors test-vectors
  uv run scripts/independent_verifier.py https://openentity.org --rebuild DIR
--rebuild DIR: DIR is a copy of the log bucket (snapshots/*.jsonl, tile/...); rebuilds the leaves from the snapshots,
cross-checks the tiles, and compares the Merkle root with the live signed checkpoint. Exit 1 on any mismatch.
Checks the signed checkpoint (C2SP note, key from /v1/spec), N random RFC 6962 inclusion proofs and N random
object signatures (eddsa-jcs-2022, did:key). Prints a report, exits 1 on any failure."""
import argparse, base64, hashlib, json, random, sys, urllib.request
from decimal import Decimal
from pathlib import Path
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
H = lambda b: hashlib.sha256(b.encode() if isinstance(b, str) else b).digest()
ED = lambda pub: Ed25519PublicKey.from_public_bytes(pub)

def b58d(s):
    n = 0
    for c in s: n = n * 58 + B58.index(c)
    return b"\0" * (len(s) - len(s.lstrip("1"))) + n.to_bytes((n.bit_length() + 7) // 8, "big")

def num(x):  # RFC 8785 numbers (ECMAScript Number::toString)
    if isinstance(x, int) or x == 0: return str(int(x))
    t = Decimal(repr(abs(x))).normalize().as_tuple()
    s = "".join(map(str, t.digits)); k, n = len(s), len(s) + t.exponent
    r = (s + "0" * (n - k) if k <= n <= 21 else s[:n] + "." + s[n:] if 0 < n <= 21 else "0." + "0" * -n + s if -6 < n <= 0
         else (s if k == 1 else s[0] + "." + s[1:]) + f"e{'-' if n < 1 else '+'}{abs(n - 1)}")
    return ("-" if x < 0 else "") + r

def jcs(v):
    if isinstance(v, bool) or v is None: return json.dumps(v)
    if isinstance(v, (int, float)): return num(v)
    if isinstance(v, str): return json.dumps(v, ensure_ascii=False)
    if isinstance(v, list): return "[" + ",".join(map(jcs, v)) + "]"
    return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + jcs(v[k]) for k in sorted(v, key=lambda k: k.encode("utf-16-be"))) + "}"

def verify_sig(obj, p=None):
    """eddsa-jcs-2022: signature over sha256(jcs(proof minus proofValue)) || sha256(jcs(object minus proof/proofs))."""
    p = p or obj["proof"]; did = p["verificationMethod"].split("#")[0]
    raw = b58d(did.removeprefix("did:key:z"))
    if not did.startswith("did:key:z") or raw[:2] != b"\xed\x01": raise ValueError(f"cannot resolve {did[:24]}")
    cfg = {k: v for k, v in p.items() if k != "proofValue"}
    ED(raw[2:]).verify(b58d(p["proofValue"][1:]), H(jcs(cfg)) + H(jcs(unsigned(obj))))

def unsigned(o): return {k: v for k, v in o.items() if k not in ("proof", "proofs")}  # ContinuityLink carries proofs[]

def verify_inclusion(i, size, leaf, proof, root):  # RFC 9162 2.1.3.2
    fn, sn, r = i, size - 1, leaf
    if i >= size: return False
    for p in proof:
        if sn == 0: return False
        if fn & 1 or fn == sn:
            r = H(b"\x01" + p + r)
            while not fn & 1 and fn: fn, sn = fn >> 1, sn >> 1
        else: r = H(b"\x01" + r + p)
        fn, sn = fn >> 1, sn >> 1
    return sn == 0 and r == root

def get(url):
    with urllib.request.urlopen(urllib.request.Request(url, headers={"user-agent": "oe-independent-verifier"}), timeout=30) as r:
        return json.loads(r.read()) if url.split("?")[0].split("/")[-1] != "checkpoint" else r.read().decode()

def check_checkpoint(note, pub):  # body "origin\nsize\nbase64(root)\n", blank line, "<em dash> name base64(keyid||sig)"
    body, _, sigs = note.partition("\n\n")
    origin, size, root = body.split("\n")[:3]
    keyid = H(origin.encode() + b"\n\x01" + pub)[:4]
    for line in sigs.splitlines():
        parts = line.split(" ")
        if len(parts) == 3 and parts[1] == origin and (raw := base64.b64decode(parts[2]))[:4] == keyid:
            ED(pub).verify(raw[4:], (body + "\n").encode())
            return origin, int(size), base64.b64decode(root)
    raise ValueError("no signature by the registry key")

def check_vectors(d):
    """test-vectors/*.json: {object, canonical, sha256, unsigned_canonical}; keys.json has no object and is skipped."""
    res = []
    for f in sorted(Path(d).glob("*.json")):
        v = json.loads(f.read_text())
        if "request" in v:  # rotation: POST /v1/continuity body; link signed by previous and successor, document by the successor
            l, doc = v["request"]["link"], v["request"]["document"]
            try:
                signers = []
                for p in l["proofs"]: verify_sig(l, p); signers.append(p["verificationMethod"].split("#")[0])
                verify_sig(doc)
                good = signers == [l["previous"], l["successor"]] and doc["eid"] == l["successor"] and doc["seq"] == 1 and doc["continuity"]["previous"] == l["previous"]
            except (InvalidSignature, ValueError, KeyError): good = False
            res.append((f.name, "rotation", good)); continue
        if "object" not in v: continue
        o = v["object"]; c = jcs(o)
        res += [(f.name, "canonical", v["canonical"] == c), (f.name, "sha256", v["sha256"] == H(c).hex()),
                (f.name, "unsigned_canonical", v["unsigned_canonical"] == jcs(unsigned(o)))]
        if "proof" not in o and "proofs" not in o: continue  # log leaves are unsigned by design
        try: [verify_sig(o, p) for p in o.get("proofs") or [o["proof"]]]; res.append((f.name, "proof", True))
        except (InvalidSignature, ValueError, KeyError): res.append((f.name, "proof", False))
    for r in res: print("ok  " if r[2] else "FAIL", r[0], r[1])
    bad = sum(not r[2] for r in res); print(f"vectors: {len(res)} checks, {bad} failed")
    return 1 if bad or not res else 0

def mth(hs):  # RFC 6962 Merkle tree hash over leaf hashes
    if not hs: return H(b"")
    if len(hs) == 1: return hs[0]
    k = 1 << (len(hs) - 1).bit_length() - 1
    return H(b"\x01" + mth(hs[:k]) + mth(hs[k:]))

def tile_path(n):  # C2SP: 1234067 -> x001/x234/067
    s = str(n); s = s.rjust(-(-len(s) // 3) * 3, "0"); g = [s[i:i + 3] for i in range(0, len(s), 3)]
    return "/".join(("x" if i < len(g) - 1 else "") + x for i, x in enumerate(g))

def rebuild(d, checkpoint):
    """Leaves from d/snapshots/*.jsonl, tiles from d/tile; returns (ok, report lines). checkpoint = (size, root)."""
    d, out, leaves, snaps = Path(d), [], {}, []
    for f in sorted((d / "snapshots").glob("*.jsonl")):
        for line in filter(None, f.read_text().splitlines()):  # snapshots of leafless days start with a blank line
            r = json.loads(line)
            if "checkpoint" in r: snaps.append((f.name, r["checkpoint"])); continue
            if leaves.setdefault(r["index"], r) != r: return False, [f"FAIL {f.name}: leaf {r['index']} differs between snapshots"]
    size, root = checkpoint; hs = []
    for i in range(size):
        r = leaves.get(i)
        if not r: return False, out + [f"FAIL leaf {i} is in no snapshot (leaves found: {len(leaves)})"]
        h = H(b"\x00" + jcs(r["leaf"]).encode())
        if h.hex() != r["leaf_hash"]: return False, out + [f"FAIL leaf {i}: leaf_hash does not match its leaf"]
        hs.append(h)
    ok = True
    for name, cp in snaps:  # each snapshot embeds the checkpoint current when it was taken
        n = cp["tree_size"]; good = n <= size and mth(hs[:n]).hex() == cp["root_hash"]; ok &= good
        out.append(f"{'ok  ' if good else 'FAIL'} snapshot {name}: size {n}, rebuilt root {mth(hs[:n]).hex() if n <= size else '?'}, recorded {cp['root_hash']}")
    for kind, want in (("tile/0", lambda i: hs[i]), ("tile/entries", None)):  # the newest partial or full tile of each kind
        for N in range(-(-size // 256)):
            n = min(256, size - 256 * N); p = d / kind / (tile_path(N) + (f".p/{n}" if n < 256 else ""))
            if not p.exists(): out.append(f"skip {kind}/{p.name}: not in the copy"); continue
            b, good = p.read_bytes(), True
            if want: good = b == b"".join(want(256 * N + j) for j in range(n))
            else:
                o, got = 0, []
                while o < len(b): l = int.from_bytes(b[o:o + 2], "big"); got.append(b[o + 2:o + 2 + l]); o += 2 + l
                good = got == [jcs(leaves[256 * N + j]["leaf"]).encode() for j in range(n)]
            ok &= good; out.append(f"{'ok  ' if good else 'FAIL'} {kind}/{p.relative_to(d / kind)}: {n} entries")
    got = mth(hs)
    out.append(f"{'ok  ' if got == root else 'FAIL'} live checkpoint: size {size}, rebuilt root {got.hex()}, signed root {root.hex()}")
    return ok and got == root, out

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("registry", nargs="?"); ap.add_argument("--samples", type=int, default=100)
    ap.add_argument("--vectors"); ap.add_argument("--rebuild"); a = ap.parse_args()
    if a.vectors: return check_vectors(a.vectors)
    base, fails, inc, sig, skipped = a.registry.rstrip("/") + "/v1", [], 0, 0, 0
    origin, size, root = check_checkpoint(get(base + "/log/checkpoint"), base64.b64decode(get(base + "/spec")["registry"]["note_key"].split("+")[2])[1:])
    print(f"checkpoint: signature ok, origin {origin}, size {size}")
    if a.rebuild:
        ok, lines = rebuild(a.rebuild, (size, root)); print(*lines, f"RESULT: {'PASS' if ok else 'FAIL'}", sep="\n")
        return 0 if ok else 1
    for i in sorted(random.sample(range(size), min(a.samples, size))):
        try:
            e = get(f"{base}/log/entries?start={i}&end={i + 1}")["entries"][0]; leaf = e["leaf"]
            if e["index"] != i or e["leaf_hash"] != H(b"\x00" + jcs(leaf).encode()).hex(): fails.append(f"entry {i}: index or leaf_hash wrong")
            hashes = [bytes.fromhex(x) for x in get(f"{base}/log/proof/{i}?tree_size={size}")["proof"]]
            if not verify_inclusion(i, size, H(b"\x00" + jcs(leaf).encode()), hashes, root): fails.append(f"inclusion {i}: root mismatch")
            inc += 1
            if leaf["eid"].startswith("did:key:") and leaf["type"] in ("EntityDocument", "Declaration"):
                ent = get(f"{base}/entities/{leaf['eid']}")
                for o in (ent.get("document"), ent.get("declaration")):
                    if o and "proof" in o: verify_sig(o); sig += 1
            else: skipped += 1
        except Exception as ex: fails.append(f"sample {i}: {type(ex).__name__}: {ex}")
    print(f"inclusion proofs checked: {inc}\nobject signatures verified: {sig} (samples with no did:key object: {skipped})")
    print(*("FAIL " + f for f in fails), f"RESULT: {'FAIL' if fails else 'PASS'}", sep="\n")
    return 1 if fails else 0

if __name__ == "__main__":
    sys.exit(main())
