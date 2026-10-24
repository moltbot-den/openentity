#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = ["cryptography"]
# ///
"""Open Entity independent verifier. Read-only. Written from spec/OEIS-1.md; shares no code with any SDK.
  uv run scripts/independent_verifier.py https://openentity.org [--samples 100]
  uv run scripts/independent_verifier.py --vectors test-vectors
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

def verify_sig(obj):
    """eddsa-jcs-2022: signature over sha256(jcs(proof minus proofValue)) || sha256(jcs(object minus proof))."""
    p = obj["proof"]; did = p["verificationMethod"].split("#")[0]
    raw = b58d(did.removeprefix("did:key:z"))
    if not did.startswith("did:key:z") or raw[:2] != b"\xed\x01": raise ValueError(f"cannot resolve {did[:24]}")
    cfg = {k: v for k, v in p.items() if k != "proofValue"}
    ED(raw[2:]).verify(b58d(p["proofValue"][1:]), H(jcs(cfg)) + H(jcs({k: v for k, v in obj.items() if k != "proof"})))

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
        if "object" not in v: continue
        o = v["object"]; c = jcs(o)
        res += [(f.name, "canonical", v["canonical"] == c), (f.name, "sha256", v["sha256"] == H(c).hex()),
                (f.name, "unsigned_canonical", v["unsigned_canonical"] == jcs({k: x for k, x in o.items() if k != "proof"}))]
        try: verify_sig(o); res.append((f.name, "proof", True))
        except (InvalidSignature, ValueError, KeyError): res.append((f.name, "proof", False))
    for r in res: print("ok  " if r[2] else "FAIL", r[0], r[1])
    bad = sum(not r[2] for r in res); print(f"vectors: {len(res)} checks, {bad} failed")
    return 1 if bad or not res else 0

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("registry", nargs="?"); ap.add_argument("--samples", type=int, default=100)
    ap.add_argument("--vectors"); a = ap.parse_args()
    if a.vectors: return check_vectors(a.vectors)
    base, fails, inc, sig, skipped = a.registry.rstrip("/") + "/v1", [], 0, 0, 0
    origin, size, root = check_checkpoint(get(base + "/log/checkpoint"), base64.b64decode(get(base + "/spec")["registry"]["note_key"].split("+")[2])[1:])
    print(f"checkpoint: signature ok, origin {origin}, size {size}")
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
