#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = ["cryptography"]
# ///
"""Disaster-recovery check (docs/DR-RUNBOOK.md). Read-only. Reuses the canonicalization and checkpoint code of independent_verifier.py.
  uv run scripts/rebuild_check.py https://openentity.org DIR
DIR is a copy of the log bucket (snapshots/*.jsonl, tile/..., objects/*.jsonl); rebuilds the leaves from the snapshots,
cross-checks the tiles and any objects against the leaves, and compares the Merkle root with the live signed checkpoint. Exit 1 on any mismatch."""
import base64, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from independent_verifier import H, jcs, get, check_checkpoint

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
    seen, bad = set(), 0  # objects/<date>.jsonl: each line must be its leaf's object (a redacted entry is its placeholder)
    for f in sorted((d / "objects").glob("*.jsonl")):
        for line in filter(None, f.read_text().splitlines()):
            x = json.loads(line); lf = leaves.get(x["idx"], {}).get("leaf", {}); o = x["object"]
            good = (lf.get("type"), lf.get("eid"), lf.get("object_sha256")) == (x["type"], x["eid"], x["object_sha256"]) and \
                (o["hash"] if o.get("redacted") else H(jcs(o)).hex()) == x["object_sha256"]
            if good: seen.add(x["idx"])
            else: bad += 1; out.append(f"FAIL {f.name}: object of leaf {x['idx']} does not match its leaf")
    if seen or bad: out.append(f"{'ok  ' if not bad else 'FAIL'} objects: {len(seen)} of {size} leaves have a matching object")
    ok &= not bad
    got = mth(hs)
    out.append(f"{'ok  ' if got == root else 'FAIL'} live checkpoint: size {size}, rebuilt root {got.hex()}, signed root {root.hex()}")
    return ok and got == root, out

def main():
    base = sys.argv[1].rstrip("/") + "/v1"
    origin, size, root = check_checkpoint(get(base + "/log/checkpoint"), base64.b64decode(get(base + "/spec")["registry"]["note_key"].split("+")[2])[1:])
    print(f"checkpoint: signature ok, origin {origin}, size {size}")
    ok, lines = rebuild(sys.argv[2], (size, root)); print(*lines, f"RESULT: {'PASS' if ok else 'FAIL'}", sep="\n")
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())
