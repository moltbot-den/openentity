import { describe, expect, it } from "vitest";
import { base58btcDecode, canonicalize, leafHash, merkleRoot, nowSeconds, recordEntryHash, signObject, verifyConsistency, verifyInclusion, verifyNote, type KeyPair } from "../src/sdk.ts";
import { hex, unhex } from "../src/env.ts";
import { incorporate } from "../src/log.ts";
import { app, scheduled } from "../src/index.ts";
import { E, adopted, call, write } from "./helpers.ts";

const enc = new TextEncoder();
async function records(kp: KeyPair, from: number, n: number, prev: string | null) {
  const out = [];
  for (let seq = from; seq < from + n; seq++) {
    const e = await signObject({ spec: "openentity/1.0", type: "RecordEntry", eid: kp.did, seq, prev, kind: "belief_update", at: nowSeconds(), payload: { topic: "t", from_summary: "a", to_summary: "b" } }, kp);
    prev = await recordEntryHash(e);
    out.push(e);
  }
  return { entries: out, prev };
}
const raw = async (path: string) => new Uint8Array(await (await app.request(`https://openentity.org/v1${path}`, {}, E)).arrayBuffer());

describe("transparency log (spec 10.3)", () => {
  it("signs a checkpoint, and every leaf's inclusion proof verifies against it", async () => {
    const a = await adopted(), b = await adopted();
    await incorporate(E);
    const firstSize = (await call("GET", "/log/sth")).body.tree_size;
    let prev: string | null = null;
    for (let i = 0; i < 3; i++) {
      const batch = await records(a.kp, 1 + 100 * i, 100, prev);
      prev = batch.prev;
      expect((await write("POST", `/entities/${a.kp.did}/record`, a.kp.did, { entries: batch.entries })).status).toBe(201);
    }
    expect(b.res.log_index).toBeGreaterThan(a.res.log_index);
    await incorporate(E);

    const spec = (await call("GET", "/spec")).body;
    expect(spec.registry).toMatchObject({ did: "did:web:openentity.org", log_origin: "openentity.org/log" });
    expect(spec.registry.note_key).toMatch(/^openentity\.org\/log\+[0-9a-f]{8}\+/);
    const pk = base58btcDecode(spec.registry.publicKeyMultibase.slice(1)).slice(2);
    const note = (await call("GET", "/log/checkpoint")).text;
    expect(await verifyNote(note, "openentity.org/log", pk)).toBe(true);
    const [origin, sizeLine, rootB64] = note.split("\n");
    expect(origin).toBe("openentity.org/log");
    const size = Number(sizeLine), root = Uint8Array.from(atob(rootB64), (ch) => ch.charCodeAt(0));
    expect(size).toBeGreaterThanOrEqual(304);
    const sth = (await call("GET", "/log/sth")).body;
    expect(sth).toMatchObject({ tree_size: size, root_hash: hex(root), signature: note });

    const hashes: Uint8Array[] = [];
    for (let start = 0; start < size; start += 1000) {
      for (const e of (await call("GET", `/log/entries?start=${start}&end=${Math.min(size, start + 1000)}`)).body.entries) {
        expect(e.leaf_hash).toBe(hex(await leafHash(enc.encode(canonicalize(e.leaf)))));
        expect(Object.keys(e.leaf).sort()).toEqual(["eid", "object_sha256", "received_at", "type"]);
        hashes.push(unhex(e.leaf_hash));
      }
    }
    expect(hashes).toHaveLength(size);
    expect(hex(await merkleRoot(hashes))).toBe(hex(root));
    for (let i = 0; i < size; i++) {
      const p = (await call("GET", `/log/proof/${i}?tree_size=${size}`)).body;
      expect(p.root_hash).toBe(hex(root));
      expect(await verifyInclusion(i, size, unhex(p.leaf_hash), p.proof.map(unhex), root)).toBe(true);
    }

    const c = (await call("GET", `/log/consistency?first=${firstSize}&second=${size}`)).body;
    const firstRoot = unhex((await E.DB.prepare("SELECT root_hash FROM checkpoints WHERE tree_size = ?").bind(firstSize).first<string>("root_hash"))!);
    expect(await verifyConsistency(firstSize, size, firstRoot, root, c.proof.map(unhex))).toBe(true);

    // Tiles, read the way a tlog-tiles client reads them.
    const tile0 = await raw("/log/tile/0/000");
    expect(tile0.length).toBe(256 * 32);
    expect(hex(tile0.slice(0, 32))).toBe(hex(hashes[0]));
    const w = size - 256;
    const partial = await raw(`/log/tile/0/001.p/${w}`);
    expect(hex(partial)).toBe(hashes.slice(256).map(hex).join(""));
    const level1 = await raw("/log/tile/1/000.p/1");
    expect(hex(level1)).toBe(hex(await merkleRoot(hashes.slice(0, 256))));
    const bundle = await raw("/log/tile/entries/000");
    const len = (bundle[0] << 8) | bundle[1];
    expect(hex(await leafHash(bundle.slice(2, 2 + len)))).toBe(hex(hashes[0]));
  });

  it("returns 404 for a proof of a leaf not yet incorporated", async () => {
    const r = await call("GET", "/log/proof/999999");
    expect(r.status).toBe(404);
  });

  it("the scheduled handler incorporates, records daily stats and writes a snapshot", async () => {
    await adopted();
    await scheduled(E);
    const csv = (await call("GET", "/stats/history.csv")).text;
    expect(csv.split("\n")[0]).toBe("date,entities_l0,entities_l1,entities_l2,entities_l3,adoptions,record_entries,attestations,observers");
    expect(csv.split("\n").length).toBeGreaterThanOrEqual(3);
    const yesterday = new Date(Date.now() - 86400_000).toISOString().slice(0, 10);
    const snap = (await call("GET", `/log/snapshots/${yesterday}.jsonl`)).text.trim().split("\n");
    expect(JSON.parse(snap[snap.length - 1]).checkpoint.tree_size).toBeGreaterThan(0);
    const stats = (await call("GET", "/stats")).body;
    expect(stats.entities.l0).toBeGreaterThanOrEqual(1);
    expect(stats.log.tree_size).toBe((await call("GET", "/log/sth")).body.tree_size);
  });
});
