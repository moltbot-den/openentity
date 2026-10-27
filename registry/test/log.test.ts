import { describe, expect, it, vi } from "vitest";
import { base58btcDecode, canonicalize, leafHash, merkleRoot, nowSeconds, recordEntryHash, signObject, verifyConsistency, verifyInclusion, verifyNote, type KeyPair } from "../src/sdk.ts";
import { hex, unhex } from "../src/env.ts";
import { type Stmt, incorporate, leafFor, park, sequence, sequenced } from "../src/log.ts";
import type { Db } from "../src/db.ts";
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
    const firstRoot = unhex((await E.db.first("SELECT root_hash FROM checkpoints WHERE tree_size = $1", [firstSize])).root_hash);
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
  }, 30_000); // 304 leaves plus a proof per leaf on PGlite: about 7 s on a CI runner

  it("keeps log indexes contiguous: concurrent writes and rejected writes leave no hole", async () => {
    const dup = await adopted();
    const results = await Promise.all([
      ...Array.from({ length: 8 }, () => adopted().then((a) => a.res.log_index)),
      write("POST", "/adopt", dup.kp.did, { document: dup.document, declaration: dup.declaration }).then((r) => r.body.error),
    ]);
    expect(results.pop()).toBe("declaration_exists");
    const idx = (await E.db.all<{ idx: number }>("SELECT idx FROM log_leaves ORDER BY idx")).map((r) => r.idx);
    expect(idx).toEqual(idx.map((_, i) => i));
    expect(new Set(results).size).toBe(8);
    expect(await incorporate(E)).toBe(idx.length);
  });

  it("group commit: 50 concurrent adopts get distinct contiguous indexes that match each entity's stored index", async () => {
    await incorporate(E);
    const old = (await E.db.first<{ n: number }>("SELECT count(*) AS n FROM log_leaves"))!.n;
    const rs = await Promise.all(Array.from({ length: 50 }, () => adopted()));
    const firsts = rs.map((a) => a.res.log_index).sort((x, y) => x - y);
    expect(new Set(firsts).size).toBe(50);
    const all = (await E.db.all<{ idx: number }>("SELECT idx FROM log_leaves ORDER BY idx")).map((r) => Number(r.idx));
    expect(all).toEqual(all.map((_, i) => i));
    expect(all.length).toBe(Number(old) + 100); // a Declaration and a document leaf per adopt
    for (const a of rs) {
      const d = await E.db.first<{ log_index: number; idx: number }>("SELECT d.log_index, l.idx FROM declarations d JOIN log_leaves l ON l.object_sha256 = d.sha256 WHERE d.eid = $1", [a.kp.did]);
      expect(Number(d!.log_index)).toBe(a.res.log_index);
      expect(Number(d!.idx)).toBe(a.res.log_index);
      expect((await E.db.first<{ adopted_log_index: number }>("SELECT adopted_log_index FROM entities WHERE eid = $1", [a.kp.did]))!.adopted_log_index).toBe(a.res.log_index);
    }
    expect(await E.db.all("SELECT 1 FROM log_pending")).toEqual([]);
    expect(await E.db.all("SELECT 1 FROM documents WHERE log_index < 0")).toEqual([]);
  }, 30_000);

  it("a write that fails its unique guard leaves nothing pending and no gap", async () => {
    const dup = await adopted();
    const before = (await E.db.first<{ n: number }>("SELECT next AS n FROM log_head"))!.n;
    const r = await write("POST", "/adopt", dup.kp.did, { document: dup.document, declaration: dup.declaration });
    expect(r.body.error).toBe("declaration_exists");
    expect(await E.db.all("SELECT 1 FROM log_pending")).toEqual([]);
    expect((await E.db.first<{ n: number }>("SELECT next AS n FROM log_head"))!.n).toBe(before);
    expect((await E.db.first<{ n: number }>("SELECT count(*) AS n FROM log_leaves"))!.n).toEqual(before);
  });

  it("leaves parked by an interrupted write are sequenced by the cron path", async () => {
    await incorporate(E);
    const size = (await E.db.first<{ n: number }>("SELECT count(*) AS n FROM log_leaves"))!.n;
    const l = await leafFor("Alias", "did:key:zInterrupted", "ab".repeat(32), "2026-01-01T00:00:00Z");
    await park(E.db, [l], [["INSERT INTO disputes (sha256, issuer, subject, object_sha256, reason, json, received_at, log_index) VALUES ('crash', 'i', 's', NULL, 'r', '{}', 'now', $i)", []]]);
    expect(await E.db.all("SELECT 1 FROM log_pending")).toHaveLength(1);
    expect(Number((await E.db.first<{ log_index: number }>("SELECT log_index FROM disputes WHERE sha256 = 'crash'"))!.log_index)).toBeLessThan(0);
    expect(await incorporate(E)).toBe(Number(size) + 1);
    expect(await E.db.all("SELECT 1 FROM log_pending")).toEqual([]);
    expect(Number((await E.db.first<{ log_index: number }>("SELECT log_index FROM disputes WHERE sha256 = 'crash'"))!.log_index)).toBe(Number(size));
  });

  // PGlite has one connection, so SKIP LOCKED never skips here. `busy` stands in for a sequencer statement that
  // found log_head locked by another one: it moves nothing and finds no index for its write ({ i: null }).
  const busy = (skips: number, before?: () => Promise<unknown>): Db => ({
    ...E.db,
    first: async (sql, params) => {
      if (!sql.startsWith("SELECT log_sequence") || skips-- <= 0) return E.db.first(sql, params);
      await before?.();
      return { i: null } as any;
    },
  });
  const dispute = async (id: string) => ({
    leaves: [await leafFor("Dispute", "did:key:zBusy", "cd".repeat(32), "2026-01-01T00:00:00Z")],
    stmts: [[`INSERT INTO disputes (sha256, issuer, subject, object_sha256, reason, json, received_at, log_index) VALUES ('${id}', 'i', 's', NULL, 'r', '{}', 'now', $i)`, []]] as Stmt[],
  });

  it("a write that finds the sequencer busy polls, and gets the index the other sequencer gave it", async () => {
    const { leaves, stmts } = await dispute("busy");
    const naps: number[] = [];
    // The other sequencer commits while this write waits, and moves this write's parked leaf.
    const i = await sequenced(busy(1, () => sequence(E.db)), leaves, stmts, async (ms) => { naps.push(ms); });
    expect(naps).toHaveLength(1);
    expect(Number((await E.db.first<{ log_index: number }>("SELECT log_index FROM disputes WHERE sha256 = 'busy'"))!.log_index)).toBe(i);
    expect((await E.db.first<{ object_sha256: string }>("SELECT object_sha256 FROM log_leaves WHERE idx = $1", [i]))!.object_sha256).toBe("cd".repeat(32));
    expect(await E.db.all("SELECT 1 FROM log_pending")).toEqual([]);
  });

  it("a write never sequenced in time fails loud and stays parked for the next sequencer", async () => {
    const { leaves, stmts } = await dispute("stuck");
    vi.useFakeTimers({ toFake: ["Date"] });
    try {
      await expect(sequenced(busy(Infinity), leaves, stmts, async (ms) => { vi.setSystemTime(Date.now() + ms); })).rejects.toThrow(/was not sequenced/);
    } finally {
      vi.useRealTimers();
    }
    expect(await E.db.all("SELECT 1 FROM log_pending")).toHaveLength(1);
    await incorporate(E);
    expect(await E.db.all("SELECT 1 FROM log_pending")).toEqual([]);
    expect(Number((await E.db.first<{ log_index: number }>("SELECT log_index FROM disputes WHERE sha256 = 'stuck'"))!.log_index)).toBeGreaterThanOrEqual(0);
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
    const snapText = (await call("GET", `/log/snapshots/${yesterday}.jsonl`)).text;
    expect(snapText.startsWith("\n")).toBe(false); // a day with no leaves must not start with a blank line
    const snap = snapText.trim().split("\n");
    expect(JSON.parse(snap[snap.length - 1]).checkpoint.tree_size).toBeGreaterThan(0);
    const stats = (await call("GET", "/stats")).body;
    expect(stats.entities.l0).toBeGreaterThanOrEqual(1);
    expect(stats.log.tree_size).toBe((await call("GET", "/log/sth")).body.tree_size);
  });

  it("refreshes the checkpoint timestamp every run even when the tree did not grow (spec 10.3)", async () => {
    await adopted();
    await scheduled(E);
    await E.db.run("UPDATE checkpoints SET timestamp = '2000-01-01T00:00:00Z'");
    await scheduled(E);
    const sth = (await call("GET", "/log/sth")).body;
    expect(Date.now() - Date.parse(sth.timestamp)).toBeLessThan(60_000);
  });
});
