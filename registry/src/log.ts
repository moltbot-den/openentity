// Transparency log (spec 10.3): RFC 6962 Merkle tree over Postgres, C2SP tlog-tiles on S3, signed checkpoints.
import { canonicalize, checkpointBody, keyPairFromJwk, leafHash, logLeaf, nodeHash, sha256, signNote, type KeyPair } from "./sdk.ts";
import { type Env, LOG_ORIGIN, hex, nowIso, unhex } from "./env.ts";
import type { Db } from "./db.ts";

const enc = new TextEncoder();

/** Leaf and leaf hash for an accepted object. */
export async function leafFor(type: string, eid: string, objectSha256: string, receivedAt: string) {
  const leaf = logLeaf(type, eid, objectSha256, receivedAt);
  return { leaf, leaf_hash: hex(await leafHash(enc.encode(canonicalize(leaf)))) };
}

export type Stmt = [sql: string, params: unknown[]];
/**
 * Group commit, step 1 and 2. Step 1 runs `stmts` and parks `leaves` in log_pending as ONE statement with no
 * log_head lock: atomic (a unique guard or crash leaves nothing behind) and fully parallel. In it, `$i` is a
 * negative placeholder log index (`$i + k` for the k-th leaf) that step 2 rewrites to the real index. Step 2,
 * `sequence`, moves every pending leaf, this write's and everyone else's, into the log under the log_head lock.
 * Only one sequencer runs at a time; a write that finds it busy polls until its leaves have an index (the busy
 * sequencer, or the next one, takes them). Returns the index of this write's first leaf.
 */
export async function sequenced(db: Db, leaves: Leaf[], stmts: Stmt[], sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))): Promise<number> {
  const wid = await park(db, leaves, stmts);
  for (const end = Date.now() + 15_000; Date.now() < end;) { // a sequencer holds the lock for tens of milliseconds
    const i = await sequence(db, wid);
    if (i !== undefined) return i;
    await sleep(20 + Math.random() * 20);
  }
  throw new Error(`write ${wid} was not sequenced`); // it stays parked; the next sequencer or the cron takes it
}
type Leaf = { leaf: object; leaf_hash: string };

/** Step 1 alone; returns the write id. */
export async function park(db: Db, leaves: Leaf[], stmts: Stmt[]): Promise<number> {
  const wid = Math.floor(Math.random() * 2 ** 40) + 1; // 1024 leaves per write max (batch limit is 100); 2^40 random ids make a collision between writes in flight negligible
  const params: unknown[] = [JSON.stringify(leaves.map((l, o) => ({ ...l.leaf, leaf_hash: l.leaf_hash, o, wid })))];
  const ctes = [
    "p AS (INSERT INTO log_pending (wid, o, leaf_hash, type, eid, object_sha256, received_at) SELECT x.wid, x.o, x.leaf_hash, x.type, x.eid, x.object_sha256, x.received_at FROM json_to_recordset(CAST($1 AS json)) AS x(wid bigint, o int, leaf_hash text, type text, eid text, object_sha256 text, received_at text) ORDER BY x.o)",
    ...stmts.map(([sql, ps], k) => {
      const off = params.length;
      params.push(...ps);
      return `s${k} AS (${sql.replace(/\$(\d+)/g, (_, d) => `$${Number(d) + off}`).replaceAll("$i", `(${-wid * 1024})`)})`;
    }),
  ];
  await db.run(`WITH ${ctes.join(",\n")}\nSELECT 1`, params);
  return wid;
}

/**
 * Step 2 (`log_sequence` in schema.sql): move every pending leaf into the log if no other sequencer holds log_head.
 * Returns the first index of write `wid` once it is in the log, else undefined (the sequencer was busy).
 * Without `wid` it just drains the queue.
 */
export async function sequence(db: Db, wid?: number): Promise<number | undefined> {
  const i = (await db.first<{ i: number | null }>("SELECT log_sequence(CAST($1 AS BIGINT)) AS i", [wid ?? null]))?.i;
  return wid === undefined || i == null ? undefined : Number(i);
}

let cachedKey: { jwk: string; kp: KeyPair } | undefined;
export async function registryKey(env: Env): Promise<KeyPair> {
  if (!env.REGISTRY_KEY_JWK) throw new Error("REGISTRY_KEY_JWK secret is not set");
  if (cachedKey?.jwk !== env.REGISTRY_KEY_JWK) cachedKey = { jwk: env.REGISTRY_KEY_JWK, kp: await keyPairFromJwk(JSON.parse(env.REGISTRY_KEY_JWK)) };
  return cachedKey.kp;
}
class Nodes {
  cache = new Map<string, string>();
  fresh: [number, number, string][] = [];
  constructor(private db: Db) {}
  async get(level: number, idx: number): Promise<string> {
    const k = `${level}:${idx}`;
    let h = this.cache.get(k);
    if (!h) {
      h = (await this.db.first<{ hash: string }>("SELECT hash FROM log_nodes WHERE level = $1 AND idx = $2", [level, idx]))?.hash;
      if (!h) throw new Error(`missing log node ${k}`);
      this.cache.set(k, h);
    }
    return h;
  }
  put(level: number, idx: number, h: string) {
    this.cache.set(`${level}:${idx}`, h);
    this.fresh.push([level, idx, h]);
  }
}

const largestPow2Below = (n: number) => { let k = 1; while (k * 2 < n) k *= 2; return k; };
const H = async (l: string, r: string) => hex(await nodeHash(unhex(l), unhex(r)));

/** RFC 6962 MTH of leaves [lo, lo + n). */
async function mth(nodes: Nodes, lo: number, n: number): Promise<string> {
  if ((n & (n - 1)) === 0 && lo % n === 0) return nodes.get(Math.log2(n), lo / n);
  const k = largestPow2Below(n);
  return H(await mth(nodes, lo, k), await mth(nodes, lo + k, n - k));
}
async function rootOf(nodes: Nodes, size: number): Promise<string> {
  return size === 0 ? hex(await sha256(new Uint8Array())) : mth(nodes, 0, size);
}
async function path(nodes: Nodes, m: number, lo: number, n: number): Promise<string[]> {
  if (n === 1) return [];
  const k = largestPow2Below(n);
  return m < k
    ? [...(await path(nodes, m, lo, k)), await mth(nodes, lo + k, n - k)]
    : [...(await path(nodes, m - k, lo + k, n - k)), await mth(nodes, lo, k)];
}
async function subproof(nodes: Nodes, m: number, lo: number, n: number, b: boolean): Promise<string[]> {
  if (m === n) return b ? [] : [await mth(nodes, lo, n)];
  const k = largestPow2Below(n);
  return m <= k
    ? [...(await subproof(nodes, m, lo, k, b)), await mth(nodes, lo + k, n - k)]
    : [...(await subproof(nodes, m - k, lo + k, n - k, false)), await mth(nodes, lo, k)];
}
export const inclusionProof = (db: Db, index: number, size: number) => path(new Nodes(db), index, 0, size);
export const consistencyProof = (db: Db, m: number, n: number) => subproof(new Nodes(db), m, 0, n, true);
export const treeRoot = (db: Db, size: number) => rootOf(new Nodes(db), size);

/** C2SP tile index: 1234067 -> x001/x234/067. */
export function tileIndex(n: number): string {
  let s = String(n);
  s = s.padStart(Math.ceil(s.length / 3) * 3, "0");
  const g = s.match(/.../g)!;
  return g.map((x, i) => (i < g.length - 1 ? "x" + x : x)).join("/");
}

export async function latestSize(db: Db): Promise<number> {
  return (await db.first<{ n: number }>("SELECT COALESCE(MAX(tree_size), 0) AS n FROM checkpoints"))?.n ?? 0;
}

/** Incorporate sequenced leaves into the tree, write tiles, sign a checkpoint. Idempotent. Returns the new size. */
export async function incorporate(env: Env, maxLeaves = 5000): Promise<number> {
  const db = env.db;
  await sequence(db); // picks up leaves a crashed write left pending
  const old = await latestSize(db);
  // Two columns only: 5000 full rows passed the Data API's 1 MB result limit.
  const rows = await db.all<Pick<LeafRow, "idx" | "leaf_hash">>("SELECT idx, leaf_hash FROM log_leaves WHERE idx >= $1 ORDER BY idx LIMIT $2", [old, maxLeaves]);
  let size = old;
  for (const r of rows) { if (r.idx !== size) break; size++; }
  if (size === old) return old;

  const nodes = new Nodes(db);
  for (let i = old; i < size; i++) {
    nodes.put(0, i, rows[i - old].leaf_hash);
    for (let level = 0, j = i; j & 1; level++, j >>= 1) nodes.put(level + 1, j >> 1, await H(await nodes.get(level, j - 1), await nodes.get(level, j)));
  }
  for (let i = 0; i < nodes.fresh.length; i += 500) {
    await db.run(
      "INSERT INTO log_nodes (level, idx, hash) SELECT * FROM json_to_recordset(CAST($1 AS json)) AS x(level bigint, idx bigint, hash text) ON CONFLICT DO NOTHING",
      [JSON.stringify(nodes.fresh.slice(i, i + 500).map(([level, idx, hash]) => ({ level, idx, hash })))],
    );
  }

  // Hash tiles: level L holds the subtree hashes of height 8L, 256 per tile.
  for (let L = 0; ; L++) {
    const per = 2 ** (8 * L), cOld = Math.floor(old / per), cNew = Math.floor(size / per);
    if (cNew === 0) break;
    if (cNew === cOld) continue;
    for (let N = Math.floor(cOld / 256); N <= Math.floor((cNew - 1) / 256); N++) {
      const from = N * 256, to = Math.min(from + 256, cNew);
      const hs = await db.all<{ hash: string }>("SELECT hash FROM log_nodes WHERE level = $1 AND idx >= $2 AND idx < $3 ORDER BY idx", [8 * L, from, to]);
      const body = new Uint8Array(32 * hs.length);
      hs.forEach((h, i) => body.set(unhex(h.hash), 32 * i));
      await env.log.put(`tile/${L}/${tileIndex(N)}${to - from < 256 ? `.p/${to - from}` : ""}`, body);
    }
  }
  // Entry bundles: big-endian uint16 length + canonical leaf bytes.
  for (let N = Math.floor(old / 256); N <= Math.floor((size - 1) / 256); N++) {
    const from = N * 256, to = Math.min(from + 256, size);
    const ls = await db.all<LeafRow>("SELECT type, eid, object_sha256, received_at FROM log_leaves WHERE idx >= $1 AND idx < $2 ORDER BY idx", [from, to]);
    const parts = ls.map((l) => enc.encode(leafJson(l)));
    const body = new Uint8Array(parts.reduce((a, p) => a + 2 + p.length, 0));
    let o = 0;
    for (const p of parts) { body[o] = p.length >> 8; body[o + 1] = p.length & 255; body.set(p, o + 2); o += 2 + p.length; }
    await env.log.put(`tile/entries/${tileIndex(N)}${to - from < 256 ? `.p/${to - from}` : ""}`, body);
  }

  const root = await rootOf(nodes, size);
  const note = await signNote(checkpointBody(LOG_ORIGIN, size, unhex(root)), LOG_ORIGIN, await registryKey(env));
  const timestamp = nowIso();
  await env.log.put("checkpoint", note, "text/plain; charset=utf-8");
  await db.run("INSERT INTO checkpoints (tree_size, root_hash, timestamp, signed_note) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING", [size, root, timestamp, note]);
  return rows.length === maxLeaves ? incorporate(env, maxLeaves) : size;
}

export interface LeafRow { idx: number; leaf_hash: string; type: string; eid: string; object_sha256: string; received_at: string }
export const leafJson = (l: Pick<LeafRow, "type" | "eid" | "object_sha256" | "received_at">) =>
  canonicalize(logLeaf(l.type, l.eid, l.object_sha256, l.received_at));

/** Daily snapshot: one JSON line per leaf of `date`, then the latest checkpoint. Copied to the Object Lock bucket when configured. */
export async function snapshot(env: Env, date: string): Promise<boolean> {
  const key = `snapshots/${date}.jsonl`;
  if (await env.log.get(key)) return false;
  const leaves = await env.db.all<LeafRow>("SELECT * FROM log_leaves WHERE received_at >= $1 AND received_at < $2 ORDER BY idx", [`${date}T00:00:00Z`, `${date}T99`]);
  const cp = await env.db.first("SELECT tree_size, root_hash, timestamp, signed_note FROM checkpoints ORDER BY tree_size DESC LIMIT 1");
  // ponytail: whole day in one string; stream to S3 if a day's leaves outgrow Lambda memory.
  const body = leaves.map((l) => JSON.stringify({ index: l.idx, leaf: JSON.parse(leafJson(l)), leaf_hash: l.leaf_hash })).join("\n") + "\n" + JSON.stringify({ checkpoint: cp }) + "\n";
  await env.log.put(key, body, "application/jsonl");
  if (env.snapshots) await env.snapshots.put(key, body, "application/jsonl");
  else console.log(`snapshot ${key}: off-site copy skipped, no snapshots bucket`);
  return true;
}
