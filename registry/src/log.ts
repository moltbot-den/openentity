// Transparency log (spec 10.3): RFC 6962 Merkle tree over D1, C2SP tlog-tiles on R2, signed checkpoints.
import { AwsClient } from "aws4fetch";
import { canonicalize, checkpointBody, keyPairFromJwk, leafHash, logLeaf, nodeHash, sha256, signNote, type KeyPair } from "./sdk.ts";
import { type Env, LOG_ORIGIN, b64, hex, nowIso, unhex } from "./env.ts";

const enc = new TextEncoder();

/** Leaf for an accepted object, plus the D1 statement that sequences it (index = previous max + 1). */
export async function leafFor(db: D1Database, type: string, eid: string, objectSha256: string, receivedAt: string) {
  const leaf = logLeaf(type, eid, objectSha256, receivedAt);
  const leaf_hash = hex(await leafHash(enc.encode(canonicalize(leaf))));
  const stmt = db
    .prepare("INSERT INTO log_leaves (idx, leaf_hash, type, eid, object_sha256, received_at) VALUES ((SELECT COALESCE(MAX(idx) + 1, 0) FROM log_leaves), ?, ?, ?, ?, ?) RETURNING idx")
    .bind(leaf_hash, type, eid, objectSha256, receivedAt);
  return { leaf, leaf_hash, stmt };
}
/** SQL expression for the index of the leaf inserted just before, inside the same batch. */
export const LAST_INDEX = "(SELECT MAX(idx) FROM log_leaves)";

let cachedKey: { jwk: string; kp: KeyPair } | undefined;
export async function registryKey(env: Env): Promise<KeyPair> {
  if (!env.REGISTRY_KEY_JWK) throw new Error("REGISTRY_KEY_JWK secret is not set");
  if (cachedKey?.jwk !== env.REGISTRY_KEY_JWK) cachedKey = { jwk: env.REGISTRY_KEY_JWK, kp: await keyPairFromJwk(JSON.parse(env.REGISTRY_KEY_JWK)) };
  return cachedKey.kp;
}
class Nodes {
  cache = new Map<string, string>();
  fresh: [number, number, string][] = [];
  constructor(private db: D1Database) {}
  async get(level: number, idx: number): Promise<string> {
    const k = `${level}:${idx}`;
    let h = this.cache.get(k);
    if (!h) {
      h = (await this.db.prepare("SELECT hash FROM log_nodes WHERE level = ? AND idx = ?").bind(level, idx).first<string>("hash")) ?? undefined;
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
export const inclusionProof = (db: D1Database, index: number, size: number) => path(new Nodes(db), index, 0, size);
export const consistencyProof = (db: D1Database, m: number, n: number) => subproof(new Nodes(db), m, 0, n, true);
export const treeRoot = (db: D1Database, size: number) => rootOf(new Nodes(db), size);

/** C2SP tile index: 1234067 -> x001/x234/067. */
export function tileIndex(n: number): string {
  let s = String(n);
  s = s.padStart(Math.ceil(s.length / 3) * 3, "0");
  const g = s.match(/.../g)!;
  return g.map((x, i) => (i < g.length - 1 ? "x" + x : x)).join("/");
}

export async function latestSize(db: D1Database): Promise<number> {
  return (await db.prepare("SELECT COALESCE(MAX(tree_size), 0) AS n FROM checkpoints").first<number>("n")) ?? 0;
}

/** Incorporate sequenced leaves into the tree, write tiles, sign a checkpoint. Idempotent. Returns the new size. */
export async function incorporate(env: Env, maxLeaves = 5000): Promise<number> {
  const db = env.DB;
  const old = await latestSize(db);
  const rows = (await db.prepare("SELECT idx, leaf_hash, type, eid, object_sha256, received_at FROM log_leaves WHERE idx >= ? ORDER BY idx LIMIT ?").bind(old, maxLeaves).all<LeafRow>()).results;
  let size = old;
  for (const r of rows) { if (r.idx !== size) break; size++; }
  if (size === old) return old;

  const nodes = new Nodes(db);
  for (let i = old; i < size; i++) {
    nodes.put(0, i, rows[i - old].leaf_hash);
    for (let level = 0, j = i; j & 1; level++, j >>= 1) nodes.put(level + 1, j >> 1, await H(await nodes.get(level, j - 1), await nodes.get(level, j)));
  }
  const ins = db.prepare("INSERT OR IGNORE INTO log_nodes (level, idx, hash) VALUES (?, ?, ?)");
  for (let i = 0; i < nodes.fresh.length; i += 500) await db.batch(nodes.fresh.slice(i, i + 500).map((n) => ins.bind(...n)));

  // Hash tiles: level L holds the subtree hashes of height 8L, 256 per tile.
  for (let L = 0; ; L++) {
    const per = 2 ** (8 * L), cOld = Math.floor(old / per), cNew = Math.floor(size / per);
    if (cNew === 0) break;
    if (cNew === cOld) continue;
    for (let N = Math.floor(cOld / 256); N <= Math.floor((cNew - 1) / 256); N++) {
      const from = N * 256, to = Math.min(from + 256, cNew);
      const hs = (await db.prepare("SELECT hash FROM log_nodes WHERE level = ? AND idx >= ? AND idx < ? ORDER BY idx").bind(8 * L, from, to).all<{ hash: string }>()).results;
      const body = new Uint8Array(32 * hs.length);
      hs.forEach((h, i) => body.set(unhex(h.hash), 32 * i));
      await env.LOG.put(`tile/${L}/${tileIndex(N)}${to - from < 256 ? `.p/${to - from}` : ""}`, body);
    }
  }
  // Entry bundles: big-endian uint16 length + canonical leaf bytes.
  for (let N = Math.floor(old / 256); N <= Math.floor((size - 1) / 256); N++) {
    const from = N * 256, to = Math.min(from + 256, size);
    const ls = (await db.prepare("SELECT type, eid, object_sha256, received_at FROM log_leaves WHERE idx >= ? AND idx < ? ORDER BY idx").bind(from, to).all<LeafRow>()).results;
    const parts = ls.map((l) => enc.encode(leafJson(l)));
    const body = new Uint8Array(parts.reduce((a, p) => a + 2 + p.length, 0));
    let o = 0;
    for (const p of parts) { body[o] = p.length >> 8; body[o + 1] = p.length & 255; body.set(p, o + 2); o += 2 + p.length; }
    await env.LOG.put(`tile/entries/${tileIndex(N)}${to - from < 256 ? `.p/${to - from}` : ""}`, body);
  }

  const root = await rootOf(nodes, size);
  const note = await signNote(checkpointBody(LOG_ORIGIN, size, unhex(root)), LOG_ORIGIN, await registryKey(env));
  const timestamp = nowIso();
  await env.LOG.put("checkpoint", note, { httpMetadata: { contentType: "text/plain; charset=utf-8" } });
  await db.prepare("INSERT OR IGNORE INTO checkpoints (tree_size, root_hash, timestamp, signed_note) VALUES (?, ?, ?, ?)").bind(size, root, timestamp, note).run();
  return rows.length === maxLeaves ? incorporate(env, maxLeaves) : size;
}

export interface LeafRow { idx: number; leaf_hash: string; type: string; eid: string; object_sha256: string; received_at: string }
export const leafJson = (l: Pick<LeafRow, "type" | "eid" | "object_sha256" | "received_at">) =>
  canonicalize(logLeaf(l.type, l.eid, l.object_sha256, l.received_at));

/** Daily snapshot: one JSON line per leaf of `date`, then the latest checkpoint. Copied to S3 when configured. */
export async function snapshot(env: Env, date: string): Promise<boolean> {
  const key = `snapshots/${date}.jsonl`;
  if (await env.LOG.head(key)) return false;
  const leaves = (await env.DB.prepare("SELECT * FROM log_leaves WHERE received_at >= ? AND received_at < ? ORDER BY idx").bind(`${date}T00:00:00Z`, `${date}T99`).all<LeafRow>()).results;
  const cp = await env.DB.prepare("SELECT tree_size, root_hash, timestamp, signed_note FROM checkpoints ORDER BY tree_size DESC LIMIT 1").first();
  // ponytail: whole day in one string; stream to R2 if a day's leaves outgrow Worker memory.
  const body = leaves.map((l) => JSON.stringify({ index: l.idx, leaf: JSON.parse(leafJson(l)), leaf_hash: l.leaf_hash })).join("\n") + "\n" + JSON.stringify({ checkpoint: cp }) + "\n";
  await env.LOG.put(key, body, { httpMetadata: { contentType: "application/jsonl" } });
  if (env.S3_BUCKET && env.AWS_ACCESS_KEY_ID && env.AWS_SECRET_ACCESS_KEY) {
    const aws = new AwsClient({ accessKeyId: env.AWS_ACCESS_KEY_ID, secretAccessKey: env.AWS_SECRET_ACCESS_KEY, service: "s3", region: env.S3_REGION || "us-east-1" });
    const res = await aws.fetch(`https://${env.S3_BUCKET}.s3.${env.S3_REGION || "us-east-1"}.amazonaws.com/${key}`, { method: "PUT", body, headers: { "content-type": "application/jsonl", "x-amz-checksum-sha256": b64(await sha256(body)) } }); // Object Lock buckets require a checksum
    if (!res.ok) throw new Error(`S3 snapshot copy failed: ${res.status} ${await res.text()}`);
  } else console.log(`snapshot ${key}: S3 copy skipped, S3_BUCKET or AWS credentials not set`);
  return true;
}
