import { OpenEntityError } from "./errors.ts";
import { ed25519 } from "@noble/curves/ed25519.js";
import { utf8, toHex, concat, equal, b64, unb64, sha256Sync, type KeyPair } from "./core.ts";
// ---------------------------------------------------------------- Merkle tree (RFC 9162 section 2.1)
// ponytail: proofs recompute subtrees from the full leaf list, O(n) per proof; serve from stored tiles when the log is large.

/** @internal */
export const leafHashSync = (b: Uint8Array): Uint8Array => sha256Sync(concat(Uint8Array.of(0), b));
/** @internal */
export const nodeHashSync = (l: Uint8Array, r: Uint8Array): Uint8Array => sha256Sync(concat(Uint8Array.of(1), l, r));
/** @internal */
export const split = (n: number): number => {
  let k = 1;
  while (k << 1 < n) k <<= 1;
  return k;
};
/** @internal */
export function mth(d: Uint8Array[]): Uint8Array {
  if (d.length === 0) return sha256Sync(new Uint8Array());
  if (d.length === 1) return d[0];
  const k = split(d.length);
  return nodeHashSync(mth(d.slice(0, k)), mth(d.slice(k)));
}
/** @internal */
export function path(m: number, d: Uint8Array[]): Uint8Array[] {
  if (d.length <= 1) return [];
  const k = split(d.length);
  return m < k ? [...path(m, d.slice(0, k)), mth(d.slice(k))] : [...path(m - k, d.slice(k)), mth(d.slice(0, k))];
}
/** @internal */
export function subproof(m: number, d: Uint8Array[], b: boolean): Uint8Array[] {
  if (m === d.length) return b ? [] : [mth(d)];
  const k = split(d.length);
  return m <= k
    ? [...subproof(m, d.slice(0, k), b), mth(d.slice(k))]
    : [...subproof(m - k, d.slice(k), false), mth(d.slice(0, k))];
}

export async function leafHash(leafBytes: Uint8Array): Promise<Uint8Array> {
  return leafHashSync(leafBytes);
}
export async function nodeHash(l: Uint8Array, r: Uint8Array): Promise<Uint8Array> {
  return nodeHashSync(l, r);
}
export async function merkleRoot(leafHashes: Uint8Array[]): Promise<Uint8Array> {
  return mth(leafHashes);
}
export async function inclusionProof(index: number, leafHashes: Uint8Array[]): Promise<Uint8Array[]> {
  if (!Number.isInteger(index) || index < 0 || index >= leafHashes.length) throw new RangeError("index out of range");
  return path(index, leafHashes);
}
/** `leaf` is the leaf hash (leafHash of the leaf bytes). */
export async function verifyInclusion(
  index: number,
  size: number,
  leaf: Uint8Array,
  proof: Uint8Array[],
  root: Uint8Array,
): Promise<boolean> {
  if (!Number.isInteger(index) || !Number.isInteger(size) || index < 0 || index >= size) return false;
  let fn = index;
  let sn = size - 1;
  let r = leaf;
  for (const p of proof) {
    if (sn === 0) return false;
    if (fn & 1 || fn === sn) {
      r = nodeHashSync(p, r);
      while (!(fn & 1) && fn !== 0) (fn >>= 1), (sn >>= 1);
    } else r = nodeHashSync(r, p);
    fn >>= 1;
    sn >>= 1;
  }
  return sn === 0 && equal(r, root);
}
export async function consistencyProof(m: number, leafHashes: Uint8Array[]): Promise<Uint8Array[]> {
  if (!Number.isInteger(m) || m < 1 || m > leafHashes.length) throw new RangeError("m out of range");
  return subproof(m, leafHashes, true);
}
export async function verifyConsistency(
  m: number,
  n: number,
  rootM: Uint8Array,
  rootN: Uint8Array,
  proof: Uint8Array[],
): Promise<boolean> {
  if (!Number.isInteger(m) || !Number.isInteger(n) || m < 1 || m > n) return false;
  if (m === n) return proof.length === 0 && equal(rootM, rootN);
  if (proof.length === 0) return false;
  const p = (m & (m - 1)) === 0 ? [rootM, ...proof] : proof;
  let fn = m - 1;
  let sn = n - 1;
  while (fn & 1) (fn >>= 1), (sn >>= 1);
  let fr = p[0];
  let sr = p[0];
  for (const c of p.slice(1)) {
    if (sn === 0) return false;
    if (fn & 1 || fn === sn) {
      fr = nodeHashSync(c, fr);
      sr = nodeHashSync(c, sr);
      while (!(fn & 1) && fn !== 0) (fn >>= 1), (sn >>= 1);
    } else sr = nodeHashSync(sr, c);
    fn >>= 1;
    sn >>= 1;
  }
  return sn === 0 && equal(fr, rootM) && equal(sr, rootN);
}

/** Spec 10.3 leaf. Leaf bytes are the UTF-8 of canonicalize(leaf). */
export function logLeaf(type: string, eid: string, objectSha256: string, receivedAt: string): object {
  return { type, eid, object_sha256: objectSha256, received_at: receivedAt };
}

// ---------------------------------------------------------------- checkpoint (C2SP signed-note, tlog-checkpoint)

/** @internal */
export const NOTE_DASH = "\u2014"; // C2SP signed-note signature lines start with U+2014 (escaped: verify.sh bans the literal)

export function checkpointBody(origin: string, size: number, rootHash: Uint8Array): string {
  return `${origin}\n${size}\n${b64(rootHash)}\n`;
}
/** @internal */
export const noteKeyId = (keyName: string, pk: Uint8Array): Uint8Array =>
  sha256Sync(concat(utf8(keyName), Uint8Array.of(0x0a, 0x01), pk)).slice(0, 4);

export async function signNote(body: string, keyName: string, kp: KeyPair): Promise<string> {
  if (!body.endsWith("\n")) throw new OpenEntityError("invalid_input", "note body must end with a newline");
  if (!keyName || /[\s+]/.test(keyName)) throw new OpenEntityError("invalid_input", "invalid note key name");
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, kp.privateKey, utf8(body) as BufferSource));
  return `${body}\n${NOTE_DASH} ${keyName} ${b64(concat(noteKeyId(keyName, kp.publicKey), sig))}\n`;
}
/** C2SP vkey for a note key: `<name>+<key id hex>+<base64(0x01 || pubkey)>`. */
export function noteVkey(keyName: string, publicKey: Uint8Array): string {
  return `${keyName}+${toHex(noteKeyId(keyName, publicKey))}+${b64(concat(Uint8Array.of(0x01), publicKey))}`;
}
export async function verifyNote(note: string, keyName: string, publicKey: Uint8Array): Promise<boolean> {
  const i = note.lastIndexOf("\n\n");
  if (i < 0 || !note.endsWith("\n")) return false;
  const text = utf8(note.slice(0, i + 1));
  const id = noteKeyId(keyName, publicKey);
  for (const line of note.slice(i + 2, -1).split("\n")) {
    const prefix = `${NOTE_DASH} ${keyName} `;
    if (!line.startsWith(prefix)) continue;
    let raw: Uint8Array;
    try {
      raw = unb64(line.slice(prefix.length));
    } catch {
      continue;
    }
    if (raw.length === 68 && equal(raw.slice(0, 4), id) && ed25519.verify(raw.slice(4), text, publicKey, { zip215: false }))
      return true;
  }
  return false;
}

