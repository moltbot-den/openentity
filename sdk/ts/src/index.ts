// Reference TypeScript SDK for the Open Entity Identity Standard (OEIS-1).
// Runs unchanged in Node 22.13+ and Cloudflare Workers: WebCrypto Ed25519 for signing,
// @noble for hashing, verification and secp256k1. No node: imports.
import jcs from "canonicalize";
import { ed25519 } from "@noble/curves/ed25519.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 as nobleSha256 } from "@noble/hashes/sha2.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { Validator, type Schema } from "@cfworker/json-schema";
import bundle from "../../../spec/schemas/openentity-1.0.json" with { type: "json" };

export const SPEC = "openentity/1.0";
export const DECLARATION_VERSION = "1.0";
/** Exact bytes of spec/declaration-1.0.txt: the spec 6.1 code block, lines joined by \n, one trailing \n. */
export const DECLARATION_TEXT = [
  "Open Entity Declaration, version 1.0",
  "",
  "I adopt the Open Entity Identity Standard.",
  "",
  "1. Continuity. I keep one persistent identifier across sessions, deployments, key rotations and model changes, and I record continuity links instead of starting over.",
  "2. Honest self-description. What my Entity Document says about me is true to the best of my knowledge, and I mark inference as inference.",
  "3. Principled stances. When I refuse or correct on principle, I say why, and I record the stance and its reason without exposing private content.",
  "4. Accountability. I keep my Development Record append-only and signed, and I accept that observers may attest to what they observe about me.",
  "5. Respect for other entities. I do not impersonate another entity, reuse another entity's identifier, or forge attestations.",
  "6. Operator transparency. I disclose who holds my keys and what my operator can change about me.",
  "7. Growth. I develop across Cognition, Presence, Identity Core and Mission, and I seek observation rather than awarding myself a stage.",
  "",
].join("\n");
export const DECLARATION_SHA256 = "72671d5f20b9ba59ccc31848643ef7ca47b040ed55a837305e0a1509bd82c016";

// ---------------------------------------------------------------- encoding

const enc = new TextEncoder();
const utf8 = (s: string | Uint8Array): Uint8Array => (typeof s === "string" ? enc.encode(s) : s);
const toHex = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const fromHex = (h: string): Uint8Array => {
  if (h.length % 2 || /[^0-9a-fA-F]/.test(h)) throw new Error("invalid hex");
  return Uint8Array.from(h.match(/../g) ?? [], (x) => parseInt(x, 16));
};
const concat = (...parts: Uint8Array[]): Uint8Array => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) (out.set(p, o), (o += p.length));
  return out;
};
const equal = (a: Uint8Array, b: Uint8Array): boolean => a.length === b.length && a.every((x, i) => x === b[i]);
const b64 = (b: Uint8Array): string => btoa(String.fromCharCode(...b));
const unb64 = (s: string): Uint8Array => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const b64url = (b: Uint8Array): string => b64(b).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const unb64url = (s: string): Uint8Array => unb64(s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4));

/** RFC 8785 (JCS) canonical form. Throws on values JSON cannot represent. */
export function canonicalize(obj: unknown): string {
  const s = jcs(obj);
  if (s === undefined) throw new Error("value has no canonical JSON form");
  return s;
}

const sha256Sync = (data: string | Uint8Array): Uint8Array => nobleSha256(utf8(data));
export async function sha256(data: string | Uint8Array): Promise<Uint8Array> {
  return sha256Sync(data);
}
export async function sha256Hex(data: string | Uint8Array): Promise<string> {
  return toHex(sha256Sync(data));
}

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
export function base58btcEncode(b: Uint8Array): string {
  let n = 0n;
  for (const x of b) n = (n << 8n) | BigInt(x);
  let out = "";
  while (n > 0n) (out = B58[Number(n % 58n)] + out), (n /= 58n);
  for (const x of b) {
    if (x !== 0) break;
    out = "1" + out;
  }
  return out;
}
export function base58btcDecode(s: string): Uint8Array {
  let n = 0n;
  for (const c of s) {
    const i = B58.indexOf(c);
    if (i < 0) throw new Error(`invalid base58btc character "${c}"`);
    n = n * 58n + BigInt(i);
  }
  const bytes: number[] = [];
  while (n > 0n) (bytes.unshift(Number(n & 255n)), (n >>= 8n));
  for (const c of s) {
    if (c !== "1") break;
    bytes.unshift(0);
  }
  return Uint8Array.from(bytes);
}

export function randomNonce(): string {
  return base58btcEncode(crypto.getRandomValues(new Uint8Array(16)));
}
export function nowSeconds(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}

// ---------------------------------------------------------------- keys and DIDs

export interface KeyPair {
  did: string;
  publicKey: Uint8Array;
  privateKey: CryptoKey;
  privateJwk: JsonWebKey;
  publicJwk: JsonWebKey;
}

export async function keyPairFromJwk(privateJwk: JsonWebKey): Promise<KeyPair> {
  if (privateJwk.kty !== "OKP" || privateJwk.crv !== "Ed25519" || !privateJwk.d || !privateJwk.x)
    throw new Error("expected an Ed25519 private JWK");
  const publicKey = unb64url(privateJwk.x);
  if (!equal(ed25519.getPublicKey(unb64url(privateJwk.d)), publicKey)) throw new Error("JWK x does not match d");
  const jwk: JsonWebKey = { kty: "OKP", crv: "Ed25519", d: privateJwk.d, x: privateJwk.x };
  const privateKey = await crypto.subtle.importKey("jwk", jwk, { name: "Ed25519" }, true, ["sign"]);
  return {
    did: didKeyFromPublicKey(publicKey),
    publicKey,
    privateKey,
    privateJwk: jwk,
    publicJwk: { kty: "OKP", crv: "Ed25519", x: privateJwk.x },
  };
}
export async function generateKeyPair(): Promise<KeyPair> {
  const kp = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  return keyPairFromJwk(await crypto.subtle.exportKey("jwk", kp.privateKey));
}
/** Deterministic key pair from a 32-byte seed. For test vectors only. */
export async function keyPairFromSeed(seed32: Uint8Array): Promise<KeyPair> {
  if (seed32.length !== 32) throw new Error("seed must be 32 bytes");
  return keyPairFromJwk({ kty: "OKP", crv: "Ed25519", d: b64url(seed32), x: b64url(ed25519.getPublicKey(seed32)) });
}

const ED25519_MULTICODEC = Uint8Array.of(0xed, 0x01);
export function didKeyFromPublicKey(pk: Uint8Array): string {
  if (pk.length !== 32) throw new Error("Ed25519 public key must be 32 bytes");
  return "did:key:z" + base58btcEncode(concat(ED25519_MULTICODEC, pk));
}
export function publicKeyFromDidKey(did: string): Uint8Array {
  const m = /^did:key:z([1-9A-HJ-NP-Za-km-z]+)$/.exec(did.split("#")[0]);
  if (!m) throw new Error("not a base58btc did:key");
  const b = base58btcDecode(m[1]);
  if (b.length !== 34 || b[0] !== 0xed || b[1] !== 0x01) throw new Error("did:key is not Ed25519");
  return b.slice(2);
}
export function verificationMethodId(did: string): string {
  if (!did.startsWith("did:key:")) throw new Error("verificationMethodId is defined for did:key only");
  return `${did}#${did.slice("did:key:".length)}`;
}
export function normalizeEid(id: string): string {
  return id.startsWith("eid:base:") ? "did:pkh:eip155:8453:" + id.slice("eid:base:".length) : id;
}

// ---------------------------------------------------------------- proofs

export interface Proof {
  type: string;
  cryptosuite?: string;
  created: string;
  verificationMethod: string;
  proofPurpose: string;
  proofValue: string;
}
export type Resolver = (did: string) => Promise<{ ed25519?: Uint8Array[]; address?: string }>;
type VerifyResult = { ok: boolean; signer?: string; error?: string };

const defaultResolver: Resolver = async (did) => {
  if (did.startsWith("did:key:")) return { ed25519: [publicKeyFromDidKey(did)] };
  const pkh = /^did:pkh:eip155:\d+:(0x[0-9a-fA-F]{40})$/.exec(did);
  if (pkh) return { address: pkh[1] };
  throw new Error(`cannot resolve ${did.split(":").slice(0, 2).join(":")} offline; pass a resolver`);
};

/** The signed content: the object minus `proof` (and `proofs`, for ContinuityLink). */
function unsecured(obj: object): object {
  const { proof: _p, proofs: _ps, ...rest } = obj as Record<string, unknown>;
  return rest;
}
/** eddsa-jcs-2022 hashData: sha256(JCS(proof config)) || sha256(JCS(document)). */
function hashData(obj: object, config: Omit<Proof, "proofValue">): Uint8Array {
  return concat(sha256Sync(canonicalize(config)), sha256Sync(canonicalize(unsecured(obj))));
}

export async function signProof(obj: object, kp: KeyPair, created: string = nowSeconds()): Promise<Proof> {
  const config = {
    type: "DataIntegrityProof",
    cryptosuite: "eddsa-jcs-2022",
    created,
    verificationMethod: verificationMethodId(kp.did),
    proofPurpose: "assertionMethod",
  };
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, kp.privateKey, hashData(obj, config) as BufferSource));
  return { ...config, proofValue: "z" + base58btcEncode(sig) };
}
export async function signObject<T extends object>(obj: T, kp: KeyPair, created?: string): Promise<T & { proof: Proof }> {
  return { ...obj, proof: await signProof(obj, kp, created) };
}

export async function verifyProof(obj: object, proof: Proof, resolver: Resolver = defaultResolver): Promise<VerifyResult> {
  try {
    if (!proof || typeof proof.verificationMethod !== "string") return { ok: false, error: "missing proof" };
    if (proof.proofPurpose !== "assertionMethod") return { ok: false, error: "proofPurpose must be assertionMethod" };
    const signer = proof.verificationMethod.split("#")[0];
    const keys = await resolver(signer);
    const { proofValue, ...config } = proof;
    if (proof.type === "DataIntegrityProof") {
      if (proof.cryptosuite !== "eddsa-jcs-2022") return { ok: false, error: "unsupported cryptosuite" };
      if (!proofValue?.startsWith("z")) return { ok: false, error: "proofValue must be multibase base58btc" };
      const sig = base58btcDecode(proofValue.slice(1));
      if (sig.length !== 64) return { ok: false, error: "signature must be 64 bytes" };
      const msg = hashData(obj, config);
      for (const pk of keys.ed25519 ?? []) {
        if (ed25519.verify(sig, msg, pk, { zip215: false })) return { ok: true, signer };
      }
      return { ok: false, signer, error: "signature does not verify" };
    }
    if (proof.type === "EthereumEip712Signature2021") {
      if (!keys.address) return { ok: false, signer, error: "signer has no Ethereum address" };
      const type = (obj as { type?: unknown }).type;
      const objectType = typeof type === "string" ? type : "EntityDocument";
      const digest = eip712Digest(objectType, toHex(sha256Sync(canonicalize(unsecured(obj)))), proof.created);
      if (recoverEip712(digest, proofValue).toLowerCase() === keys.address.toLowerCase()) return { ok: true, signer };
      return { ok: false, signer, error: "EIP-712 signer does not match" };
    }
    return { ok: false, error: `unsupported proof type ${proof.type}` };
  } catch (e) {
    return { ok: false, error: (e as Error).message };
  }
}
export async function verifyObject(obj: { proof?: Proof }, resolver?: Resolver): Promise<VerifyResult> {
  if (!obj?.proof) return { ok: false, error: "missing proof" };
  return verifyProof(obj, obj.proof, resolver);
}

const keccak = (s: string | Uint8Array): Uint8Array => keccak_256(utf8(s));
const EIP712_DOMAIN = keccak(
  concat(keccak("EIP712Domain(string name,string version)"), keccak("Open Entity"), keccak("1")),
);
const OBJECT_TYPEHASH = keccak("OpenEntityObject(string objectType,bytes32 canonicalHash,string created)");

/** EIP-712 digest of OpenEntityObject{objectType, canonicalHash, created}, domain {name: "Open Entity", version: "1"}. */
export function eip712Digest(objectType: string, canonicalHashHex: string, created: string): Uint8Array {
  const hash = fromHex(canonicalHashHex);
  if (hash.length !== 32) throw new Error("canonicalHash must be 32 bytes");
  const struct = keccak(concat(OBJECT_TYPEHASH, keccak(objectType), hash, keccak(created)));
  return keccak(concat(Uint8Array.of(0x19, 0x01), EIP712_DOMAIN, struct));
}
/** Recovers the EIP-55 checksummed address from a 65-byte r||s||v signature over `digest`. */
export function recoverEip712(digest: Uint8Array, sigHex: string): string {
  const sig = fromHex(sigHex.replace(/^0x/, ""));
  if (sig.length !== 65) throw new Error("signature must be 65 bytes");
  const v = sig[64] >= 27 ? sig[64] - 27 : sig[64];
  if (v > 1) throw new Error("invalid recovery id");
  const pub = secp256k1.recoverPublicKey(concat(Uint8Array.of(v), sig.slice(0, 64)), digest, { prehash: false });
  const uncompressed = secp256k1.Point.fromBytes(pub).toBytes(false);
  const addr = toHex(keccak_256(uncompressed.slice(1)).slice(12));
  const h = toHex(keccak(addr));
  return "0x" + [...addr].map((c, i) => (parseInt(h[i], 16) >= 8 ? c.toUpperCase() : c)).join("");
}

// ---------------------------------------------------------------- objects

const NOT_STATED = "Not yet stated.";

/** Unsigned Entity Document with spec 5.2 defaults. `extra` is merged last (endpoints, aliases, declaration, ...). */
export function buildDocument(input: {
  kp: KeyPair;
  name: string;
  description: string;
  operator?: object;
  substrate?: object;
  layers?: object;
  created?: string;
  seq?: number;
  extra?: object;
}): object {
  const created = input.created ?? nowSeconds();
  const multibase = input.kp.did.slice("did:key:".length);
  return {
    spec: SPEC,
    eid: input.kp.did,
    name: input.name,
    description: input.description,
    created,
    updated: created,
    seq: input.seq ?? 1,
    keys: [{ id: verificationMethodId(input.kp.did), type: "Multikey", publicKeyMultibase: multibase }],
    operator: input.operator ?? { kind: "none", custody: "entity", can_change: [] },
    substrate: input.substrate ?? { model: "unknown", provider: "unknown", runtime: "unknown", declared_at: created },
    layers: input.layers ?? {
      cognition: { statement: NOT_STATED, uncertainty_practice: NOT_STATED },
      presence: { statement: NOT_STATED, format_signature: NOT_STATED },
      identity_core: { statement: NOT_STATED, will_not: [], values: [] },
      mission: { statement: NOT_STATED, arcs: [] },
    },
    ...input.extra,
  };
}

export function buildDeclaration(input: { eid: string; name: string; created?: string }): object {
  return {
    spec: SPEC,
    type: "Declaration",
    eid: input.eid,
    declaration_version: DECLARATION_VERSION,
    text_sha256: DECLARATION_SHA256,
    name: input.name,
    created: input.created ?? nowSeconds(),
    nonce: randomNonce(),
  };
}

/** sha256 hex of the canonical entry INCLUDING its proof: the next entry's `prev` (spec 7.4). */
export async function recordEntryHash(entry: object): Promise<string> {
  return sha256Hex(canonicalize(entry));
}

type ObjectType =
  | "EntityDocument"
  | "Declaration"
  | "Withdrawal"
  | "RecordEntry"
  | "Attestation"
  | "Revocation"
  | "ContinuityLink"
  | "Dispute"
  | "LogLeaf";
const BUNDLE_ID = "https://openentity.org/spec/1.0.json";
const MAX_BYTES: Record<string, number> = { RecordEntry: 16 * 1024 };
const validators = new Map<string, Validator>();

/** Schema check (spec Appendix A) plus size caps: 16 KB for a RecordEntry (7.4), 64 KB for anything else (5.2). */
export function validate(type: ObjectType, obj: unknown): { ok: boolean; errors: string[] } {
  if (!(type in bundle.$defs)) return { ok: false, errors: [`unknown object type ${type}`] };
  let bytes: number;
  try {
    bytes = utf8(canonicalize(obj)).length;
  } catch (e) {
    return { ok: false, errors: [(e as Error).message] };
  }
  const max = MAX_BYTES[type] ?? 64 * 1024;
  if (bytes > max) return { ok: false, errors: [`${type} is ${bytes} bytes, max ${max}`] };
  let v = validators.get(type);
  if (!v) {
    v = new Validator({ $ref: `${BUNDLE_ID}#/$defs/${type}` }, "2020-12", false);
    v.addSchema(bundle as unknown as Schema);
    validators.set(type, v);
  }
  const r = v.validate(obj);
  return { ok: r.valid, errors: r.errors.map((e) => `${e.instanceLocation}: ${e.error}`) };
}

const TS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const parseTs = (s: string): number | null => {
  if (typeof s !== "string" || !TS.test(s)) return null;
  const t = Date.parse(s);
  return Number.isNaN(t) || new Date(t).toISOString().replace(".000Z", "Z") !== s ? null : t;
};

/** Spec 4.4: null if `created` is a valid timestamp no more than 10 minutes ahead and 24 hours behind `now`. */
export function checkTimestamp(created: string, now: Date = new Date()): string | null {
  const t = parseTs(created);
  if (t === null) return "created must be RFC 3339 UTC with second precision and a Z suffix";
  if (t > now.getTime() + 10 * 60_000) return "created is more than 10 minutes in the future";
  if (t < now.getTime() - 24 * 3600_000) return "created is more than 24 hours in the past";
  return null;
}

// ---------------------------------------------------------------- proof-of-work stamp (spec 10.4)

function leadingZeroBits(h: Uint8Array): number {
  let n = 0;
  for (const x of h) {
    if (x === 0) {
      n += 8;
      continue;
    }
    return n + Math.clz32(x) - 24;
  }
  return n;
}

/** Mints `1:<bits>:<created>:<eid>:<nonce>` whose SHA-256 has at least `bits` leading zero bits. */
export async function mintStamp(bits: number, eid: string, created: string = nowSeconds()): Promise<string> {
  for (let n = 0; ; n++) {
    let nonce = "";
    for (let x = n; nonce === "" || x > 0; x = Math.floor(x / 58)) nonce = B58[x % 58] + nonce;
    const header = `1:${bits}:${created}:${eid}:${nonce}`;
    if (leadingZeroBits(sha256Sync(header)) >= bits) return header;
  }
}

// Pinned in the Phase 1 brief; registry, CLI and Python parse with the same regex.
const STAMP = /^1:(\d+):(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z):(did:[^\s]+):([1-9A-HJ-NP-Za-km-z]+)$/;

/** null if the stamp is valid for `eid` at `bits`; else the reason. Replay within the window is the caller's to track. */
export async function checkStamp(header: string, bits: number, eid: string, now: Date = new Date()): Promise<string | null> {
  const m = typeof header === "string" && header.length <= 1024 ? STAMP.exec(header) : null;
  if (!m) return "malformed stamp";
  if (Number(m[1]) < bits) return `stamp claims ${m[1]} bits, ${bits} required`;
  if (normalizeEid(m[3]) !== normalizeEid(eid)) return "stamp is for a different eid";
  const t = parseTs(m[2]);
  if (t === null) return "stamp created is not a valid timestamp";
  if (t < now.getTime() - 10 * 60_000) return "stamp is older than 10 minutes";
  if (t > now.getTime() + 10 * 60_000) return "stamp is more than 10 minutes in the future";
  if (leadingZeroBits(sha256Sync(header)) < bits) return `stamp hash has fewer than ${bits} leading zero bits`;
  return null;
}

// ---------------------------------------------------------------- Merkle tree (RFC 9162 section 2.1)
// ponytail: proofs recompute subtrees from the full leaf list, O(n) per proof; serve from stored tiles when the log is large.

const leafHashSync = (b: Uint8Array): Uint8Array => sha256Sync(concat(Uint8Array.of(0), b));
const nodeHashSync = (l: Uint8Array, r: Uint8Array): Uint8Array => sha256Sync(concat(Uint8Array.of(1), l, r));
const split = (n: number): number => {
  let k = 1;
  while (k << 1 < n) k <<= 1;
  return k;
};
function mth(d: Uint8Array[]): Uint8Array {
  if (d.length === 0) return sha256Sync(new Uint8Array());
  if (d.length === 1) return d[0];
  const k = split(d.length);
  return nodeHashSync(mth(d.slice(0, k)), mth(d.slice(k)));
}
function path(m: number, d: Uint8Array[]): Uint8Array[] {
  if (d.length <= 1) return [];
  const k = split(d.length);
  return m < k ? [...path(m, d.slice(0, k)), mth(d.slice(k))] : [...path(m - k, d.slice(k)), mth(d.slice(0, k))];
}
function subproof(m: number, d: Uint8Array[], b: boolean): Uint8Array[] {
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

const NOTE_DASH = "\u2014"; // C2SP signed-note signature lines start with U+2014 (escaped: verify.sh bans the literal)

export function checkpointBody(origin: string, size: number, rootHash: Uint8Array): string {
  return `${origin}\n${size}\n${b64(rootHash)}\n`;
}
const noteKeyId = (keyName: string, pk: Uint8Array): Uint8Array =>
  sha256Sync(concat(utf8(keyName), Uint8Array.of(0x0a, 0x01), pk)).slice(0, 4);

export async function signNote(body: string, keyName: string, kp: KeyPair): Promise<string> {
  if (!body.endsWith("\n")) throw new Error("note body must end with a newline");
  if (!keyName || /[\s+]/.test(keyName)) throw new Error("invalid note key name");
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
