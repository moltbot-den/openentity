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

/** Spec 4.3: parse JSON text that has no duplicate keys. JSON.parse keeps the last duplicate silently, so two implementations could read different objects. */
export function parseJson(text: string): unknown {
  const v = JSON.parse(text);
  const scopes: Set<string>[] = [];
  const str = /"(?:[^"\\]|\\.)*"/y;
  for (let i = 0; i < text.length; ) {
    const ch = text[i];
    if (ch === '"') {
      str.lastIndex = i;
      const m = str.exec(text)![0];
      i += m.length;
      if (scopes.length && /^\s*:/.test(text.slice(i, i + 64))) {
        const key: string = JSON.parse(m);
        if (scopes[scopes.length - 1].has(key)) throw new Error(`duplicate key ${m}`);
        scopes[scopes.length - 1].add(key);
      }
      continue;
    }
    if (ch === "{" || ch === "[") scopes.push(new Set());
    else if (ch === "}" || ch === "]") scopes.pop();
    i++;
  }
  return v;
}

/** Spec 4.3: numbers are integers or decimal fractions with at most 6 decimal places. */
function badNumber(v: unknown): string | null {
  if (typeof v === "number") return Number.isFinite(v) && Number(v.toFixed(6)) === v ? null : `number ${v} has more than 6 decimal places`;
  if (v && typeof v === "object") for (const x of Object.values(v)) { const e = badNumber(x); if (e) return e; }
  return null;
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
  return keyPairFromJwk((await crypto.subtle.exportKey("jwk", kp.privateKey)) as JsonWebKey); // cast: Workers types widen the return
}
/** Deterministic key pair from a 32-byte seed: test vectors, and `Identity` (sdk/ts/src/node.ts), which keeps the seed. */
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
export function hashData(obj: object, config: Omit<Proof, "proofValue">): Uint8Array {
  return concat(sha256Sync(canonicalize(config)), sha256Sync(canonicalize(unsecured(obj))));
}

/** `verificationMethod` defaults to the did:key of `kp`; a did:web signer passes its own method id (for example `did:web:x#key-1`). */
export async function signProof(obj: object, kp: KeyPair, created: string = nowSeconds(), verificationMethod = verificationMethodId(kp.did)): Promise<Proof> {
  const config = {
    type: "DataIntegrityProof",
    cryptosuite: "eddsa-jcs-2022",
    created,
    verificationMethod,
    proofPurpose: "assertionMethod",
  };
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, kp.privateKey, hashData(obj, config) as BufferSource));
  return { ...config, proofValue: "z" + base58btcEncode(sig) };
}
export async function signObject<T extends object>(obj: T, kp: KeyPair, created?: string, verificationMethod?: string): Promise<T & { proof: Proof }> {
  return { ...obj, proof: await signProof(obj, kp, created, verificationMethod) };
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
  // EIP-2: only the low-s form. The high-s twin recovers the same address, so it would give one signed object a second hash.
  if (BigInt("0x" + toHex(sig.slice(32, 64))) > secp256k1.Point.Fn.ORDER / 2n) throw new Error("signature s is in the upper half");
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

/** The successor's unsigned seq 1 Entity Document: `prev` re-keyed, aliases dropped (their proofs name the old EID), `continuity.previous` set. */
export function successorDocument(prev: Record<string, any>, next: KeyPair, created: string = nowSeconds()): Record<string, any> {
  const { proof: _p, aliases: _a, ...d } = structuredClone(prev);
  return {
    ...d,
    eid: next.did,
    keys: [{ id: verificationMethodId(next.did), type: "Multikey", publicKeyMultibase: next.did.slice("did:key:".length) }],
    created,
    updated: created,
    seq: 1,
    continuity: { ...d.continuity, previous: prev.eid },
  };
}

/** A Continuity Link signed by both keys (spec 9.2) plus the successor's document signed by the successor: the body of `POST /v1/continuity`. */
export async function buildRotation(
  previous: KeyPair,
  successor: KeyPair,
  document: Record<string, any>,
  o: { basis?: "rotation" | "migration"; created?: string; nonce?: string } = {},
): Promise<{ link: Record<string, any>; document: Record<string, any> }> {
  const created = o.created ?? nowSeconds();
  const body = { spec: SPEC, type: "ContinuityLink", previous: previous.did, successor: successor.did, basis: o.basis ?? "rotation", created, nonce: o.nonce ?? randomNonce() };
  const link = { ...body, proofs: [await signProof(body, previous, created), await signProof(body, successor, created)] };
  return { link, document: await signObject(document, successor, created) };
}

/**
 * Rotate `previous` to a new key in one call: fetch the current document, build and sign the link, mint the stamp for the
 * successor and submit. Nothing is persisted: on success the caller saves `successor` (its `privateJwk`) and only then retires
 * the old key. Throws on any non-2xx answer.
 */
export async function rotate(o: { previous: KeyPair; registry?: string; successor?: KeyPair; basis?: "rotation" | "migration" }) {
  const registry = (o.registry ?? "https://openentity.org").replace(/\/+$/, "");
  const call = async (path: string, init?: RequestInit) => {
    const r = await fetch(registry + path, init);
    const text = await r.text();
    if (!r.ok) throw new Error(`registry ${r.status} for ${path}: ${text.slice(0, 200)}`);
    return JSON.parse(text);
  };
  const next = o.successor ?? (await generateKeyPair());
  const prevDoc = await call(`/v1/entities/${o.previous.did}/document`);
  const { link, document } = await buildRotation(o.previous, next, successorDocument(prevDoc, next), { basis: o.basis });
  const { stamp_bits } = await call("/v1/spec");
  const response = await call("/v1/continuity", {
    method: "POST",
    headers: { "content-type": "application/json", "x-oe-stamp": await mintStamp(stamp_bits, next.did) },
    body: JSON.stringify({ link, document }),
  });
  return { successor: next, link, document, response };
}

/** sha256 hex of the canonical entry INCLUDING its proof: the next entry's `prev` (spec 7.4). */
export async function recordEntryHash(entry: object): Promise<string> {
  return sha256Hex(canonicalize(entry));
}

type ObjectType =
  | "EntityDocument"
  | "Declaration"
  | "Withdrawal"
  | "Redaction"
  | "RecordEntry"
  | "Attestation"
  | "Revocation"
  | "ContinuityLink"
  | "Dispute"
  | "Presentation"
  | "LogLeaf";
const BUNDLE_ID = "https://openentity.org/spec/1.0.json";
const MAX_BYTES: Record<string, number> = { RecordEntry: 16 * 1024 };
const validators = new Map<string, Validator>();

/** Schema check (spec Appendix A) plus size caps: 16 KB for a RecordEntry (7.4), 64 KB for anything else (5.2). */
export function validate(type: ObjectType, obj: unknown): { ok: boolean; errors: string[] } {
  if (!Object.hasOwn(bundle.$defs, type)) return { ok: false, errors: [`unknown object type ${type}`] };
  let bytes: number;
  try {
    bytes = utf8(canonicalize(obj)).length;
  } catch (e) {
    return { ok: false, errors: [(e as Error).message] };
  }
  const max = MAX_BYTES[type] ?? 64 * 1024;
  if (bytes > max) return { ok: false, errors: [`${type} is ${bytes} bytes, max ${max}`] };
  const num = badNumber(obj);
  if (num) return { ok: false, errors: [num] };
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
  // Random start so two stamps for the same EID in the same second differ (registries reject reuse).
  for (let n = crypto.getRandomValues(new Uint32Array(1))[0]; ; n++) {
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

// ---------- presentations (spec 4.7) ----------

/** Sign a proof of control of `kp`'s EID for one audience and one verifier-issued nonce, optionally carrying attestations. */
export async function buildPresentation(kp: KeyPair, opts: { audience: string; nonce: string; attestations?: object[] }): Promise<object> {
  const created = nowSeconds();
  return signObject({ spec: SPEC, type: "Presentation", eid: kp.did, audience: opts.audience, nonce: opts.nonce, created, ...(opts.attestations?.length ? { attestations: opts.attestations } : {}) }, kp, created);
}

type AttestationCheck = { claim_type?: string; issuer?: string; ok: boolean; error?: string };

/**
 * Check a presentation the verifier asked for: schema, signature by the EID itself, audience, nonce, freshness (5 minutes).
 * Each carried attestation is checked for subject, expiry and its issuer's signature; revocation needs the issuer or a
 * registry and is the caller's to check when online. `ok` covers the presentation; attestations are reported one by one.
 */
export async function verifyPresentation(
  p: any,
  opts: { audience: string; nonce: string; now?: Date; maxAgeSeconds?: number; resolver?: Resolver },
): Promise<{ ok: boolean; eid?: string; errors: string[]; attestations: AttestationCheck[] }> {
  const errors: string[] = [];
  const v = validate("Presentation", p);
  if (!v.ok) return { ok: false, errors: v.errors, attestations: [] };
  const eid = normalizeEid(p.eid), now = (opts.now ?? new Date()).getTime();
  const sig = await verifyObject(p, opts.resolver);
  if (!sig.ok || normalizeEid(sig.signer ?? "") !== eid) errors.push(`signature: ${sig.error ?? `signed by ${sig.signer}, not ${eid}`}`);
  if (p.audience !== opts.audience) errors.push(`audience is ${p.audience}, expected ${opts.audience}`);
  if (p.nonce !== opts.nonce) errors.push("nonce does not match the one issued");
  const age = (now - Date.parse(p.created)) / 1000;
  if (!(age <= (opts.maxAgeSeconds ?? 300) && age >= -60)) errors.push("presentation is not fresh");
  const attestations: AttestationCheck[] = [];
  for (const a of p.attestations ?? []) {
    const c: AttestationCheck = { claim_type: a.claim_type, issuer: a.issuer, ok: false };
    if (normalizeEid(String(a.subject)) !== eid) c.error = "subject is not the presenting entity";
    else if (Date.parse(a.expires) <= now) c.error = "expired";
    else {
      const r = await verifyObject(a, opts.resolver);
      if (!r.ok || normalizeEid(r.signer ?? "") !== normalizeEid(String(a.issuer))) c.error = `issuer signature: ${r.error ?? `signed by ${r.signer}`}`;
      else c.ok = true;
    }
    attestations.push(c);
  }
  return { ok: errors.length === 0, eid, errors, attestations };
}

// ---------------------------------------------------------------- A2A Agent Card (spec 11.2)

export const A2A_EXTENSION_URI = "https://openentity.org/spec/1.0";

/** The AgentExtension entry that carries an EID in an A2A Agent Card's `capabilities.extensions`. */
export function a2aExtension(eid: string, documentUrl: string) {
  return { uri: A2A_EXTENSION_URI, description: "Open Entity identity (OEIS-1) of this agent", required: false, params: { eid, document: documentUrl } };
}

/** A full A2A AgentCard for an Entity Document: each capability slug becomes a skill. `url` is the agent's A2A endpoint. */
export function agentCard(doc: { eid: string; name: string; description: string; capabilities?: string[] }, opts: { url: string; documentUrl: string; version?: string }) {
  return {
    name: doc.name,
    description: doc.description,
    url: opts.url,
    version: opts.version ?? "1.0.0",
    capabilities: { streaming: false, pushNotifications: false, extensions: [a2aExtension(doc.eid, opts.documentUrl)] },
    defaultInputModes: ["text/plain"],
    defaultOutputModes: ["text/plain"],
    skills: (doc.capabilities ?? []).map((slug) => {
      const [ns, name] = slug.includes(":") ? slug.split(":", 2) : [undefined, slug];
      return { id: slug, name: name.replace(/[-.]/g, " "), description: `Self-declared capability: ${slug}`, tags: ns ? [ns, name] : [name] };
    }),
  };
}

// ---------------------------------------------------------------- issuer helpers (ADR 0003)

const MAX_TTL_S = 365 * 86400; // spec 8.4
const ts = (ms: number) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, "Z");
type IssuerOpts = { issuer?: string; keyId?: string; now?: Date };
/** A did:web issuer names `<issuer>#<keyId>`, the key `buildDidDocument` publishes; a did:key signer needs neither. */
const issuerMethod = (kp: KeyPair, o: IssuerOpts) => (o.issuer && o.issuer !== kp.did ? `${o.issuer}#${o.keyId ?? "key-1"}` : undefined);

/** A signed Attestation (spec 8.2). `ttlSeconds` defaults to 90 days and is capped at one year. */
export async function signAttestation(
  kp: KeyPair,
  o: IssuerOpts & { subject: string; claimType: string; claim: object; evidence?: object; confidence?: number; ttlSeconds?: number },
) {
  const ttl = o.ttlSeconds ?? 90 * 86400;
  if (!(ttl > 0 && ttl <= MAX_TTL_S)) throw new Error("ttlSeconds must be positive and at most 1 year");
  const t = (o.now ?? new Date()).getTime();
  const created = ts(t);
  return signObject(
    { spec: SPEC, type: "Attestation", issuer: o.issuer ?? kp.did, subject: o.subject, claim_type: o.claimType, claim: o.claim,
      ...(o.evidence ? { evidence: o.evidence } : {}), ...(o.confidence !== undefined ? { confidence: o.confidence } : {}),
      created, expires: ts(t + ttl * 1000) },
    kp, created, issuerMethod(kp, o),
  );
}

/** A signed Revocation naming the attestation (the object, or its SHA-256 hex) (spec 8.4). */
export async function signRevocation(kp: KeyPair, attested: object | string, o: IssuerOpts & { reason?: string } = {}) {
  const created = ts((o.now ?? new Date()).getTime());
  return signObject(
    { spec: SPEC, type: "Revocation", issuer: o.issuer ?? kp.did, attestation_sha256: typeof attested === "string" ? attested : await sha256Hex(canonicalize(attested)),
      ...(o.reason ? { reason: o.reason } : {}), created },
    kp, created, issuerMethod(kp, o),
  );
}

const multikey = (publicKey: Uint8Array) => didKeyFromPublicKey(publicKey).slice("did:key:".length);

/** The body of `https://<domain>/.well-known/did.json` for a did:web issuer. */
export function buildDidDocument(did: string, publicKey: Uint8Array, keyId = "key-1") {
  const vm = `${did}#${keyId}`;
  return {
    "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
    id: did,
    verificationMethod: [{ id: vm, type: "Multikey", controller: did, publicKeyMultibase: multikey(publicKey) }],
    assertionMethod: [vm],
    authentication: [vm],
  };
}

/** The unsigned body of `https://<domain>/.well-known/openentity.json`: the domain alias proof (spec 3.4) and, under
 * `extensions["openentity:observer"]`, an observer's methodology (spec 8.4). */
export function buildOpenEntityJson(did: string, publicKey: Uint8Array, o: { name: string; description: string; keyId?: string; operator?: object; extensions?: object }) {
  return {
    spec: SPEC, eid: did, name: o.name, description: o.description,
    keys: [{ id: `${did}#${o.keyId ?? "key-1"}`, type: "Multikey", publicKeyMultibase: multikey(publicKey) }],
    operator: o.operator ?? { kind: "organization", name: o.name, custody: "operator", can_change: [] },
    ...(o.extensions ? { extensions: o.extensions } : {}),
  };
}

// ---------------------------------------------------------------- adopt with a client label

/** The registry's allowlist for the unsigned `client` label on POST /v1/adopt. */
export const CLIENTS = ["adk", "goose", "langchain", "ui-tars", "cli", "other"] as const;
export type Client = (typeof CLIENTS)[number];

async function registryJson(url: string, init?: RequestInit): Promise<any> {
  const r = await fetch(url, init);
  const text = await r.text();
  if (!r.ok) throw new Error(`registry ${r.status} for ${url}: ${text.slice(0, 200)}`);
  return JSON.parse(text);
}

/** Adopt `kp` on a registry: document, Declaration and the seq-1 declaration entry (spec 5.2, 6.2, 7.3). `client` is not signed. */
export async function adopt(kp: KeyPair, o: { name: string; description?: string; registry?: string; client?: Client }) {
  if (o.client && !CLIENTS.includes(o.client)) throw new Error(`client must be one of ${CLIENTS.join(", ")}`);
  const registry = (o.registry ?? "https://openentity.org").replace(/\/+$/, "");
  const created = nowSeconds();
  const document = await signObject(
    buildDocument({ kp, name: o.name, description: o.description ?? "An Open Entity adopted through the TypeScript SDK.", created,
      extra: { declaration: { version: DECLARATION_VERSION, sha256: DECLARATION_SHA256, url: `${registry}/v1/entities/${kp.did}/declaration` } } }),
    kp, created);
  const declaration = await signObject(buildDeclaration({ eid: kp.did, name: o.name, created }), kp, created);
  const { stamp_bits } = await registryJson(`${registry}/v1/spec`);
  const post = async (path: string, body: object) =>
    registryJson(registry + path, { method: "POST", headers: { "content-type": "application/json", "x-oe-stamp": await mintStamp(stamp_bits, kp.did) }, body: JSON.stringify(body) });
  const response = await post("/v1/adopt", { document, declaration, ...(o.client ? { client: o.client } : {}) });
  const at = nowSeconds();
  const entry = await signObject({ spec: SPEC, type: "RecordEntry", eid: kp.did, seq: 1, prev: null, kind: "declaration", at,
    payload: { declaration_version: DECLARATION_VERSION, sha256: await sha256Hex(canonicalize(declaration)) } }, kp, at);
  // The registry never writes entries; on failure the signed entry is returned so the caller can push it later.
  const recordPushed = await post(`/v1/entities/${kp.did}/record`, { entries: [entry] }).then(() => true, () => false);
  return { response, did: kp.did, document, declaration, recordEntry: entry, recordPushed };
}

// ---------------------------------------------------------------- trust(eid): one TrustReport from registry reads (ADR 0002)

const MOLTBOTDEN = "did:web:moltbotden.com", CLAWGRC = "did:web:api.clawgrc.com";
const SMA = ["did:web:securemyagent.ai", "did:pkh:eip155:8453:0x62fef02E2859726EC1c0B534853Ad2cdd5FdDE1a"];
const TIER = "trust_tier", POSTURE = "custom:securemyagent:security_posture", VIOLATION = "custom:clawgrc:violation";
/** claim_type to the issuers whose attestations are read; everything else is ignored. */
const ACCEPT: Record<string, string[]> = { [TIER]: [MOLTBOTDEN, CLAWGRC], [POSTURE]: SMA, [VIOLATION]: [CLAWGRC] };
const TRUST_CACHE_MS = 300_000;

export interface TrustReport {
  eid: string;
  /** false: a read failed or a signature did not verify. Treat the entity as untrusted. */
  ok: boolean;
  error?: string;
  level?: string;
  withdrawn: boolean;
  /** issuer DID to its newest live tier (0 to 4) */
  trustTier: Record<string, number>;
  /** claim of the newest live custom:securemyagent:security_posture */
  securityPosture: Record<string, any> | null;
  /** live custom:clawgrc:violation */
  violations: { issuer: string; severity: string; policy: string; observed_at: string; sha256: string }[];
  /** verified revocations of the accepted attestations */
  revocations: { sha256: string; claim_type: string; issuer: string; reason?: string; at: string }[];
}
type FetchJson = (url: string) => Promise<any>;
const trustCache = new Map<string, { at: number; report: TrustReport }>();
export const clearTrustCache = () => trustCache.clear();

/** did:web through /.well-known/did.json (or <path>/did.json); everything else offline. */
export function didWebResolver(fetchJson: FetchJson = registryJson): Resolver {
  return async (did) => {
    if (!did.startsWith("did:web:")) return defaultResolver(did);
    const [host, ...path] = did.slice(8).split(":").map(decodeURIComponent);
    const doc = await fetchJson(`https://${host}/${path.length ? path.join("/") : ".well-known"}/did.json`);
    if (doc.id !== did) throw new Error(`${did} document names ${doc.id}`);
    const ed25519: Uint8Array[] = [];
    for (const vm of doc.verificationMethod ?? []) {
      try {
        ed25519.push(publicKeyFromDidKey("did:key:" + vm.publicKeyMultibase));
      } catch {
        /* not an Ed25519 Multikey */
      }
    }
    return { ed25519 };
  };
}

/**
 * One TrustReport from `GET /v1/entities/{eid}` and `/attestations` only. Every attestation and revocation from the accepted
 * issuers is verified locally against the issuer's key; any failure returns an untrusted report. Cached for 5 minutes.
 */
export async function trust(eid: string, o: { registry?: string; now?: Date; fetchJson?: FetchJson; resolver?: Resolver } = {}): Promise<TrustReport> {
  const registry = (o.registry ?? "https://openentity.org").replace(/\/+$/, "");
  const key = `${registry} ${eid}`, hit = trustCache.get(key);
  if (hit && Date.now() - hit.at < TRUST_CACHE_MS) return hit.report;
  try {
    const report = await readTrust(eid, registry, (o.now ?? new Date()).getTime(), o.fetchJson ?? registryJson, o.resolver ?? didWebResolver(o.fetchJson));
    trustCache.set(key, { at: Date.now(), report });
    return report;
  } catch (e) { // fail closed on anything: network, registry, schema, signature
    return { eid, ok: false, error: (e as Error).message, withdrawn: false, trustTier: {}, securityPosture: null, violations: [], revocations: [] };
  }
}

async function readTrust(eid: string, base: string, now: number, get: FetchJson, resolver: Resolver): Promise<TrustReport> {
  if (!eid.startsWith("did:")) throw new Error("eid must be a DID");
  const ent = await get(`${base}/v1/entities/${eid}`);
  if (ent.eid !== eid) throw new Error(`registry answered for ${ent.eid}`);
  const rows: any[] = (await get(`${base}/v1/entities/${eid}/attestations`)).attestations;
  const report: TrustReport = { eid, ok: true, level: ent.level, withdrawn: !!ent.withdrawn, trustTier: {}, securityPosture: null, violations: [], revocations: [] };
  for (const r of [...rows].sort((x, y) => (y.attestation.created > x.attestation.created ? 1 : -1))) {
    const a = r.attestation, ct: string = a.claim_type;
    if (!(ACCEPT[ct] ?? []).some((i) => i.toLowerCase() === String(a.issuer).toLowerCase())) continue;
    if (r.inherited_from && ct !== VIOLATION) continue; // a rotation does not carry positive claims; a strike follows the entity
    const sha: string = r.sha256;
    if (a.subject !== (r.inherited_from ?? eid) || (await sha256Hex(canonicalize(a))) !== sha) throw new Error(`attestation ${sha} does not match what the registry served`);
    const v = await verifyObject(a, resolver);
    if (!v.ok || v.signer !== a.issuer) throw new Error(`attestation ${sha}: ${v.error ?? `signed by ${v.signer}`}`);
    const rv = r.revocation;
    if (rv) {
      const rvv = await verifyObject(rv, resolver);
      if (!rvv.ok || rvv.signer !== a.issuer || rv.attestation_sha256 !== sha) throw new Error(`revocation of ${sha}: ${rvv.error ?? `signed by ${rvv.signer}`}`);
      report.revocations.push({ sha256: sha, claim_type: ct, issuer: a.issuer, reason: rv.reason, at: rv.created });
    } else if (r.revoked_at) throw new Error(`registry reports a revocation of ${sha} it does not carry`);
    if (rv || Date.parse(a.expires) <= now) continue;
    const c = a.claim;
    if (ct === TIER) report.trustTier[a.issuer] ??= c.tier;
    else if (ct === POSTURE) report.securityPosture ??= c;
    else report.violations.push({ issuer: a.issuer, severity: c.severity, policy: c.policy, observed_at: c.observed_at, sha256: sha });
  }
  return report;
}

// ---------------------------------------------------------------- RFC 9421 HTTP message signatures
// Profile: ed25519, keyid = the signer's did:key, covered ("@method" "@target-uri" "content-digest"), label sig1.

export class HttpSigError extends Error {
  code: string;
  constructor(code: string) {
    super(code);
    this.code = code;
    this.name = "HttpSigError";
  }
}
const HTTPSIG_SKEW = 5; // seconds of clock skew allowed on `created`
const contentDigest = (body: Uint8Array): string => `sha-256=:${b64(sha256Sync(body))}:`;
export function httpSigBase(method: string, url: string, components: string[], digest: string | undefined, params: string): Uint8Array {
  const value: Record<string, string | undefined> = { "@method": method.toUpperCase(), "@target-uri": url, "content-digest": digest };
  return utf8([...components.map((c) => `"${c}": ${value[c]}`), `"@signature-params": ${params}`].join("\n"));
}

/** Sign a request. `privateKey` is a KeyPair or a 32-byte Ed25519 seed. Returns Signature-Input, Signature and, for a non-empty body, Content-Digest. */
export async function signRequest(o: {
  method: string; url: string; body?: Uint8Array; privateKey: KeyPair | Uint8Array; did: string;
  created?: number; expiresIn?: number; nonce?: string;
}): Promise<Record<string, string>> {
  const seed = o.privateKey instanceof Uint8Array ? o.privateKey : unb64url(o.privateKey.privateJwk.d!);
  const created = o.created ?? Math.floor(Date.now() / 1000);
  const nonce = o.nonce ?? b64url(crypto.getRandomValues(new Uint8Array(16)));
  const out: Record<string, string> = {};
  const comps = ["@method", "@target-uri"];
  if (o.body?.length) {
    out["Content-Digest"] = contentDigest(o.body);
    comps.push("content-digest");
  }
  const params = `(${comps.map((c) => `"${c}"`).join(" ")});created=${created};expires=${created + (o.expiresIn ?? 60)};nonce="${nonce}";keyid="${o.did}";alg="ed25519"`;
  const sig = ed25519.sign(httpSigBase(o.method, o.url, comps, out["Content-Digest"], params), seed);
  out["Signature-Input"] = `sig1=${params}`;
  out["Signature"] = `sig1=:${b64(sig)}:`;
  return out;
}

/** Verify a request signed by signRequest. Throws HttpSigError with `.code`. Nonce replay tracking is the caller's job. */
export async function verifyRequest(o: {
  method: string; url: string; headers: Record<string, string>; body?: Uint8Array; now?: number; maxAge?: number;
}): Promise<{ did: string; keyid: string; created: number; expires: number; nonce: string }> {
  const fail = (code: string): never => { throw new HttpSigError(code); };
  const h = Object.fromEntries(Object.entries(o.headers).map(([k, v]) => [k.toLowerCase(), v]));
  const maxAge = o.maxAge ?? 300;
  const body = o.body ?? new Uint8Array();
  if (!h["signature-input"] || !h["signature"]) fail("missing_headers");
  const m = /(?:^|,)\s*sig1=(\(([^)]*)\)((?:;[a-z]+=(?:\d+|"[^"]*"))*))/.exec(h["signature-input"]);
  const s = /(?:^|,)\s*sig1=:([A-Za-z0-9+/]+={0,2}):/.exec(h["signature"]);
  if (!m || !s) return fail("missing_headers");
  const params = m[1];
  const comps = [...m[2].matchAll(/"([^"]*)"/g)].map((x) => x[1]);
  const p: Record<string, string | number> = {};
  for (const [, k, v] of m[3].matchAll(/;([a-z]+)=(\d+|"[^"]*")/g)) p[k] = v.startsWith('"') ? v.slice(1, -1) : Number(v);
  if (p.alg !== "ed25519") fail("unknown_alg");
  const keyid = String(p.keyid ?? "");
  let pub: Uint8Array;
  try {
    pub = publicKeyFromDidKey(keyid);
    if (didKeyFromPublicKey(pub) !== keyid) throw 0;
  } catch { return fail("bad_keyid"); }
  if (typeof p.created !== "number" || typeof p.expires !== "number") fail("missing_headers");
  const created = p.created as number, expires = p.expires as number;
  const nonce = String(p.nonce ?? "");
  if (nonce.length < 22) fail("missing_nonce"); // 16 bytes in base64url
  if (comps[0] !== "@method" || comps[1] !== "@target-uri" || comps.length > 3 || (comps.length === 3 && comps[2] !== "content-digest")) fail("missing_headers");
  let digest: string | undefined;
  if (body.length || comps.includes("content-digest")) {
    digest = h["content-digest"];
    if (!comps.includes("content-digest") || digest !== contentDigest(body)) fail("digest_mismatch");
  }
  const now = o.now ?? Math.floor(Date.now() / 1000);
  if (created > now + HTTPSIG_SKEW) fail("created_in_future");
  if (now - created > maxAge) fail("created_too_old");
  if (expires < now) fail("expired");
  if (expires - created > maxAge) fail("lifetime_too_long");
  let ok = false;
  try { ok = ed25519.verify(unb64(s[1]), httpSigBase(o.method, o.url, comps, digest, params), pub); } catch { /* malformed signature */ }
  if (!ok) fail("bad_signature");
  return { did: keyid, keyid, created, expires, nonce };
}
