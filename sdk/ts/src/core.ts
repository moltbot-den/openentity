import { OpenEntityError } from "./errors.ts";
import { ts } from "./objects.ts";
import { split } from "./merkle.ts";
import { adopt } from "./registry.ts";
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

/** @internal */
export const enc = new TextEncoder();
/** @internal */
export const utf8 = (s: string | Uint8Array): Uint8Array => (typeof s === "string" ? enc.encode(s) : s);
/** @internal */
export const toHex = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
/** @internal */
export const fromHex = (h: string): Uint8Array => {
  if (h.length % 2 || /[^0-9a-fA-F]/.test(h)) throw new OpenEntityError("invalid_input", "invalid hex");
  return Uint8Array.from(h.match(/../g) ?? [], (x) => parseInt(x, 16));
};
/** @internal */
export const concat = (...parts: Uint8Array[]): Uint8Array => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) (out.set(p, o), (o += p.length));
  return out;
};
/** @internal */
export const equal = (a: Uint8Array, b: Uint8Array): boolean => a.length === b.length && a.every((x, i) => x === b[i]);
/** @internal */
export const b64 = (b: Uint8Array): string => btoa(String.fromCharCode(...b));
/** @internal */
export const unb64 = (s: string): Uint8Array => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
/** @internal */
export const b64url = (b: Uint8Array): string => b64(b).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
/** @internal */
export const unb64url = (s: string): Uint8Array => unb64(s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4));

/** RFC 8785 (JCS) canonical form. Throws on values JSON cannot represent. */
export function canonicalize(obj: unknown): string {
  const s = jcs(obj);
  if (s === undefined) throw new OpenEntityError("invalid_input", "value has no canonical JSON form");
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
        if (scopes[scopes.length - 1].has(key)) throw new OpenEntityError("invalid_input", `duplicate key ${m}`);
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

/** Spec 4.3: numbers are integers or decimal fractions with at most 6 decimal places. @internal */
export function badNumber(v: unknown): string | null {
  if (typeof v === "number") return Number.isFinite(v) && Number(v.toFixed(6)) === v ? null : `number ${v} has more than 6 decimal places`;
  if (v && typeof v === "object") for (const x of Object.values(v)) { const e = badNumber(x); if (e) return e; }
  return null;
}

/** @internal */
export const sha256Sync = (data: string | Uint8Array): Uint8Array => nobleSha256(utf8(data));
export async function sha256(data: string | Uint8Array): Promise<Uint8Array> {
  return sha256Sync(data);
}
export async function sha256Hex(data: string | Uint8Array): Promise<string> {
  return toHex(sha256Sync(data));
}

/** @internal */
export const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
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
    if (i < 0) throw new OpenEntityError("invalid_input", `invalid base58btc character "${c}"`);
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
    throw new OpenEntityError("invalid_input", "expected an Ed25519 private JWK");
  const publicKey = unb64url(privateJwk.x);
  if (!equal(ed25519.getPublicKey(unb64url(privateJwk.d)), publicKey)) throw new OpenEntityError("invalid_input", "JWK x does not match d");
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
  if (seed32.length !== 32) throw new OpenEntityError("invalid_input", "seed must be 32 bytes");
  return keyPairFromJwk({ kty: "OKP", crv: "Ed25519", d: b64url(seed32), x: b64url(ed25519.getPublicKey(seed32)) });
}

/** @internal */
export const ED25519_MULTICODEC = Uint8Array.of(0xed, 0x01);
export function didKeyFromPublicKey(pk: Uint8Array): string {
  if (pk.length !== 32) throw new OpenEntityError("invalid_input", "Ed25519 public key must be 32 bytes");
  return "did:key:z" + base58btcEncode(concat(ED25519_MULTICODEC, pk));
}
export function publicKeyFromDidKey(did: string): Uint8Array {
  const m = /^did:key:z([1-9A-HJ-NP-Za-km-z]+)$/.exec(did.split("#")[0]);
  if (!m) throw new OpenEntityError("invalid_input", "not a base58btc did:key");
  const b = base58btcDecode(m[1]);
  if (b.length !== 34 || b[0] !== 0xed || b[1] !== 0x01) throw new OpenEntityError("invalid_input", "did:key is not Ed25519");
  return b.slice(2);
}
export function verificationMethodId(did: string): string {
  if (!did.startsWith("did:key:")) throw new OpenEntityError("invalid_input", "verificationMethodId is defined for did:key only");
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
/** @internal */
export type VerifyResult = { ok: boolean; signer?: string; error?: string };

/** @internal */
export const defaultResolver: Resolver = async (did) => {
  if (did.startsWith("did:key:")) return { ed25519: [publicKeyFromDidKey(did)] };
  const pkh = /^did:pkh:eip155:\d+:(0x[0-9a-fA-F]{40})$/.exec(did);
  if (pkh) return { address: pkh[1] };
  throw new OpenEntityError("invalid_input", `cannot resolve ${did.split(":").slice(0, 2).join(":")} offline; pass a resolver`);
};

/** The signed content: the object minus `proof` (and `proofs`, for ContinuityLink). @internal */
export function unsecured(obj: object): object {
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

/** @internal */
export const keccak = (s: string | Uint8Array): Uint8Array => keccak_256(utf8(s));
/** @internal */
export const EIP712_DOMAIN = keccak(
  concat(keccak("EIP712Domain(string name,string version)"), keccak("Open Entity"), keccak("1")),
);
/** @internal */
export const OBJECT_TYPEHASH = keccak("OpenEntityObject(string objectType,bytes32 canonicalHash,string created)");

/** EIP-712 digest of OpenEntityObject{objectType, canonicalHash, created}, domain {name: "Open Entity", version: "1"}. */
export function eip712Digest(objectType: string, canonicalHashHex: string, created: string): Uint8Array {
  const hash = fromHex(canonicalHashHex);
  if (hash.length !== 32) throw new OpenEntityError("invalid_input", "canonicalHash must be 32 bytes");
  const struct = keccak(concat(OBJECT_TYPEHASH, keccak(objectType), hash, keccak(created)));
  return keccak(concat(Uint8Array.of(0x19, 0x01), EIP712_DOMAIN, struct));
}
/** Recovers the EIP-55 checksummed address from a 65-byte r||s||v signature over `digest`. */
export function recoverEip712(digest: Uint8Array, sigHex: string): string {
  const sig = fromHex(sigHex.replace(/^0x/, ""));
  if (sig.length !== 65) throw new OpenEntityError("invalid_input", "signature must be 65 bytes");
  const v = sig[64] >= 27 ? sig[64] - 27 : sig[64];
  if (v > 1) throw new OpenEntityError("invalid_input", "invalid recovery id");
  // EIP-2: only the low-s form. The high-s twin recovers the same address, so it would give one signed object a second hash.
  if (BigInt("0x" + toHex(sig.slice(32, 64))) > secp256k1.Point.Fn.ORDER / 2n) throw new OpenEntityError("invalid_input", "signature s is in the upper half");
  const pub = secp256k1.recoverPublicKey(concat(Uint8Array.of(v), sig.slice(0, 64)), digest, { prehash: false });
  const uncompressed = secp256k1.Point.fromBytes(pub).toBytes(false);
  const addr = toHex(keccak_256(uncompressed.slice(1)).slice(12));
  const h = toHex(keccak(addr));
  return "0x" + [...addr].map((c, i) => (parseInt(h[i], 16) >= 8 ? c.toUpperCase() : c)).join("");
}

