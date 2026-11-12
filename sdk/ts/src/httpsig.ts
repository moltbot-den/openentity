import { HttpSigError, OpenEntityError } from "./errors.ts";
import { ed25519 } from "@noble/curves/ed25519.js";
import { utf8, b64, unb64, b64url, unb64url, sha256Sync, type KeyPair, didKeyFromPublicKey, publicKeyFromDidKey, didWebUrl } from "./core.ts";
// ---------------------------------------------------------------- RFC 9421 HTTP message signatures
// Profile: ed25519, keyid = the signer's did:key, or `did:web:<host>#<key>` for a did:web signer the verifier allows
// (services such as the OpenEntity Account), covered ("@method" "@target-uri" "content-digest"), label sig1. A did:web key is an
// Ed25519 method under `authentication` in the DID's did.json. A signed response (the account service's GET /v1/paused answer)
// covers ("@status" "content-digest"), has no nonce, lives at most 60 seconds and always has a did:web keyid.

/** @internal Ed25519 `authentication` keys of allowed did:web signers by verification method id, per DID, from its did.json. */
export const didWebKeys = new Map<string, { at: number; keys: Map<string, Uint8Array> }>();
const DID_CACHE_MS = 600_000; // the account service serves did.json with max-age=600
const DID_REFETCH_MS = 30_000; // an unknown key refetches, at most this often per DID

async function didJson(url: string): Promise<unknown> {
  const r = await fetch(url, { redirect: "error", signal: AbortSignal.timeout(5000), headers: { accept: "application/did+json, application/json" } });
  if (!r.ok) throw new Error(`${url} answered ${r.status}`);
  return r.json();
}

/** @internal Ed25519 keys of a DID document by absolute method id (Ed25519 publicKeyMultibase or OKP publicKeyJwk); with `relationship`, only the methods it references. */
export function ed25519Methods(did: string, doc: any, relationship?: "authentication"): Map<string, Uint8Array> {
  if (doc?.id !== did) throw new OpenEntityError("verification_failed", `${did} document names ${doc?.id}`);
  const abs = (id: unknown) => (typeof id === "string" && id.startsWith("#") ? did + id : id); // "#key-1" is relative to the DID
  const refs = relationship && new Set((Array.isArray(doc[relationship]) ? doc[relationship] : []).map((r: any) => abs(typeof r === "string" ? r : r?.id)));
  const keys = new Map<string, Uint8Array>();
  for (const vm of Array.isArray(doc.verificationMethod) ? doc.verificationMethod : []) {
    const id = abs(vm?.id), jwk = vm?.publicKeyJwk;
    if (typeof id !== "string" || (refs && !refs.has(id))) continue;
    try {
      const key = typeof vm.publicKeyMultibase === "string" ? publicKeyFromDidKey("did:key:" + vm.publicKeyMultibase)
        : jwk?.kty === "OKP" && jwk.crv === "Ed25519" && b64url(unb64url(jwk.x)) === jwk.x ? unb64url(jwk.x) : undefined;
      if (key?.length === 32) keys.set(id, key);
    } catch { /* not an Ed25519 method */ }
  }
  return keys;
}

async function didWebKey(keyid: string, fetchJson: (url: string) => Promise<unknown>): Promise<Uint8Array | undefined> {
  const did = keyid.split("#")[0];
  const hit = didWebKeys.get(did), age = hit ? Date.now() - hit.at : Infinity;
  if (hit && age < DID_CACHE_MS && (hit.keys.has(keyid) || age < DID_REFETCH_MS)) return hit.keys.get(keyid);
  const keys = ed25519Methods(did, await fetchJson(didWebUrl(did)), "authentication");
  didWebKeys.set(did, { at: Date.now(), keys });
  return keys.get(keyid);
}

/** @internal */
export const HTTPSIG_SKEW = 5; // seconds of clock skew allowed on `created`
/** @internal */
export const contentDigest = (body: Uint8Array): string => `sha-256=:${b64(sha256Sync(body))}:`;
export function httpSigBase(method: string, url: string, components: string[], digest: string | undefined, params: string): Uint8Array {
  const value: Record<string, string | undefined> = { "@method": method.toUpperCase(), "@target-uri": url, "content-digest": digest };
  return utf8([...components.map((c) => `"${c}": ${value[c]}`), `"@signature-params": ${params}`].join("\n"));
}

const fail = (code: string): never => { throw new HttpSigError(code); };
const lower = (headers: Record<string, string>) => Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]));

/** The sig1 members of Signature-Input and Signature: the raw parameters, the covered components, the parameters, the signature. */
function sig1(h: Record<string, string>) {
  const m = /(?:^|,)\s*sig1=(\(([^)]*)\)((?:;[a-z]+=(?:\d+|"[^"]*"))*))/.exec(h["signature-input"] ?? "");
  const s = /(?:^|,)\s*sig1=:([A-Za-z0-9+/]+={0,2}):/.exec(h["signature"] ?? "");
  if (!m || !s) return fail("missing_headers");
  const p: Record<string, string | number> = {};
  for (const [, k, v] of m[3].matchAll(/;([a-z]+)=(\d+|"[^"]*")/g)) p[k] = v.startsWith('"') ? v.slice(1, -1) : Number(v);
  if (p.alg !== "ed25519") fail("unknown_alg");
  return { params: m[1], comps: [...m[2].matchAll(/"([^"]*)"/g)].map((x) => x[1]), p, sig: s[1], keyid: String(p.keyid ?? "") };
}

/** A `did:web:<host>#<key>` keyid whose DID is allowed, so a message never makes the verifier fetch a URL of the sender's choosing. */
const allowedDidWeb = (keyid: string, allow: unknown) => /^did:web:[^#]+#[^#]+$/.test(keyid) && Array.isArray(allow) && allow.includes(keyid.split("#")[0]);

const verifies = (sig: string, base: Uint8Array, pub: Uint8Array) => {
  try { return ed25519.verify(unb64(sig), base, pub); } catch { return false; } // malformed signature
};

/** Sign a request. `privateKey` is a KeyPair or an Ed25519 seed. Returns Signature-Input, Signature and, for a non-empty body, Content-Digest. */
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

/**
 * Verify a request signed by signRequest. Throws HttpSigError with `.code`. Nonce replay tracking is the caller's job.
 * A did:key keyid verifies offline. A `did:web:<host>#<key>` keyid verifies only when its DID is in `allowDidWeb`: the key is an
 * Ed25519 method listed under `authentication` in the DID's did.json, cached for ten minutes and refetched when it names an unknown key.
 */
export async function verifyRequest(o: {
  method: string; url: string; headers: Record<string, string>; body?: Uint8Array; now?: number; maxAge?: number;
  allowDidWeb?: string[]; fetchJson?: (url: string) => Promise<unknown>;
}): Promise<{ did: string; keyid: string; created: number; expires: number; nonce: string }> {
  const h = lower(o.headers);
  const maxAge = o.maxAge ?? 300;
  const body = o.body ?? new Uint8Array();
  const { params, comps, p, sig, keyid } = sig1(h);
  const did = keyid.split("#")[0];
  let pub: Uint8Array | undefined;
  if (keyid.startsWith("did:web:")) {
    if (!allowedDidWeb(keyid, o.allowDidWeb)) fail("bad_keyid");
  } else {
    try {
      pub = publicKeyFromDidKey(keyid);
      if (didKeyFromPublicKey(pub) !== keyid) throw 0;
    } catch { return fail("bad_keyid"); }
  }
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
  if (!pub) pub = await didWebKey(keyid, o.fetchJson ?? didJson).catch(() => undefined);
  if (!pub) return fail("bad_keyid");
  if (!verifies(sig, httpSigBase(o.method, o.url, comps, digest, params), pub)) fail("bad_signature");
  return { did, keyid, created, expires, nonce };
}

/**
 * Verify a response signed by a did:web service, such as the OpenEntity Account's signed paused list. Throws HttpSigError with `.code`.
 * The signature covers `"@status"` and `"content-digest"`, lives at most `maxAge` seconds (one minute by default), and its keyid is a
 * `did:web:<host>#<key>` of a DID in `allowDidWeb`, resolved as verifyRequest resolves one.
 */
export async function verifyResponse(o: {
  status: number; headers: Record<string, string>; body: Uint8Array; now?: number; maxAge?: number;
  allowDidWeb: string[]; fetchJson?: (url: string) => Promise<unknown>;
}): Promise<{ did: string; keyid: string; created: number; expires: number }> {
  const h = lower(o.headers);
  const { params, comps, p, sig, keyid } = sig1(h);
  if (!allowedDidWeb(keyid, o.allowDidWeb)) fail("bad_keyid");
  if (typeof p.created !== "number" || typeof p.expires !== "number") fail("missing_headers");
  const created = p.created as number, expires = p.expires as number;
  if (comps.length !== 2 || comps[0] !== "@status" || comps[1] !== "content-digest") fail("missing_headers");
  const digest = h["content-digest"];
  if (digest !== contentDigest(o.body)) fail("digest_mismatch");
  const now = o.now ?? Math.floor(Date.now() / 1000);
  if (created > now + HTTPSIG_SKEW) fail("created_in_future");
  if (expires < now) fail("expired");
  if (expires - created > (o.maxAge ?? 60)) fail("lifetime_too_long");
  const pub = await didWebKey(keyid, o.fetchJson ?? didJson).catch(() => undefined);
  if (!pub) return fail("bad_keyid");
  if (!verifies(sig, utf8(`"@status": ${o.status}\n"content-digest": ${digest}\n"@signature-params": ${params}`), pub)) fail("bad_signature");
  return { did: keyid.split("#")[0], keyid, created, expires };
}
