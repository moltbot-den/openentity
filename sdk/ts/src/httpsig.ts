import { HttpSigError } from "./errors.ts";
import { ed25519 } from "@noble/curves/ed25519.js";
import { utf8, b64, unb64, b64url, unb64url, sha256Sync, type KeyPair, didKeyFromPublicKey, publicKeyFromDidKey, didWebUrl } from "./core.ts";
// ---------------------------------------------------------------- RFC 9421 HTTP message signatures
// Profile: ed25519, keyid = the signer's did:key, or `did:web:<host>#<key>` for a did:web signer the verifier allows
// (services such as the OpenEntity Account), covered ("@method" "@target-uri" "content-digest"), label sig1.

/** @internal Ed25519 keys of allowed did:web signers by verification method id, per DID, from its did.json. */
export const didWebKeys = new Map<string, { at: number; keys: Map<string, Uint8Array> }>();
const DID_CACHE_MS = 600_000; // the account service serves did.json with max-age=600
const DID_REFETCH_MS = 30_000; // an unknown key refetches, at most this often per DID

async function didJson(url: string): Promise<unknown> {
  const r = await fetch(url, { redirect: "error", signal: AbortSignal.timeout(5000), headers: { accept: "application/did+json, application/json" } });
  if (!r.ok) throw new Error(`${url} answered ${r.status}`);
  return r.json();
}

/** Ed25519 Multikey and JsonWebKey (OKP) methods of a DID document, by absolute id. */
function ed25519Methods(did: string, doc: any): Map<string, Uint8Array> {
  if (doc?.id !== did) throw new Error(`${did} document names ${doc?.id}`);
  const keys = new Map<string, Uint8Array>();
  for (const vm of Array.isArray(doc.verificationMethod) ? doc.verificationMethod : []) {
    if (typeof vm?.id !== "string") continue;
    try {
      const jwk = vm.publicKeyJwk;
      const key = vm.type === "Multikey" ? publicKeyFromDidKey("did:key:" + vm.publicKeyMultibase)
        : vm.type === "JsonWebKey" && jwk?.kty === "OKP" && jwk.crv === "Ed25519" && b64url(unb64url(jwk.x)) === jwk.x ? unb64url(jwk.x) : undefined;
      if (key?.length === 32) keys.set(vm.id.startsWith("#") ? did + vm.id : vm.id, key);
    } catch { /* not an Ed25519 method */ }
  }
  return keys;
}

async function didWebKey(keyid: string, fetchJson: (url: string) => Promise<unknown>): Promise<Uint8Array | undefined> {
  const did = keyid.split("#")[0];
  const hit = didWebKeys.get(did), age = hit ? Date.now() - hit.at : Infinity;
  if (hit && age < DID_CACHE_MS && (hit.keys.has(keyid) || age < DID_REFETCH_MS)) return hit.keys.get(keyid);
  const keys = ed25519Methods(did, await fetchJson(didWebUrl(did)));
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
 * A did:key keyid verifies offline. A `did:web:<host>#<key>` keyid verifies only when its DID is in `allowDidWeb`: the key comes from
 * the DID's did.json (Ed25519 Multikey or JsonWebKey), cached for ten minutes and refetched when it names an unknown key.
 */
export async function verifyRequest(o: {
  method: string; url: string; headers: Record<string, string>; body?: Uint8Array; now?: number; maxAge?: number;
  allowDidWeb?: string[]; fetchJson?: (url: string) => Promise<unknown>;
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
  const did = keyid.split("#")[0];
  let pub: Uint8Array | undefined;
  if (keyid.startsWith("did:web:")) {
    // Allowed DIDs only, so a request never makes the verifier fetch a URL of the sender's choosing.
    if (!/#[^#]+$/.test(keyid) || !(o.allowDidWeb ?? []).includes(did)) fail("bad_keyid");
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
  let ok = false;
  try { ok = ed25519.verify(unb64(s[1]), httpSigBase(o.method, o.url, comps, digest, params), pub); } catch { /* malformed signature */ }
  if (!ok) fail("bad_signature");
  return { did, keyid, created, expires, nonce };
}

