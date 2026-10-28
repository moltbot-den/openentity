import dns from "node:dns/promises";
import { EventEmitter } from "node:events";
import https from "node:https";
import { Readable } from "node:stream";
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { vi } from "vitest";
import { app } from "../src/index.ts";
import { pgliteDb } from "../src/db.ts";
import { memoryBlobs } from "../src/blob.ts";
import { base58btcEncode, buildDeclaration, buildDocument, canonicalize, generateKeyPair, nowSeconds, randomNonce, sha256, signObject, type KeyPair, type Proof } from "../src/sdk.ts";
import type { Env } from "../src/env.ts";

// One fresh database per test file, and fresh throwaway keys per run; nothing secret is committed.
export const E: Env = {
  db: await pgliteDb(), log: memoryBlobs(), snapshots: memoryBlobs(),
  STAMP_BITS: "8", REGISTRY_HOST: "openentity.org", BASE_RPC_URL: "https://rpc.test",
  REGISTRY_KEY_JWK: JSON.stringify(generateKeyPairSync("ed25519").privateKey.export({ format: "jwk" })),
  CUSTODY_KEY: randomBytes(32).toString("base64"), HASH_SALT: "test-salt",
  WRITE_PER_MINUTE: "100000", // the suite writes from one IP faster than the published limit; a test covers the limit
};

export async function call(method: string, path: string, body?: unknown, headers: Record<string, string> = {}, e: Env = E) {
  const res = await app.request(`https://openentity.org/v1${path}`, {
    method, headers: { "content-type": "application/json", ...headers },
    body: body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body),
  }, e);
  const text = await res.text();
  let json: any = null;
  try { json = JSON.parse(text); } catch { /* not JSON */ }
  return { status: res.status, body: json, text };
}
/** 8-bit stamp with a random nonce: the SDK's mintStamp is deterministic per (eid, second) and the registry accepts each stamp once. */
export async function freshStamp(eid: string): Promise<string> {
  for (;;) {
    const h = `1:8:${nowSeconds()}:${eid}:${randomNonce()}`;
    if (new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(h)))[0] === 0) return h;
  }
}
export const stamp = async (eid: string) => ({ "x-oe-stamp": await freshStamp(eid) });
export const write = async (method: string, path: string, eid: string, body: unknown) => call(method, path, body, await stamp(eid));

export const later = (s: number) => new Date(Date.now() + s * 1000).toISOString().replace(/\.\d+Z$/, "Z");

export async function signed(kp: KeyPair, name = "Test Entity", extra: object = {}) {
  const document = await signObject({ ...buildDocument({ kp, name, description: "A test entity." }), ...extra }, kp);
  const declaration = await signObject(buildDeclaration({ eid: kp.did, name }), kp);
  return { document, declaration };
}
export async function adopted(name = "Test Entity", extra: object = {}) {
  const kp = await generateKeyPair();
  const objs = await signed(kp, name, extra);
  const res = await write("POST", "/adopt", kp.did, objs);
  if (res.status !== 201) throw new Error(JSON.stringify(res.body));
  return { kp, ...objs, res: res.body };
}
export { nowSeconds };

/** eddsa-jcs-2022 proof under an arbitrary verification method (for did:web signers). */
export async function signAs(obj: object, kp: KeyPair, verificationMethod: string): Promise<Proof> {
  const { proof: _p, proofs: _ps, ...rest } = obj as Record<string, unknown>;
  const config = { type: "DataIntegrityProof", cryptosuite: "eddsa-jcs-2022", created: nowSeconds(), verificationMethod, proofPurpose: "assertionMethod" };
  const input = Uint8Array.from([...(await sha256(canonicalize(config))), ...(await sha256(canonicalize(rest)))]);
  const sig = new Uint8Array(await crypto.subtle.sign("Ed25519", kp.privateKey, input));
  return { ...config, proofValue: "z" + base58btcEncode(sig) };
}

/** A did:web document publishing one Ed25519 key. */
export const didWebDoc = (domain: string, kp: KeyPair) => ({
  id: `did:web:${domain}`, verificationMethod: [{ id: `did:web:${domain}#k`, type: "Multikey", controller: `did:web:${domain}`, publicKeyMultibase: kp.did.slice(8) }],
});

/** Routes outbound https GETs by URL substring; unmatched URLs get a 404. The fake connects the way node does: through the request's `lookup` option, else a fresh dns lookup. */
export function mockFetch(routes: Record<string, (req: Request) => unknown>, dnsAnswers: Record<string, string> = {}) {
  // Every host resolves to a public address unless the test says otherwise (see the SSRF guard in aliases.ts).
  vi.spyOn(dns, "lookup").mockImplementation((async (host: string) => { const address = dnsAnswers[host] ?? "93.184.216.34"; return [{ address, family: address.includes(":") ? 6 : 4 }]; }) as any);
  const connected: string[] = [];
  const spy = vi.spyOn(https, "request").mockImplementation(((url: URL, opts: any, cb: (res: any) => void) => {
    const req: any = new EventEmitter();
    req.end = () => void (async () => {
      const [{ address }] = opts.lookup ? await new Promise<any[]>((ok) => opts.lookup(url.hostname, { all: true }, (_e: unknown, a: any[]) => ok(a))) : await dns.lookup(url.hostname, { all: true });
      connected.push(address);
      let status = 404, body = "not found";
      for (const [k, f] of Object.entries(routes)) if (url.href.includes(k)) { const r = await f(new Request(url.href, { headers: opts.headers })); const res = r instanceof Response ? r : Response.json(r); status = res.status; body = await res.text(); break; }
      const res: any = Readable.from([Buffer.from(body)]);
      res.statusCode = status;
      cb(res);
    })();
    return req;
  }) as any);
  // The operator-configured Base RPC (not a writer-chosen host) still goes through global fetch.
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
    const req = new Request(input as RequestInfo, init);
    for (const [k, f] of Object.entries(routes)) if (req.url.includes(k)) { const r = await f(req); return r instanceof Response ? r : Response.json(r); }
    return new Response("not found", { status: 404 });
  });
  return Object.assign(spy, { connected });
}
