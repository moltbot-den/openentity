import { createExecutionContext, env } from "cloudflare:test";
import { vi } from "vitest";
import { app } from "../src/index.ts";
import { base58btcEncode, buildDeclaration, buildDocument, canonicalize, generateKeyPair, nowSeconds, randomNonce, sha256, signObject, type KeyPair, type Proof } from "../src/sdk.ts";
import type { Env } from "../src/env.ts";

export const E = env as unknown as Env;

export async function call(method: string, path: string, body?: unknown, headers: Record<string, string> = {}, e: Env = E) {
  const res = await app.request(`https://openentity.org/v1${path}`, {
    method, headers: { "content-type": "application/json", ...headers },
    body: body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body),
  }, e, createExecutionContext());
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

/** Routes outbound fetches by URL substring; unmatched URLs get a 404. */
export function mockFetch(routes: Record<string, (req: Request) => unknown>) {
  return vi.spyOn(globalThis, "fetch").mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
    const req = new Request(input as RequestInfo, init);
    for (const [k, f] of Object.entries(routes)) if (req.url.includes(k)) { const r = await f(req); return r instanceof Response ? r : Response.json(r); }
    return new Response("not found", { status: 404 });
  });
}
