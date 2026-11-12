// Inbound RFC 9421 signatures (openapi.yaml agentSignature and productSignature), checked with verifyRequest from
// @openentity/sdk. Each (keyid, nonce) is accepted once while the signature is valid (sig_nonces).
import { createHash } from "node:crypto";
import type { Context } from "hono";
import { HttpSigError, verifyRequest } from "@openentity/sdk";
import type { Deps } from "./app.ts";
import { testProductDocument, testProductsOf } from "./approve.ts";
import { now } from "./db.ts";
import { fail } from "./http.ts";
import { PRODUCT_DIDS } from "./wellknown.ts";

export interface SignedRequest { method: string; url: string; headers: Record<string, string>; body?: Uint8Array }

/** did.json of a product signer, fetched with the injected fetch (tests) and never redirected. A staging test product's
 * document is built from its configured key, as /test-products/<name>/did.json serves it. */
const fetchJson = (d: Deps) => async (url: string) => {
  for (const [id, t] of testProductsOf(d)) if (url === `https://${d.host}/test-products/${t.name}/did.json`) return testProductDocument(id, t.key);
  const r = await (d.fetch ?? fetch)(url, { redirect: "error", signal: AbortSignal.timeout(5000), headers: { accept: "application/did+json, application/json" } });
  if (!r.ok) throw new Error(`${url} answered ${r.status}`);
  return r.json();
};

/**
 * Verifies a signed request and spends its nonce. `products` accepts the four product DIDs (did:web keyids, 403
 * unknown_signer for any other signer) and, in staging, the test products (approve.ts TEST_PRODUCTS), each returned as
 * the product it stands in for; otherwise only an agent did:key. Returns the signer DID.
 */
export async function verifySigned(d: Deps, req: SignedRequest, o: { products: boolean }): Promise<{ did: string; keyid: string }> {
  const has = (n: string) => Object.keys(req.headers).some((k) => k.toLowerCase() === n);
  if (!has("signature-input") || !has("signature")) fail(401, "signature_invalid", "missing_headers");
  const tests = o.products ? testProductsOf(d) : new Map();
  let v;
  try {
    // The SDK verifies the sig1 member only; every decision below reads the DID it verified, never the raw header.
    v = await verifyRequest({ ...req, now: now(), maxAge: 300, allowDidWeb: o.products ? [...PRODUCT_DIDS, ...tests.keys()] : [], fetchJson: fetchJson(d) });
  } catch (e) {
    // A did:web keyid outside the allow list is the SDK's bad_keyid: for a product call, a signer that is not a product.
    if (e instanceof HttpSigError && o.products && e.code === "bad_keyid") fail(403, "unknown_signer", "only the four product DIDs sign these calls");
    if (e instanceof HttpSigError) fail(401, "signature_invalid", e.code);
    throw e;
  }
  const test = tests.get(v!.did);
  if (o.products && !PRODUCT_DIDS.includes(v!.did) && !test) fail(403, "unknown_signer", "only the four product DIDs sign these calls");
  if (!o.products && !v!.did.startsWith("did:key:")) fail(401, "signature_invalid", "bad_keyid");
  const key = createHash("sha256").update(`${v!.keyid}|${v!.nonce}`).digest("hex");
  const spent = await d.db.run("INSERT INTO sig_nonces (key, expires_at) VALUES ($1, $2) ON CONFLICT DO NOTHING", [key, v!.expires]);
  if (!spent.changes) fail(401, "signature_replayed", "this signature nonce was already used");
  return { did: test?.as ?? v!.did, keyid: v!.keyid };
}

const fromContext = async (c: Context): Promise<SignedRequest> => {
  const body = new Uint8Array(await c.req.arrayBuffer());
  return { method: c.req.method, url: c.req.url, headers: Object.fromEntries(c.req.raw.headers), body };
};

/** A call from one of the four products (productSignature). */
export async function productSigned(c: Context, d: Deps): Promise<{ did: string }> {
  return { did: (await verifySigned(d, await fromContext(c), { products: true })).did };
}

/** A call from an agent, signed by its did:key (agentSignature). Pairing state is the caller's to check. */
export async function agentSigned(c: Context, d: Deps): Promise<{ did: string }> {
  return { did: (await verifySigned(d, await fromContext(c), { products: false })).did };
}
