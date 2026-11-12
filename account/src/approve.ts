// Web approvals without the phone (PLAN 3.5; openapi /approve, /v1/approve/check, ApproveEnvelope, ApproveCheck).
// A product console sends the owner to /approve#request=<envelope>. The page asks /v1/approve/check to verify the
// envelope against the product's DID document, shows the payload, takes a WebAuthn assertion over the approval/2.0
// digest of the owner's decision and form-posts the Approval2 to return_url. The product verifies the approval itself;
// this service only checks that the request really comes from the product and names an owner it knows.
import { createHash, createPublicKey, verify, type KeyObject } from "node:crypto";
import type { Hono } from "hono";
import { approvalDigest, payloadDigest, publicKeyFromDidKey, type KeyLogState } from "@openentity/sdk";
import type { Deps } from "./app.ts";
import { bump, newId, now } from "./db.ts";
import { bearer, fail, ipOf, json } from "./http.ts";
import { signJwt } from "./keys.ts";
import { keyLogState } from "./keylog.ts";
import { requireApproval } from "./stepup.ts";
import { approveClient } from "./web/approve-client.ts";
import { page } from "./web/page.ts";

export const LINK_TTL = 600;

export const ENVELOPE_TYP = "oe-approval-request+jwt";
const MAX_TTL = 600, SKEW = 5, DOC_TTL_MS = 600_000, REFETCH_MS = 30_000;
const REQUEST_ID = /^[A-Za-z0-9:._-]{1,128}$/;
const HEX64 = /^[0-9a-f]{64}$/;

/** The registrable domain of each product DID host (the four product signers): return_url must be on it or a subdomain. */
export const PRODUCT_SITES: Record<string, { site: string; name: string }> = {
  "did:web:moltbotden.com": { site: "moltbotden.com", name: "Moltbot Den" },
  "did:web:securemyagent.ai": { site: "securemyagent.ai", name: "Secure My Agent" },
  "did:web:api.agentsecretstore.com": { site: "agentsecretstore.com", name: "Agent Secret Store" },
  "did:web:api.clawgrc.com": { site: "clawgrc.com", name: "ClawGRC" },
};

type FetchJson = (url: string) => Promise<unknown>;
const getJson = (f: typeof fetch): FetchJson => async (url) => {
  const r = await f(url, { redirect: "error", signal: AbortSignal.timeout(5000), headers: { accept: "application/did+json, application/json" } });
  if (!r.ok) throw new Error(`${url} answered ${r.status}`);
  return r.json();
};

/** Ed25519 keys listed under assertionMethod of a did:web document, by absolute verification method id. */
export function assertionKeys(did: string, doc: any): Map<string, KeyObject> {
  if (doc?.id !== did) throw new Error(`${did} document names ${String(doc?.id)}`);
  const abs = (id: unknown) => (typeof id === "string" && id.startsWith("#") ? did + id : String(id));
  const refs: unknown[] = Array.isArray(doc.assertionMethod) ? doc.assertionMethod : [];
  const listed = new Set(refs.map((v: any) => abs(typeof v === "string" ? v : v?.id)));
  const methods = [...(Array.isArray(doc.verificationMethod) ? doc.verificationMethod : []), ...refs.filter((v) => typeof v === "object")];
  const keys = new Map<string, KeyObject>();
  for (const vm of methods as any[]) {
    if (typeof vm?.id !== "string" || !listed.has(abs(vm.id))) continue;
    let x: string | undefined;
    try {
      if (vm.type === "Multikey") x = Buffer.from(publicKeyFromDidKey(`did:key:${vm.publicKeyMultibase}`)).toString("base64url");
      else if (vm.type === "JsonWebKey" && vm.publicKeyJwk?.kty === "OKP" && vm.publicKeyJwk.crv === "Ed25519") x = vm.publicKeyJwk.x;
      if (x && Buffer.from(x, "base64url").length === 32) keys.set(abs(vm.id), createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x }, format: "jwk" }));
    } catch { /* not an Ed25519 key */ }
  }
  return keys;
}

const docs = new Map<string, { at: number; keys: Map<string, KeyObject> }>();
/** A product's envelope key: did.json cached 10 minutes, refetched (at most every 30 s) when it names an unknown key. */
async function productKey(kid: string, fetchJson: FetchJson): Promise<KeyObject | undefined> {
  const did = kid.split("#")[0];
  const hit = docs.get(did), age = hit ? Date.now() - hit.at : Infinity;
  if (hit && age < DOC_TTL_MS && (hit.keys.has(kid) || age < REFETCH_MS)) return hit.keys.get(kid);
  let doc: unknown;
  try {
    doc = await fetchJson(`https://${did.slice("did:web:".length)}/.well-known/did.json`);
  } catch {
    return fail(503, "unavailable", `could not resolve ${did}; try again`);
  }
  const keys = assertionKeys(did, doc);
  docs.set(did, { at: Date.now(), keys });
  return keys.get(kid);
}

const invalid = (why: string): never => fail(400, "envelope_invalid", `the approval request is not valid: ${why}`);
const segment = (seg: string, what: string): Record<string, any> => {
  try {
    const v = JSON.parse(Buffer.from(seg, "base64url").toString("utf8"));
    if (v && typeof v === "object" && !Array.isArray(v)) return v;
  } catch { /* fall through */ }
  return invalid(`${what} is not a JSON object`);
};
const int = (v: unknown) => Number.isSafeInteger(v) && (v as number) >= 0;

export interface CheckContext {
  /** This environment's service DID (the envelope's aud) and passkey RP ID. */
  serviceDid: string;
  rpId: string;
  /** The owner's verified key log, or null when the service does not know the owner. */
  keyLog: (ownerDid: string) => Promise<Pick<KeyLogState, "approvers" | "closed"> | null>;
  now?: number;
  fetchJson?: FetchJson;
}

/**
 * Verifies an ApproveEnvelope and returns the ApproveCheck the page needs. Beyond the frozen fields it adds `kids`
 * (credential id to key log kid, the Approval2 device_id) and `challenges` (base64url approval/2.0 digest per decision).
 */
export async function checkEnvelope(jws: unknown, x: CheckContext) {
  if (typeof jws !== "string" || jws.length > 16_384) return invalid("request must be a compact JWS");
  const parts = jws.split(".");
  if (parts.length !== 3 || parts.some((p) => !/^[A-Za-z0-9_-]+$/.test(p))) return invalid("request must be a compact JWS");
  const header = segment(parts[0], "header");
  if (header.alg !== "EdDSA" || header.typ !== ENVELOPE_TYP || "crit" in header) invalid(`header must be alg EdDSA, typ ${ENVELOPE_TYP}`);
  const kid = typeof header.kid === "string" ? header.kid : invalid("header has no kid");
  const did = kid.split("#")[0];
  if (!Object.hasOwn(PRODUCT_SITES, did) || !/^[^#]+#[^#]+$/.test(kid)) fail(403, "unknown_verifier", "approval requests are accepted only from Moltbot Den, Secure My Agent, Agent Secret Store and ClawGRC");
  const key = (await productKey(kid, x.fetchJson ?? getJson(fetch))) ?? invalid(`${kid} is not an Ed25519 assertionMethod key of ${did}`);
  if (!verify(null, Buffer.from(`${parts[0]}.${parts[1]}`), key, Buffer.from(parts[2], "base64url"))) invalid("signature does not verify");

  const e = segment(parts[1], "claims");
  const now = x.now ?? Math.floor(Date.now() / 1000);
  if (e.iss !== did) invalid("iss must be the DID of the signing key");
  if (e.aud !== x.serviceDid) invalid(`aud must be ${x.serviceDid}`);
  if (!int(e.iat) || !int(e.exp) || e.exp <= e.iat || e.exp - e.iat > MAX_TTL) invalid("exp must be after iat and at most 600 seconds after it");
  if (e.iat > now + SKEW) invalid("iat is in the future");
  if (now >= e.exp) fail(410, "envelope_expired", "this approval request expired; start again from the product");
  if (typeof e.request_id !== "string" || !REQUEST_ID.test(e.request_id)) invalid("request_id must be 1 to 128 of [A-Za-z0-9:._-]");
  if (typeof e.owner_did !== "string" || !new RegExp(`^${x.serviceDid.replace(/\./g, "\\.")}:o:[a-z2-7]{52}$`).test(e.owner_did)) invalid("owner_did is not an owner DID of this service");
  if (!e.payload || typeof e.payload !== "object" || Array.isArray(e.payload)) invalid("payload must be an object");
  let digest = "";
  try { digest = payloadDigest(e.payload); } catch (err) { invalid(`payload: ${(err as Error).message}`); }
  if (typeof e.payload_digest !== "string" || !HEX64.test(e.payload_digest) || e.payload_digest !== digest) invalid("payload_digest is not the SHA-256 of the JCS of payload");
  const site = PRODUCT_SITES[did].site;
  let back: URL | undefined;
  try { back = new URL(String(e.return_url)); } catch { /* checked below */ }
  if (!back || back.protocol !== "https:" || back.username || back.password || back.port || !(back.hostname === site || back.hostname.endsWith(`.${site}`))) invalid(`return_url must be https on ${site}`);
  if (e.state !== undefined && (typeof e.state !== "string" || e.state.length > 256)) invalid("state must be a string of at most 256 characters");

  const log = await x.keyLog(e.owner_did);
  if (!log || log.closed) fail(404, "owner_unknown", "this OpenEntity account does not exist or was deleted");
  const passkeys = log!.approvers.filter((c) => c.type === "webauthn" && typeof c.credential_id === "string");
  const base = { verifier_did: did, owner_did: e.owner_did, request_id: e.request_id, payload_digest: digest, expires_at: e.exp };
  const challenge = (decision: string) => Buffer.from(approvalDigest({ ...base, decision })).toString("base64url");
  return {
    ...base, payload: e.payload, return_url: back!.href, state: e.state ?? null, rp_id: x.rpId,
    allow_credentials: passkeys.map((c) => c.credential_id as string),
    kids: Object.fromEntries(passkeys.map((c) => [c.credential_id as string, c.kid])),
    challenges: { approve: challenge("approve"), deny: challenge("deny") },
  };
}

/** The /approve page. Its form may post only to the four products' sites. */
export function approvePage() {
  const products = Object.fromEntries(Object.entries(PRODUCT_SITES).map(([d, p]) => [d, p.name]));
  return page({
    title: "Approve a request | OpenEntity",
    body: `
<section id="loading"><h1>Checking the request</h1><p>One moment.</p></section>
<section id="error" hidden><h1>This request cannot be approved here</h1><p id="error-text" class="error"></p></section>
<section id="request" hidden>
  <h1 id="title"></h1>
  <p>Check every line. Only approve what you asked for.</p>
  <div class="panel"><dl id="summary"></dl></div>
  <p class="note">Request <span id="request-id" class="mono"></span>, from <span id="verifier" class="mono"></span>. <span id="expiry"></span></p>
  <p id="no-passkey" class="warn" hidden>This account has no passkey approver yet. Approve in the OpenEntity app, or sign in on this site and add a passkey approver.</p>
  <p id="decide-error" class="error" hidden></p>
  <button id="approve" class="primary">Approve with passkey</button>
  <button id="deny">Deny with passkey</button>
  <button id="cancel">Cancel</button>
</section>
<section id="done" hidden><h1>Sending your decision</h1><p>Returning you to the product.</p></section>`,
    client: approveClient,
    config: { products },
    csp: { "form-action": Object.values(PRODUCT_SITES).flatMap((p) => [`https://${p.site}`, `https://*.${p.site}`]) },
  });
}

export function routes(app: Hono, d: Deps) {
  const did = `did:web:${d.host}`;

  app.get("/approve", () => approvePage());

  app.post("/v1/approve/check", async (c) => {
    if ((await bump(d.db, `approve:${createHash("sha256").update(ipOf(c)).digest("hex").slice(0, 32)}`, String(Math.floor(now() / 60)))) > 60) {
      fail(429, "rate_limited", "too many approval checks from this address", { retry_after: 60 });
    }
    const b = await json(c);
    return c.json(await checkEnvelope(b.request, { serviceDid: did, rpId: d.rp.id, keyLog: (owner) => keyLogState(d, owner), fetchJson: getJson(d.fetch ?? fetch) }));
  });

  // Link an existing product web account (PLAN 2.5): a product.link step-up, then a LinkOwnerEnvelope for that product.
  app.post("/v1/account/links", async (c) => {
    const owner = await bearer(c, d);
    const b = await json(c);
    const product = typeof b.product === "string" && Object.hasOwn(PRODUCT_SITES, b.product) ? b.product : fail(400, "unknown_product", `product must be one of: ${Object.keys(PRODUCT_SITES).join(", ")}`);
    await requireApproval(c, d, { accountId: owner.accountId, ownerDid: owner.ownerDid, action: "product.link", params: { product } });
    const t = now();
    const envelope = await signJwt(d.keys.did, { alg: "EdDSA", kid: `${did}#${d.keys.did.kid}`, typ: "oe-link-owner+jwt" },
      { iss: did, aud: product, sub: owner.ownerDid, purpose: "link-owner", iat: t, exp: t + LINK_TTL, jti: newId("lnk") });
    return c.json({ product, envelope, link_url: `https://${PRODUCT_SITES[product].site}/oe/link#envelope=${envelope}`, expires_at: t + LINK_TTL });
  });
}
