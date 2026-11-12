// Calls from the service to products (openapi.yaml accountSignature): RFC 9421 signed with the Ed25519 service key in
// KMS, keyid did:web:<host>#<thumbprint>. Events that cannot be delivered wait in `outbox` and jobs.ts retries them
// for 24 hours, the window in which products dedupe event ids.
import { createHash, randomBytes } from "node:crypto";
import { httpSigBase } from "@openentity/sdk";
import type { Deps } from "./app.ts";
import { newId, now } from "./db.ts";

/** Each product's API host (did:web:<product> answers there). */
export const PRODUCT_APIS: Record<string, string> = {
  "did:web:moltbotden.com": "https://api.moltbotden.com",
  "did:web:securemyagent.ai": "https://api.securemyagent.ai",
  "did:web:api.agentsecretstore.com": "https://api.agentsecretstore.com",
  "did:web:api.clawgrc.com": "https://api.clawgrc.com",
};
const TIMEOUT_MS = 5000, GIVE_UP = 86_400;

/** Signature-Input, Signature and Content-Digest for a call this service makes. */
export async function signHeaders(d: Deps, method: string, url: string, body: Uint8Array): Promise<Record<string, string>> {
  const digest = `sha-256=:${createHash("sha256").update(body).digest("base64")}:`;
  const comps = ["@method", "@target-uri", "content-digest"], created = now();
  const params = `(${comps.map((x) => `"${x}"`).join(" ")});created=${created};expires=${created + 60};nonce="${randomBytes(16).toString("base64url")}";keyid="did:web:${d.host}#${d.keys.did.kid}";alg="ed25519"`;
  const sig = await d.keys.did.sign(httpSigBase(method, url, comps, digest, params));
  return { "content-digest": digest, "signature-input": `sig1=${params}`, signature: `sig1=:${Buffer.from(sig).toString("base64")}:` };
}

/** A signed JSON POST to a product. Never throws: status 0 is a network error or timeout. */
export async function callProduct(d: Deps, product: string, path: string, payload: unknown): Promise<{ status: number; body: any }> {
  const url = `${(d.products ?? PRODUCT_APIS)[product]}${path}`;
  const body = new TextEncoder().encode(JSON.stringify(payload));
  try {
    const r = await (d.fetch ?? fetch)(url, {
      method: "POST", body, redirect: "error", signal: AbortSignal.timeout(TIMEOUT_MS),
      headers: { "content-type": "application/json", ...(await signHeaders(d, "POST", url, body)) },
    });
    const text = await r.text();
    let json: any = null;
    try { json = text ? JSON.parse(text) : null; } catch { /* not JSON */ }
    return { status: r.status, body: json };
  } catch (e) {
    console.warn(`call to ${url} failed: ${(e as Error).message}`);
    return { status: 0, body: null };
  }
}

const retryable = (status: number) => status === 0 || status === 408 || status === 425 || status === 429 || status >= 500;

/**
 * Sends a signed AccountEvent to a product's POST /v1/oe/events. A failure that may pass (network, 429, 5xx) is kept
 * in the outbox and retried by jobs; a 4xx refusal is logged and dropped. Resolves true when the product took it now.
 */
export async function sendEvent(d: Deps, productDid: string, type: string, data: Record<string, unknown>): Promise<boolean> {
  const event = { id: newId("evt"), type, created_at: now(), data };
  const r = await callProduct(d, productDid, "/v1/oe/events", event);
  if (r.status >= 200 && r.status < 300) return true;
  if (retryable(r.status)) {
    await d.db.run("INSERT INTO outbox (id, product, path, body, attempts, next_at, created_at) VALUES ($1, $2, '/v1/oe/events', $3, 1, $4, $5)",
      [event.id, productDid, JSON.stringify(event), event.created_at + 30, event.created_at]);
  } else {
    console.error(`${productDid} refused ${type} ${event.id}: ${r.status} ${JSON.stringify(r.body)?.slice(0, 200)}`);
  }
  return false;
}

/** jobs.ts: retries due outbox rows with backoff (30 s doubling, at most an hour), for 24 hours. */
export async function retryOutbox(d: Deps): Promise<void> {
  const t = now();
  const due = await d.db.all<{ id: string; product: string; path: string; body: string; attempts: number; created_at: number }>(
    "SELECT id, product, path, body, attempts, created_at FROM outbox WHERE next_at <= $1 ORDER BY next_at LIMIT 50", [t]);
  for (const row of due) {
    const r = await callProduct(d, row.product, row.path, JSON.parse(row.body));
    const attempts = Number(row.attempts) + 1;
    if ((r.status >= 200 && r.status < 300) || !retryable(r.status) || t - Number(row.created_at) > GIVE_UP) {
      if (!(r.status >= 200 && r.status < 300)) console.error(`outbox ${row.id} to ${row.product} dropped after ${attempts} attempts: ${r.status}`);
      await d.db.run("DELETE FROM outbox WHERE id = $1", [row.id]);
    } else {
      await d.db.run("UPDATE outbox SET attempts = $2, next_at = $3 WHERE id = $1", [row.id, attempts, t + Math.min(30 * 2 ** attempts, 3600)]);
    }
  }
}
