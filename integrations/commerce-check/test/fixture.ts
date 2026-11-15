// A real registry on PGlite and the published throwaway owner of test-vectors/keylog-1/add-approver.json, whose iPhone approver key signs mandates.
import { randomBytes, generateKeyPairSync } from "node:crypto";
import { readFileSync } from "node:fs";
import { p256 } from "@noble/curves/nist.js";
import { generateKeyPair, mandateDigest, signRequest, type KeyPair } from "@openentity/sdk";
import { app } from "../../../registry/src/index.ts";
import { pgliteDb } from "../../../registry/src/db.ts";
import { memoryBlobs } from "../../../registry/src/blob.ts";
import type { CommerceEnv } from "../../../registry/src/commerce.ts";

const vec = (p: string) => JSON.parse(readFileSync(new URL(`../../../test-vectors/${p}`, import.meta.url), "utf8"));
const LOG = vec("keylog-1/add-approver.json"), KEYS = vec("approval-2.0/keys.json").keys;
export const OWNER = LOG.did as string;
const unhex = (h: string) => Uint8Array.from(h.match(/../g)!.map((x) => parseInt(x, 16)));
const b64url = (b: Uint8Array) => Buffer.from(b).toString("base64url");

const env: CommerceEnv = {
  db: await pgliteDb(), log: memoryBlobs(), snapshots: memoryBlobs(), STAMP_BITS: "8", REGISTRY_HOST: "openentity.org", BASE_RPC_URL: "https://rpc.test",
  REGISTRY_KEY_JWK: JSON.stringify(generateKeyPairSync("ed25519").privateKey.export({ format: "jwk" })), CUSTODY_KEY: randomBytes(32).toString("base64"), HASH_SALT: "t", WRITE_PER_MINUTE: "100000",
  commerceOwner: async (did) => (did === OWNER ? { lines: LOG.log, serviceKeys: LOG.service_keys, origins: LOG.origins } : null),
  commerceStatus: async (url) => ({ mandate_id: url.split("/")[5], status: "active" }),
};
/** fetch() that calls the registry in-process instead of openentity.org. */
let ip = 0;
export const hosted: typeof fetch = async (input, init) => app.fetch(new Request(input as string, { ...init, headers: { ...(init?.headers as object), "x-forwarded-for": `10.2.0.${++ip % 250}` } }), env);

let n = 0;
export function mandateFor(agent: string) {
  const id = `md_${"b".repeat(25)}${"abcdefghijklmnopqrstuvwxyz234567"[++n % 32]}`, T = Math.floor(Date.now() / 1000);
  const b = {
    version: "mandate/1", mandate_id: id, issuer_did: OWNER, agent_did: agent, issued_at: T - 60, expires_at: T + 864000,
    limits: { currency: "USD", per_tx_max: 5000, period: "P1D", period_max: 20000, total_max: 100000 },
    scope: { merchants: ["did:web:shop.example"], rails: ["credits"] }, step_up_over: 2500, status: `https://account.openentity.org/v1/mandates/${id}/status`,
  };
  const signature = { device_id: KEYS.ios.kid, form: "p256", signature: b64url(p256.sign(mandateDigest(b), unhex(KEYS.ios.secret), { prehash: false, lowS: true })) };
  return { ...b, signature };
}
/** The headers a buying agent sends: an RFC 9421 signature for `url` and its mandate. */
export async function agentHeaders(kp: KeyPair, url: string, mandate?: object): Promise<Record<string, string>> {
  const h = await signRequest({ method: "POST", url, privateKey: kp, did: kp.did });
  return mandate ? { ...h, "OE-Mandate": b64url(new TextEncoder().encode(JSON.stringify(mandate))) } : h;
}
export { generateKeyPair };
