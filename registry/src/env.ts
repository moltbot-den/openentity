export interface Env {
  DB: D1Database;
  KV: KVNamespace;
  LOG: R2Bucket;
  LOG_QUEUE: Queue;
  WRITE_LIMITER?: { limit(o: { key: string }): Promise<{ success: boolean }> };
  STAMP_BITS: string;
  IP_DAILY_LIMIT?: string; // preview only, for the load test
  REGISTRY_HOST: string;
  BASE_RPC_URL: string;
  S3_BUCKET?: string;
  S3_REGION?: string;
  REGISTRY_KEY_JWK?: string;
  CUSTODY_KEY?: string;
  HASH_SALT?: string;
  TURNSTILE_SECRET?: string;
  CIO_SITE_ID?: string;
  CIO_API_KEY?: string;
  AWS_ACCESS_KEY_ID?: string;
  AWS_SECRET_ACCESS_KEY?: string;
}

export const REGISTRY_DID = "did:web:openentity.org";
export const LOG_ORIGIN = "openentity.org/log";

export const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
export const unhex = (s: string) => Uint8Array.from(s.match(/../g) ?? [], (x) => parseInt(x, 16));
export const b64 = (b: Uint8Array) => btoa(String.fromCharCode(...b));
export const nowIso = () => new Date().toISOString().replace(/\.\d+Z$/, "Z");
