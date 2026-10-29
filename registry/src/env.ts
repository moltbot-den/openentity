import type { Db } from "./db.ts";
import type { Blobs } from "./blob.ts";

export interface Env {
  db: Db;
  log: Blobs; // tiles, checkpoint, snapshots
  snapshots?: Blobs; // off-site Object Lock copy of the daily snapshots
  STAMP_BITS: string;
  REGISTRY_HOST: string;
  BASE_RPC_URL: string;
  EVM_RPC_URLS?: string; // JSON {"<chainId>": rpcUrl}; overrides the built-in public RPCs
  REGISTRY_KEY_JWK?: string;
  CUSTODY_KEY?: string;
  HASH_SALT?: string;
  TURNSTILE_SECRET?: string;
  CIO_SITE_ID?: string;
  CIO_API_KEY?: string;
  CIO_APP_API_KEY?: string; // App API bearer key: triggers the weekly digest broadcast
  CIO_BROADCAST_ID?: string; // the API-triggered broadcast "Weekly digest"
  IP_DAILY_LIMIT?: string; // overrides LIMITS.writes_per_ip_per_day (load test)
  WRITE_PER_MINUTE?: string; // overrides LIMITS.writes_per_ip_per_minute (load test)
}

export const REGISTRY_DID = "did:web:openentity.org";
export const LOG_ORIGIN = "openentity.org/log";

export const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
export const unhex = (s: string) => Uint8Array.from(s.match(/../g) ?? [], (x) => parseInt(x, 16));
export const b64 = (b: Uint8Array) => btoa(String.fromCharCode(...b));
export const nowIso = () => new Date().toISOString().replace(/\.\d+Z$/, "Z");
