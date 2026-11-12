// Request helpers every module shares: the error type, JSON bodies and the owner's bearer token.
import type { Context } from "hono";
import { importJWK, jwtVerify, errors as joseErrors } from "jose";
import type { Deps } from "./app.ts";
import { now } from "./db.ts";

/** An error the API answers as JSON {error, message} with this status (openapi.yaml, Error). */
export class HttpError extends Error {
  constructor(public status: number, public code: string, message: string, public extra: Record<string, unknown> = {}) { super(message); }
}
export const fail = (status: number, code: string, message: string, extra?: Record<string, unknown>): never => { throw new HttpError(status, code, message, extra); };

/** The request body as a JSON object, at most 64 KB. */
export async function json(c: Context): Promise<Record<string, any>> {
  const text = await c.req.text();
  if (text.length > 64_000) fail(413, "too_large", "request body exceeds 64 KB");
  try {
    const v = JSON.parse(text);
    if (!v || typeof v !== "object" || Array.isArray(v)) throw 0;
    return v;
  } catch { return fail(400, "bad_request", "the body must be a JSON object"); }
}

export const str = (v: unknown, name: string, max = 4096): string => {
  if (typeof v !== "string" || !v || v.length > max) fail(400, "bad_request", `${name} is required`);
  return v as string;
};

/**
 * The viewer's address, which the distribution's viewer-request function sets on every request (account-stack.ts
 * ViewerAddress, overwriting any value a client sends). Without it every caller would share one per-address bucket,
 * so its absence is refused rather than counted.
 */
export const ipOf = (c: Context) => c.req.header("x-oe-viewer-address") || fail(503, "unavailable", "the viewer address is missing");

export interface Owner { accountId: string; sid: string; authTime: number; ownerDid: string | null }

/** A sign-in at most 5 minutes old: deleting an account with no key log, and creating the key log (gate M2). */
export const REAUTH_WINDOW = 300;
export const freshSignIn = (o: Owner, then: string) =>
  now() - o.authTime <= REAUTH_WINDOW || fail(401, "reauth_required", `sign in again, then ${then} within 5 minutes`);

const verifyKeys = new WeakMap<object, ReturnType<typeof importJWK>>();

/** The caller behind an access token for this service, whose session is still live. */
export async function bearer(c: Context, d: Deps): Promise<Owner> {
  const h = c.req.header("authorization") ?? "";
  if (!h.startsWith("Bearer ")) fail(401, "unauthorized", "missing bearer token");
  let key = verifyKeys.get(d.keys.token);
  if (!key) verifyKeys.set(d.keys.token, (key = importJWK({ ...d.keys.token.jwk, alg: "ES256" })));
  let p;
  try {
    ({ payload: p } = await jwtVerify(h.slice(7), await key, { issuer: `https://${d.host}`, audience: `did:web:${d.host}`, algorithms: ["ES256"], typ: "at+jwt" }));
  } catch (e) {
    if (e instanceof joseErrors.JOSEError) fail(401, "unauthorized", "invalid or expired access token");
    throw e;
  }
  const s = await d.db.first<{ account_id: string; owner_did: string | null }>(
    "SELECT s.account_id, a.owner_did FROM sessions s JOIN accounts a ON a.id = s.account_id WHERE s.id = $1 AND s.revoked_at IS NULL AND s.expires_at > $2 AND a.deleted_at IS NULL",
    [p!.sid, now()]);
  if (!s) fail(401, "unauthorized", "this session has ended");
  return { accountId: s!.account_id, sid: String(p!.sid), authTime: Number(p!.auth_time), ownerDid: s!.owner_did ?? null };
}
