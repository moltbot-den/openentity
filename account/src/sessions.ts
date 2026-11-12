// Sessions and refresh tokens (PLAN 2.4). A refresh token is an opaque 256-bit value; only its SHA-256 is stored.
// Every use rotates it. Using a rotated token again revokes the whole session (its family), except an idempotent retry:
// the same token again within RETRY_GRACE seconds, while its successor is still unused, replaces that successor.
// That covers a response lost on a mobile network; theft inside the window is what device binding stops.
import { createHash, randomBytes } from "node:crypto";
import type { Context } from "hono";
import type { Deps } from "./app.ts";
import type { KeyLogState } from "@openentity/sdk";
import { deviceBinding } from "./binding.ts";
import { type Db, newId, now } from "./db.ts";
import { deletionOf } from "./deletion.ts";
import { HttpError, fail } from "./http.ts";
import { signJwt } from "./keys.ts";
import { keyLogState } from "./keylog.ts";
import { methodList } from "./methods.ts";
import { BUNDLE_ID } from "./wellknown.ts";

export const APP_TTL = 90 * 86400; // sliding
export const WEB_TTL = 12 * 3600; // absolute
export const RETRY_GRACE = 30;
export const ACCESS_TTL = 900;
export const COOKIE = "__Host-oe_session";
export type Platform = "ios" | "android" | "web";

/** A 15-minute ES256 access token for one audience (PLAN 2.4). Product audiences need an owner DID (a key log). */
export async function accessToken(d: Deps, accountId: string, aud: string, sid: string, platform: string, authTime: number, amr: string, t = now()) {
  // A deleted account mints nothing: not through a session or login code that raced the deletion (gate lead).
  const a = await d.db.first<{ owner_did: string | null }>("SELECT owner_did FROM accounts WHERE id = $1 AND deleted_at IS NULL", [accountId]) ?? fail(401, "invalid_grant", "this account was deleted");
  if (aud !== `did:web:${d.host}` && !a.owner_did) fail(403, "key_log_required", "product tokens need an owner DID; finish \"Turn on Face ID approvals\" first");
  const token = await signJwt(d.keys.token, { typ: "at+jwt" }, {
    iss: `https://${d.host}`, sub: a.owner_did ?? accountId, aud, iat: t, exp: t + ACCESS_TTL, jti: newId("at"), sid,
    client_id: platform === "web" ? "web" : BUNDLE_ID, auth_time: authTime, amr: [amr],
  });
  return { audience: aud, access_token: token, expires_at: t + ACCESS_TTL };
}

/** "Add a backup" (PLAN 3.2): until the log holds a second passkey or a second approver device, total loss is one device away. */
const needsBackup = (s: KeyLogState | null) =>
  !!s && !s.closed && !(s.approvers.some((k) => k.type === "webauthn" && k.kid !== s.root.kid) || s.approvers.filter((k) => k.type === "p256").length >= 2);

/** The Account object (openapi.yaml) for the signed-in owner. */
export async function me(d: Deps, accountId: string) {
  const a = await d.db.first<any>("SELECT * FROM accounts WHERE id = $1", [accountId]);
  return {
    id: a.id, owner_did: a.owner_did ?? null, email: a.email ?? null, email_private: !!a.email_private, created_at: Number(a.created_at),
    has_key_log: !!a.owner_did, backup_needed: a.owner_did ? needsBackup(await keyLogState(d, a.owner_did)) : false, app_account_token: a.app_account_token,
    methods: await methodList(d, accountId),
    deletion: await deletionOf(d, accountId),
  };
}


/** The session a refresh token belongs to (its binding included), or null. */
export const sessionOf = (db: Db, token: string) =>
  db.first<{ id: string; platform: Platform; binding: string | null }>("SELECT s.id, s.platform, s.binding FROM refresh_tokens r JOIN sessions s ON s.id = r.session_id WHERE r.hash = $1", [tokenHash(token)]);

export interface Session {
  id: string; account_id: string; platform: Platform; install_id: string | null; binding: string | null;
  amr: string; auth_time: number; created_at: number; expires_at: number;
}
export interface Rotated { session: Session; refreshToken: string; expiresAt: number }

export const tokenHash = (t: string) => createHash("sha256").update(t, "utf8").digest("hex");
const mint = () => `oert_${randomBytes(32).toString("base64url")}`;

export interface SessionInit { accountId: string; platform: Platform; amr: string; installId?: string | null; deviceModel?: string | null; appVersion?: string | null }
export interface Opened { sessionId: string; refreshToken: string; expiresAt: number }

/**
 * Opens a session. From a sign-in route, `openSession(c, d, init)`: device binding is enforced first (binding.ts
 * deviceBinding, from the body's `attestation` and `nonce` or the install key's proof over the body) and stored with
 * the session. `openSession(db, init & {binding})` stores what it is given (fixtures and tests only).
 */
export function openSession(c: Context, d: Deps, o: SessionInit & { attestation?: unknown; nonce?: string }): Promise<Opened>;
export function openSession(db: Db, o: SessionInit & { binding?: string | null }, t?: number): Promise<Opened>;
export async function openSession(x: Context | Db, y: any, z?: any): Promise<Opened> {
  if ("req" in x) {
    const c = x as Context, d = y as Deps, o = z as SessionInit & { attestation?: unknown; nonce?: string };
    const text = await c.req.text();
    let body: Record<string, any> = {};
    try { body = JSON.parse(text) ?? {}; } catch { /* a form post carries no attestation */ }
    const binding = await deviceBinding(d, {
      platform: o.platform, installId: o.installId ?? null, attestation: o.attestation ?? body.attestation,
      nonce: o.nonce ?? (typeof body.nonce === "string" ? body.nonce : undefined), proof: { header: (n) => c.req.header(n), body: new TextEncoder().encode(text) },
    });
    return insert(d.db, { ...o, binding });
  }
  return insert(x as Db, y, z);
}

async function insert(db: Db, o: SessionInit & { binding?: string | null }, t = now()): Promise<Opened> {
  const id = newId("ses"), token = mint(), expiresAt = t + (o.platform === "web" ? WEB_TTL : APP_TTL);
  await db.tx(async (tx) => {
    await tx.run(
      "INSERT INTO sessions (id, account_id, platform, install_id, device_model, app_version, binding, amr, auth_time, created_at, last_used_at, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $9, $9, $10)",
      [id, o.accountId, o.platform, o.installId ?? null, o.deviceModel ?? null, o.appVersion ?? null, o.binding ?? null, o.amr, t, expiresAt],
    );
    await tx.run("INSERT INTO refresh_tokens (hash, session_id, created_at) VALUES ($1, $2, $3)", [tokenHash(token), id, t]);
  });
  return { sessionId: id, refreshToken: token, expiresAt };
}

type Outcome = { ok: Rotated } | { error: "invalid_grant" | "token_reused" };

export async function rotate(db: Db, token: string, t = now()): Promise<Rotated> {
  // The revocation on reuse must commit, so the transaction returns an outcome and the error is thrown after it.
  const out = await db.tx<Outcome>(async (tx) => {
    const row = await tx.first<{ used_at: number | null; successor: string | null; session_id: string }>(
      "SELECT used_at, successor, session_id FROM refresh_tokens WHERE hash = $1 FOR UPDATE", [tokenHash(token)]);
    if (!row) return { error: "invalid_grant" };
    const s = await tx.first<Session & { revoked_at: number | null }>("SELECT * FROM sessions WHERE id = $1 FOR UPDATE", [row.session_id]);
    if (!s || s.revoked_at !== null || Number(s.expires_at) <= t) return { error: "invalid_grant" };
    if (!(await tx.first("SELECT 1 FROM accounts WHERE id = $1 AND deleted_at IS NULL", [s.account_id]))) return { error: "invalid_grant" }; // gate lead
    if (row.used_at !== null) {
      const next = row.successor ? await tx.first<{ used_at: number | null }>("SELECT used_at FROM refresh_tokens WHERE hash = $1", [row.successor]) : null;
      const retry = t - Number(row.used_at) <= RETRY_GRACE && next && next.used_at === null;
      if (!retry) {
        await tx.run("UPDATE sessions SET revoked_at = $2, revoke_reason = 'token_reused' WHERE id = $1", [s.id, t]);
        return { error: "token_reused" };
      }
      await tx.run("DELETE FROM refresh_tokens WHERE hash = $1", [row.successor]);
    }
    const fresh = mint(), expiresAt = s.platform === "web" ? Number(s.expires_at) : t + APP_TTL;
    await tx.run("INSERT INTO refresh_tokens (hash, session_id, created_at) VALUES ($1, $2, $3)", [tokenHash(fresh), s.id, t]);
    await tx.run("UPDATE refresh_tokens SET used_at = COALESCE(used_at, $2), successor = $3 WHERE hash = $1", [tokenHash(token), t, tokenHash(fresh)]);
    await tx.run("UPDATE sessions SET last_used_at = $2, expires_at = $3 WHERE id = $1", [s.id, t, expiresAt]);
    return { ok: { session: { ...s, expires_at: expiresAt }, refreshToken: fresh, expiresAt } };
  });
  if ("error" in out) throw new HttpError(401, out.error, out.error === "token_reused"
    ? "this refresh token was already used; the session is revoked, sign in again"
    : "the refresh token is unknown, expired or revoked");
  return out.ok;
}

/** Ends the session a refresh token belongs to. Unknown tokens are ignored (RFC 7009). */
export async function revoke(db: Db, token: string, reason = "signed_out", t = now()): Promise<void> {
  await db.run(
    "UPDATE sessions SET revoked_at = $2, revoke_reason = $3 WHERE revoked_at IS NULL AND id = (SELECT session_id FROM refresh_tokens WHERE hash = $1)",
    [tokenHash(token), t, reason],
  );
}
