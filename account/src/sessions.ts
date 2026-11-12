// Sessions and refresh tokens (PLAN 2.4). A refresh token is an opaque 256-bit value; only its SHA-256 is stored.
// Every use rotates it. Using a rotated token again revokes the whole session (its family), except an idempotent retry:
// the same token again within RETRY_GRACE seconds, while its successor is still unused, replaces that successor.
// That covers a response lost on a mobile network; theft inside the window is what device binding stops.
import { createHash, randomBytes } from "node:crypto";
import { type Db, newId, now } from "./db.ts";
import { HttpError } from "./http.ts";

export const APP_TTL = 90 * 86400; // sliding
export const WEB_TTL = 12 * 3600; // absolute
export const RETRY_GRACE = 30;
export type Platform = "ios" | "android" | "web";

export interface Session {
  id: string; account_id: string; platform: Platform; install_id: string | null; binding: string | null;
  amr: string; auth_time: number; created_at: number; expires_at: number;
}
export interface Rotated { session: Session; refreshToken: string; expiresAt: number }

export const tokenHash = (t: string) => createHash("sha256").update(t, "utf8").digest("hex");
const mint = () => `oert_${randomBytes(32).toString("base64url")}`;

export async function openSession(db: Db, o: {
  accountId: string; platform: Platform; amr: string; installId?: string | null; deviceModel?: string | null; appVersion?: string | null; binding?: string | null;
}, t = now()): Promise<{ sessionId: string; refreshToken: string; expiresAt: number }> {
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
