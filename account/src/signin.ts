// Sign-in (PLAN 2.3): nonce, Apple, Google, passkeys and the 8-digit email code. Web lane. app.ts runs the
// SIGNIN_OPEN gate and the per-IP limit on /v1/auth/* before these routes.
import { randomBytes, randomUUID } from "node:crypto";
import type { Context, Hono } from "hono";
import type { Deps } from "./app.ts";
import { newId, now } from "./db.ts";
import { startEmail, verifyEmailCode } from "./email.ts";
import { bearer, fail, json, str } from "./http.ts";
import { type Identity, nonceHash, verifyApple, verifyGoogle } from "./idtoken.ts";
import { authenticationOptions, registrationOptions, verifyAuthentication, verifyRegistration } from "./passkey.ts";
import { COOKIE, type Platform, accessToken, me, openSession } from "./sessions.ts";

export const NONCE_TTL = 600, CHALLENGE_TTL = 300;

interface Client { platform: Platform; install_id: string | null; app_version: string | null; device_model: string | null }
function client(v: any): Client {
  const platform = v?.platform;
  if (!["ios", "android", "web"].includes(platform)) fail(400, "bad_request", "client.platform must be ios, android or web");
  const install = typeof v.install_id === "string" ? v.install_id : null;
  if (platform !== "web" && !/^[0-9a-fA-F-]{36}$/.test(install ?? "")) fail(400, "bad_request", "client.install_id (a UUID) is required in the apps");
  const opt = (x: unknown) => (typeof x === "string" ? x.slice(0, 64) : null);
  return { platform, install_id: platform === "web" ? null : install, app_version: opt(v.app_version), device_model: opt(v.device_model) };
}

/** Consumes a nonce issued to this client. Single use; the platform and install must match. */
export async function useNonce(d: Deps, raw: string, cl: { platform: string; install_id: string | null }) {
  const row = await d.db.first<{ platform: string; install_id: string | null }>(
    "UPDATE auth_nonces SET used_at = $2 WHERE hash = $1 AND used_at IS NULL AND expires_at > $2 RETURNING platform, install_id", [nonceHash(raw), now()]);
  if (!row || row.platform !== cl.platform || (row.install_id ?? null) !== cl.install_id) fail(401, "nonce_invalid", "the nonce is unknown, expired, used, or was issued to another client");
}

export function routes(app: Hono, d: Deps) {
  const did = `did:web:${d.host}`, origin = `https://${d.host}`;
  /** The calling client; a browser must send our Origin (login CSRF). */
  const clientOf = (c: Context, v: unknown): Client => {
    const cl = client(v);
    if (cl.platform === "web" && c.req.header("origin") !== origin) fail(403, "bad_origin", "web sign-in must come from this origin");
    return cl;
  };

  app.post("/v1/auth/nonce", async (c) => {
    const b = await json(c);
    const cl = clientOf(c, b.client);
    const raw = randomBytes(32).toString("base64url"), t = now();
    await d.db.run("INSERT INTO auth_nonces (hash, platform, install_id, flow, created_at, expires_at) VALUES ($1, $2, $3, $4, $5, $6)",
      [nonceHash(raw), cl.platform, cl.install_id, "native", t, t + NONCE_TTL]);
    return c.json({ nonce: raw, expires_at: t + NONCE_TTL });
  });

  /** The account for a verified identity, created on first sight. A verified email that already has an account is never merged silently. */
  async function accountFor(type: "apple" | "google" | "email" | "passkey", subject: string, email: string | null, emailPrivate: boolean) {
    const t = now();
    const m = await d.db.first<{ account_id: string }>("SELECT account_id FROM methods WHERE type = $1 AND subject = $2", [type, subject]);
    if (m) {
      await d.db.run("UPDATE methods SET last_used_at = $3 WHERE type = $1 AND subject = $2", [type, subject, t]);
      return { accountId: m.account_id, created: false };
    }
    if (email && !emailPrivate) {
      const holders = await d.db.all<{ type: string }>(
        "SELECT DISTINCT m.type FROM methods m JOIN accounts a ON a.id = m.account_id WHERE a.deleted_at IS NULL AND (a.email = $1 OR m.email = $1) ORDER BY m.type", [email]);
      if (holders.length) fail(409, "account_exists", "this email has an OpenEntity account; sign in with one of its methods, then add this one", { methods: holders.map((h) => h.type) });
    }
    const accountId = newId("acct");
    await d.db.tx(async (tx) => {
      await tx.run("INSERT INTO accounts (id, email, email_private, app_account_token, created_at) VALUES ($1, $2, $3, $4, $5)", [accountId, email, emailPrivate, randomUUID(), t]);
      await tx.run("INSERT INTO methods (id, account_id, type, subject, email, created_at, last_used_at) VALUES ($1, $2, $3, $4, $5, $6, $6)",
        [newId("mth"), accountId, type, subject, email, t]);
    });
    return { accountId, created: true };
  }

  async function session(c: Context, accountId: string, created: boolean, cl: Client, amr: string) {
    const s = await openSession(d.db, { accountId, platform: cl.platform, amr, installId: cl.install_id, deviceModel: cl.device_model, appVersion: cl.app_version });
    const at = await accessToken(d, accountId, did, s.sessionId, cl.platform, now(), amr);
    if (cl.platform === "web") c.header("set-cookie", `${COOKIE}=${s.refreshToken}; Path=/; Max-Age=${s.expiresAt - now()}; HttpOnly; Secure; SameSite=Strict`);
    return c.json({
      account: await me(d, accountId), new_account: created, token_type: "Bearer",
      access_token: at.access_token, access_expires_at: at.expires_at,
      ...(cl.platform === "web" ? {} : { refresh_token: s.refreshToken }), refresh_expires_at: s.expiresAt,
    });
  }

  async function signInWith(c: Context, id: Identity, cl: Client) {
    const { accountId, created } = await accountFor(id.provider, id.sub, id.email, id.emailPrivate);
    return session(c, accountId, created, cl, id.provider);
  }

  app.post("/v1/auth/apple", async (c) => {
    const b = await json(c);
    const cl = clientOf(c, b.client), nonce = str(b.nonce, "nonce", 128);
    await useNonce(d, nonce, cl);
    return signInWith(c, await verifyApple(str(b.identity_token, "identity_token", 8192), { audience: cl.platform === "ios" ? d.apple.native : d.apple.web, nonce, keys: d.providerKeys?.apple }), cl);
  });

  app.post("/v1/auth/google", async (c) => {
    const b = await json(c);
    const cl = clientOf(c, b.client), nonce = str(b.nonce, "nonce", 128);
    await useNonce(d, nonce, cl);
    return signInWith(c, await verifyGoogle(str(b.id_token, "id_token", 8192), { audience: d.google, nonce, keys: d.providerKeys?.google }), cl);
  });

  app.post("/v1/auth/email/start", async (c) => {
    const b = await json(c);
    const cl = clientOf(c, b.client);
    const r = await startEmail(d.db, { email: str(b.email, "email", 254), installId: cl.install_id, pepper: d.pepper, send: d.sendCode });
    return c.json({ challenge_id: r.challengeId, expires_at: r.expiresAt }, 202);
  });

  app.post("/v1/auth/email/verify", async (c) => {
    const b = await json(c);
    const cl = clientOf(c, b.client);
    const email = await verifyEmailCode(d.db, { challengeId: str(b.challenge_id, "challenge_id", 64), code: String(b.code ?? ""), pepper: d.pepper });
    const { accountId, created } = await accountFor("email", email, email, false);
    return session(c, accountId, created, cl, "email");
  });

  app.post("/v1/auth/passkey/options", async (c) => {
    const b = await json(c);
    clientOf(c, b.client);
    const mode = b.mode === "register" ? "register" : b.mode === "authenticate" ? "authenticate" : fail(400, "bad_request", "mode must be authenticate or register");
    let accountId: string | null = null, options;
    if (mode === "register") {
      const caller = await bearer(c, d);
      accountId = caller.accountId;
      const a = await d.db.first<{ owner_did: string | null; email: string | null }>("SELECT owner_did, email FROM accounts WHERE id = $1", [accountId]);
      const mine = await d.db.all<{ subject: string }>("SELECT subject FROM methods WHERE account_id = $1 AND type = 'passkey'", [accountId]);
      // Before the key log, one passkey: the onboarding root. After it, a new passkey is for the key log (an enrollment,
      // verified here) or a sign-in method (POST /v1/account/methods with step-up).
      if (!a?.owner_did && mine.length) fail(409, "passkey_exists", "this account has its root passkey; turn on approvals (the genesis entry) first");
      options = await registrationOptions(d.rp, { accountId, userName: a?.email ?? accountId, exclude: mine.map((m) => ({ id: m.subject })) });
    } else {
      options = await authenticationOptions(d.rp);
    }
    const id = newId("pkc"), t = now();
    await d.db.run("INSERT INTO passkey_challenges (id, challenge, mode, account_id, created_at, expires_at) VALUES ($1, $2, $3, $4, $5, $6)",
      [id, options.challenge, mode, accountId, t, t + CHALLENGE_TTL]);
    return c.json({ challenge_id: id, options });
  });

  app.post("/v1/auth/passkey/verify", async (c) => {
    const b = await json(c);
    const cl = clientOf(c, b.client);
    const ch = await d.db.first<{ challenge: string; mode: string; account_id: string | null }>(
      "UPDATE passkey_challenges SET used_at = $2 WHERE id = $1 AND used_at IS NULL AND expires_at > $2 RETURNING challenge, mode, account_id", [str(b.challenge_id, "challenge_id", 64), now()]);
    if (!ch) fail(410, "challenge_expired", "this passkey challenge expired or was used; start again");
    if (!b.response || typeof b.response !== "object") fail(400, "bad_request", "response is required");
    if (ch!.mode === "register") {
      const caller = await bearer(c, d);
      if (caller.accountId !== ch!.account_id) fail(403, "forbidden", "this challenge belongs to another account");
      const r = await verifyRegistration(d.rp, b.response, ch!.challenge);
      const methodId = newId("mth"), t = now();
      // With a key log this passkey is offered to the log (POST /v1/keylog/enrollments): kept, but `pending`, so it is
      // no sign-in method; adding one is step-up method.add. Without one it is the root passkey, which signs in.
      const pending = !!caller.ownerDid;
      await d.db.run("INSERT INTO methods (id, account_id, type, subject, data, created_at, last_used_at) VALUES ($1, $2, 'passkey', $3, $4, $5, $6)", [methodId, caller.accountId, r.credential.id, JSON.stringify({
        public_key: Buffer.from(r.credential.publicKey).toString("base64url"), counter: r.credential.counter, transports: r.credential.transports ?? [], aaguid: r.aaguid, backed_up: r.backedUp, jwk: r.jwk, key_id: r.keyId,
        ...(pending ? { pending: true } : {}),
      }), t, pending ? null : t]);
      // The root Credential exactly as the key log carries it (test-vectors/keylog-1): the app puts it into the genesis entry.
      return c.json({ method_id: methodId, credential: { kid: r.keyId, type: "webauthn", jwk: r.jwk, credential_id: r.credential.id, rp_id: d.rp.id, aaguid: r.aaguid, label: "Passkey", platform: cl.platform } });
    }
    const credId = str(b.response.id, "response.id", 1024);
    const m = await d.db.first<{ account_id: string; data: string }>("SELECT account_id, data FROM methods WHERE type = 'passkey' AND subject = $1", [credId]);
    if (!m) fail(401, "passkey_invalid", "this passkey is not registered with an OpenEntity account");
    const data = JSON.parse(m!.data);
    if (data.pending) fail(401, "passkey_invalid", "this passkey is an approver key, not a sign-in method; add it with POST /v1/account/methods");
    const counter = await verifyAuthentication(d.rp, b.response, ch!.challenge, { id: credId, publicKey: Buffer.from(data.public_key, "base64url"), counter: data.counter, transports: data.transports });
    await d.db.run("UPDATE methods SET data = $2, last_used_at = $3 WHERE type = 'passkey' AND subject = $1", [credId, JSON.stringify({ ...data, counter }), now()]);
    return session(c, m!.account_id, false, cl, "passkey");
  });
}
