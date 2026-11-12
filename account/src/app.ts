// OpenEntity Account HTTP API (account/openapi.yaml). Day 1: well-known documents and sign-in.
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { Hono, type Context } from "hono";
import { getCookie } from "hono/cookie";
import { importJWK, jwtVerify, errors as joseErrors, type JWTVerifyGetKey } from "jose";
import { type Db, bump, newId, now } from "./db.ts";
import { type SendCode, startEmail, verifyEmailCode } from "./email.ts";
import { HttpError, fail } from "./http.ts";
import { type Identity, nonceHash, verifyApple, verifyGoogle } from "./idtoken.ts";
import { type SigningKey, signJwt } from "./keys.ts";
import { type Rp, authenticationOptions, registrationOptions, verifyAuthentication, verifyRegistration } from "./passkey.ts";
import { type Platform, openSession, revoke, rotate } from "./sessions.ts";
import { aasa, assetlinks, BUNDLE_ID, didDocument, jwks, openidConfiguration } from "./wellknown.ts";

export const PRODUCT_DIDS = ["did:web:moltbotden.com", "did:web:securemyagent.ai", "did:web:api.agentsecretstore.com", "did:web:api.clawgrc.com"];
export const ACCESS_TTL = 900, NONCE_TTL = 600, CHALLENGE_TTL = 300;
export const COOKIE = "__Host-oe_session";

export interface Deps {
  stage: "staging" | "production";
  host: string;
  db: Db;
  keys: { token: SigningKey; did: SigningKey; close: SigningKey };
  pepper: string;
  sendCode: SendCode;
  rp: Rp;
  /** Bundle ID for the native Apple sheet; the Services ID for the web and Android redirect. */
  apple: { native: string[]; web: string[] };
  /** iOS and web OAuth client IDs. */
  google: string[];
  androidFingerprints: string[];
  signinOpen: boolean;
  version?: string;
  /** Tests only: stand-ins for Apple's and Google's published keys. Production uses the providers' JWKS. */
  providerKeys?: { apple?: JWTVerifyGetKey; google?: JWTVerifyGetKey };
}

type C = Context;
const json = async (c: C): Promise<Record<string, any>> => {
  const text = await c.req.text();
  if (text.length > 64_000) fail(413, "too_large", "request body exceeds 64 KB");
  try {
    const v = JSON.parse(text);
    if (!v || typeof v !== "object" || Array.isArray(v)) throw 0;
    return v;
  } catch { return fail(400, "bad_request", "the body must be a JSON object"); }
};
const str = (v: unknown, name: string, max = 4096): string => {
  if (typeof v !== "string" || !v || v.length > max) fail(400, "bad_request", `${name} is required`);
  return v as string;
};

interface Client { platform: Platform; install_id: string | null; app_version: string | null; device_model: string | null }
function client(v: any): Client {
  const platform = v?.platform;
  if (!["ios", "android", "web"].includes(platform)) fail(400, "bad_request", "client.platform must be ios, android or web");
  const install = typeof v.install_id === "string" ? v.install_id : null;
  if (platform !== "web" && !/^[0-9a-fA-F-]{36}$/.test(install ?? "")) fail(400, "bad_request", "client.install_id (a UUID) is required in the apps");
  const opt = (x: unknown) => (typeof x === "string" ? x.slice(0, 64) : null);
  return { platform, install_id: platform === "web" ? null : install, app_version: opt(v.app_version), device_model: opt(v.device_model) };
}
const ipOf = (c: C) => (c.req.header("cloudfront-viewer-address") ?? "").replace(/:\d+$/, "") || "0.0.0.0";

export function createApp(d: Deps) {
  const app = new Hono();
  const did = `did:web:${d.host}`, iss = `https://${d.host}`, origin = `https://${d.host}`;
  /** The calling client; a browser must send our Origin (login CSRF). */
  const clientOf = (c: C, v: unknown): Client => {
    const cl = client(v);
    if (cl.platform === "web" && c.req.header("origin") !== origin) fail(403, "bad_origin", "web sign-in must come from this origin");
    return cl;
  };
  const audiences = new Set([...PRODUCT_DIDS, did]);
  const tokenVerifyKey = importJWK({ ...d.keys.token.jwk, alg: "ES256" });

  app.onError((e, c) => {
    if (e instanceof HttpError) {
      const retry = e.extra.retry_after;
      if (retry) c.header("retry-after", String(retry));
      const { retry_after: _, ...extra } = e.extra;
      return c.json({ error: e.code, message: e.message, ...extra }, e.status as 400);
    }
    console.error(e);
    return c.json({ error: "internal", message: "internal error" }, 500);
  });
  app.notFound((c) => c.json({ error: "not_found", message: "no such endpoint" }, 404));
  app.use("*", async (c, next) => {
    await next();
    if (!c.res.headers.has("cache-control")) c.header("cache-control", "no-store");
  });

  // ---------- well-known ----------
  app.get("/.well-known/apple-app-site-association", (c) => c.json(aasa(), 200, { "cache-control": "public, max-age=3600" }));
  app.get("/.well-known/assetlinks.json", (c) => {
    const doc = assetlinks(d.androidFingerprints);
    return doc ? c.json(doc, 200, { "cache-control": "public, max-age=3600" }) : fail(404, "not_found", "no Android signing certificate is published yet");
  });
  app.get("/.well-known/jwks.json", (c) => c.json(jwks([d.keys.token]), 200, { "cache-control": "public, max-age=600" }));
  app.get("/.well-known/openid-configuration", (c) => c.json(openidConfiguration(d.host), 200, { "cache-control": "public, max-age=600" }));
  app.get("/.well-known/did.json", (c) => c.json(didDocument(d.host, { did: [d.keys.did], close: [d.keys.close] }), 200, { "cache-control": "public, max-age=600" }));
  app.get("/v1/health", (c) => c.json({ ok: true, stage: d.stage, version: d.version ?? "dev" }));

  // ---------- sign-in ----------
  const open = async (c: C, next: () => Promise<void>) => {
    if (!d.signinOpen) fail(503, "unavailable", "sign-in is not open in this environment yet");
    if ((await bump(d.db, `ip:${createHash("sha256").update(ipOf(c)).digest("hex").slice(0, 32)}`, String(Math.floor(now() / 60)))) > 60) {
      fail(429, "rate_limited", "too many sign-in requests from this address", { retry_after: 60 });
    }
    await next();
  };
  for (const p of ["/v1/auth/*", "/v1/token"]) app.use(p, open);

  app.post("/v1/auth/nonce", async (c) => {
    const b = await json(c);
    const cl = clientOf(c, b.client);
    const raw = randomBytes(32).toString("base64url"), t = now();
    await d.db.run("INSERT INTO auth_nonces (hash, platform, install_id, flow, created_at, expires_at) VALUES ($1, $2, $3, $4, $5, $6)",
      [nonceHash(raw), cl.platform, cl.install_id, "native", t, t + NONCE_TTL]);
    return c.json({ nonce: raw, expires_at: t + NONCE_TTL });
  });

  /** Consumes a nonce issued to this client. Single use; the platform and install must match. */
  async function useNonce(raw: string, cl: Client) {
    const row = await d.db.first<{ platform: string; install_id: string | null }>(
      "UPDATE auth_nonces SET used_at = $2 WHERE hash = $1 AND used_at IS NULL AND expires_at > $2 RETURNING platform, install_id", [nonceHash(raw), now()]);
    if (!row || row.platform !== cl.platform || (row.install_id ?? null) !== cl.install_id) fail(401, "nonce_invalid", "the nonce is unknown, expired, used, or was issued to another client");
  }

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

  async function accessToken(accountId: string, aud: string, sid: string, platform: string, authTime: number, amr: string, t = now()) {
    const a = await d.db.first<{ owner_did: string | null }>("SELECT owner_did FROM accounts WHERE id = $1", [accountId]);
    if (aud !== did && !a?.owner_did) fail(403, "key_log_required", "product tokens need an owner DID; finish \"Turn on Face ID approvals\" first");
    const token = await signJwt(d.keys.token, { typ: "at+jwt" }, {
      iss, sub: a?.owner_did ?? accountId, aud, iat: t, exp: t + ACCESS_TTL, jti: newId("at"), sid,
      client_id: platform === "web" ? "web" : BUNDLE_ID, auth_time: authTime, amr: [amr],
    });
    return { audience: aud, access_token: token, expires_at: t + ACCESS_TTL };
  }

  async function session(c: C, accountId: string, created: boolean, cl: Client, amr: string) {
    const s = await openSession(d.db, { accountId, platform: cl.platform, amr, installId: cl.install_id, deviceModel: cl.device_model, appVersion: cl.app_version });
    const at = await accessToken(accountId, did, s.sessionId, cl.platform, now(), amr);
    if (cl.platform === "web") c.header("set-cookie", `${COOKIE}=${s.refreshToken}; Path=/; Max-Age=${s.expiresAt - now()}; HttpOnly; Secure; SameSite=Strict`);
    return c.json({
      account: await me(accountId), new_account: created, token_type: "Bearer",
      access_token: at.access_token, access_expires_at: at.expires_at,
      ...(cl.platform === "web" ? {} : { refresh_token: s.refreshToken }), refresh_expires_at: s.expiresAt,
    });
  }

  async function signInWith(c: C, id: Identity, cl: Client) {
    const { accountId, created } = await accountFor(id.provider, id.sub, id.email, id.emailPrivate);
    return session(c, accountId, created, cl, id.provider);
  }

  app.post("/v1/auth/apple", async (c) => {
    const b = await json(c);
    const cl = clientOf(c, b.client), nonce = str(b.nonce, "nonce", 128);
    await useNonce(nonce, cl);
    return signInWith(c, await verifyApple(str(b.identity_token, "identity_token", 8192), { audience: cl.platform === "ios" ? d.apple.native : d.apple.web, nonce, keys: d.providerKeys?.apple }), cl);
  });

  app.post("/v1/auth/google", async (c) => {
    const b = await json(c);
    const cl = clientOf(c, b.client), nonce = str(b.nonce, "nonce", 128);
    await useNonce(nonce, cl);
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
      const caller = await bearer(c);
      accountId = caller.accountId;
      const a = await d.db.first<{ owner_did: string | null; email: string | null }>("SELECT owner_did, email FROM accounts WHERE id = $1", [accountId]);
      const has = await d.db.first("SELECT 1 FROM methods WHERE account_id = $1 AND type = 'passkey'", [accountId]);
      // Day 1: only the onboarding root passkey. More passkeys are a step-up action (method.add) from Day 5.
      if (a?.owner_did || has) fail(409, "passkey_exists", "this account has its root passkey; more passkeys are a step-up action (POST /v1/account/methods)");
      options = await registrationOptions(d.rp, { accountId, userName: a?.email ?? accountId });
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
      const caller = await bearer(c);
      if (caller.accountId !== ch!.account_id) fail(403, "forbidden", "this challenge belongs to another account");
      const r = await verifyRegistration(d.rp, b.response, ch!.challenge);
      const methodId = newId("mth"), t = now();
      await d.db.run("INSERT INTO methods (id, account_id, type, subject, data, created_at, last_used_at) VALUES ($1, $2, 'passkey', $3, $4, $5, $5)", [methodId, caller.accountId, r.credential.id, JSON.stringify({
        public_key: Buffer.from(r.credential.publicKey).toString("base64url"), counter: r.credential.counter, transports: r.credential.transports ?? [], aaguid: r.aaguid, backed_up: r.backedUp, jwk: r.jwk, key_id: r.keyId,
      }), t]);
      // The root Credential exactly as the key log carries it (test-vectors/keylog-1): the app puts it into the genesis entry.
      return c.json({ method_id: methodId, credential: { kid: r.keyId, type: "webauthn", jwk: r.jwk, credential_id: r.credential.id, rp_id: d.rp.id, aaguid: r.aaguid, label: "Passkey", platform: cl.platform } });
    }
    const credId = str(b.response.id, "response.id", 1024);
    const m = await d.db.first<{ account_id: string; data: string }>("SELECT account_id, data FROM methods WHERE type = 'passkey' AND subject = $1", [credId]);
    if (!m) fail(401, "passkey_invalid", "this passkey is not registered with an OpenEntity account");
    const data = JSON.parse(m!.data);
    const counter = await verifyAuthentication(d.rp, b.response, ch!.challenge, { id: credId, publicKey: Buffer.from(data.public_key, "base64url"), counter: data.counter, transports: data.transports });
    await d.db.run("UPDATE methods SET data = $2, last_used_at = $3 WHERE type = 'passkey' AND subject = $1", [credId, JSON.stringify({ ...data, counter }), now()]);
    return session(c, m!.account_id, false, cl, "passkey");
  });

  // ---------- tokens ----------
  app.post("/v1/token", async (c) => {
    const b = await json(c);
    if (b.grant_type !== "refresh_token") fail(400, "bad_request", "grant_type must be refresh_token");
    const web = !b.refresh_token;
    if (web && c.req.header("origin") !== origin) fail(403, "bad_origin", "cookie requests must come from this origin");
    const token = web ? getCookie(c, COOKIE) ?? fail(401, "invalid_grant", "no session cookie") : str(b.refresh_token, "refresh_token", 128);
    const aud: string[] = Array.isArray(b.audience) ? b.audience : fail(400, "bad_request", "audience must be an array of 1 to 5 DIDs");
    if (!aud.length || aud.length > 5 || new Set(aud).size !== aud.length || aud.some((a) => !audiences.has(a))) fail(400, "invalid_audience", `audience must be 1 to 5 distinct values from: ${[...audiences].join(", ")}`);
    // Day 2 adds the App Attest and Play Integrity binding checks here, against sessionOf(token).binding, before rotation.
    const r = await rotate(d.db, token);
    if ((r.session.platform === "web") !== web) fail(400, "bad_request", "apps send refresh_token in the body; the web uses the cookie");
    const tokens = [];
    for (const a of aud) tokens.push(await accessToken(r.session.account_id, a, r.session.id, r.session.platform, Number(r.session.auth_time), r.session.amr));
    if (web) c.header("set-cookie", `${COOKIE}=${r.refreshToken}; Path=/; Max-Age=${r.expiresAt - now()}; HttpOnly; Secure; SameSite=Strict`);
    return c.json({ token_type: "Bearer", ...(web ? {} : { refresh_token: r.refreshToken }), refresh_expires_at: r.expiresAt, tokens });
  });

  app.post("/v1/revoke", async (c) => {
    const b = await json(c).catch(() => ({} as Record<string, any>));
    const web = !b.refresh_token;
    const token = web ? getCookie(c, COOKIE) : String(b.refresh_token);
    if (web && c.req.header("origin") !== origin) fail(403, "bad_origin", "cookie requests must come from this origin");
    if (token) await revoke(d.db, token);
    if (web) c.header("set-cookie", `${COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict`);
    return c.body(null, 200);
  });

  // ---------- owner ----------
  /** The caller behind an access token for this service, whose session is still live. */
  async function bearer(c: C): Promise<{ accountId: string; sid: string; authTime: number }> {
    const h = c.req.header("authorization") ?? "";
    if (!h.startsWith("Bearer ")) fail(401, "unauthorized", "missing bearer token");
    let p;
    try {
      ({ payload: p } = await jwtVerify(h.slice(7), await tokenVerifyKey, { issuer: iss, audience: did, algorithms: ["ES256"], typ: "at+jwt" }));
    } catch (e) {
      if (e instanceof joseErrors.JOSEError) fail(401, "unauthorized", "invalid or expired access token");
      throw e;
    }
    const s = await d.db.first<{ account_id: string }>("SELECT account_id FROM sessions WHERE id = $1 AND revoked_at IS NULL AND expires_at > $2", [p!.sid, now()]);
    if (!s) fail(401, "unauthorized", "this session has ended");
    return { accountId: s!.account_id, sid: String(p!.sid), authTime: Number(p!.auth_time) };
  }

  async function me(accountId: string) {
    const a = await d.db.first<any>("SELECT * FROM accounts WHERE id = $1", [accountId]);
    const methods = await d.db.all<any>("SELECT id, type, subject, email, created_at, last_used_at FROM methods WHERE account_id = $1 ORDER BY created_at", [accountId]);
    return {
      id: a.id, owner_did: a.owner_did ?? null, email: a.email ?? null, email_private: !!a.email_private, created_at: Number(a.created_at),
      has_key_log: !!a.owner_did, backup_needed: !!a.owner_did, app_account_token: a.app_account_token,
      methods: methods.map((m) => ({ id: m.id, type: m.type, label: m.type === "email" ? m.subject : m.email ?? m.type, created_at: Number(m.created_at), last_used_at: m.last_used_at === null ? null : Number(m.last_used_at) })),
      deletion: null,
    };
  }

  app.get("/v1/me", async (c) => c.json(await me((await bearer(c)).accountId)));

  app.get("/v1/sessions", async (c) => {
    const caller = await bearer(c);
    const rows = await d.db.all<any>("SELECT id, platform, device_model, app_version, created_at, last_used_at FROM sessions WHERE account_id = $1 AND revoked_at IS NULL AND expires_at > $2 ORDER BY last_used_at DESC", [caller.accountId, now()]);
    return c.json({ sessions: rows.map((r) => ({ ...r, created_at: Number(r.created_at), last_used_at: Number(r.last_used_at), current: r.id === caller.sid })) });
  });

  app.delete("/v1/sessions/:id", async (c) => {
    const caller = await bearer(c);
    const r = await d.db.run("UPDATE sessions SET revoked_at = $3, revoke_reason = 'revoked_by_owner' WHERE id = $1 AND account_id = $2 AND revoked_at IS NULL", [c.req.param("id"), caller.accountId, now()]);
    if (!r.changes) fail(404, "not_found", "no such session");
    return c.body(null, 204);
  });

  return app;
}

