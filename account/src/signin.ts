// Sign-in (PLAN 2.3): nonce, Apple, Google, passkeys and the 8-digit email code. Web lane. app.ts runs the
// SIGNIN_OPEN gate and the per-IP limit on /v1/auth/* before these routes.
// Web sign-ups prove Turnstile; Apple's codes are exchanged so deletion can revoke Apple's tokens; a sign-in from a new
// install or browser tells the owner's other installs and the account email.
import { createHash, generateKeyPairSync, randomBytes, randomUUID } from "node:crypto";
import type { Context, Hono } from "hono";
import { getCookie } from "hono/cookie";
import { createRemoteJWKSet, errors as joseErrors, jwtVerify, SignJWT, type JWTVerifyGetKey } from "jose";
import type { Deps } from "./app.ts";
import { type AppleData, exchangeAppleCode } from "./apple.ts";
import { newId, now } from "./db.ts";
import { normalizeEmail, startEmail, verifyEmailCode } from "./email.ts";
import { bearer, fail, ipOf, json, str } from "./http.ts";
import { type Identity, appleKeys, googleKeys, nonceHash, verifyApple, verifyGoogle } from "./idtoken.ts";
import { notifyOwner } from "./notify.ts";
import { authenticationOptions, registrationOptions, verifyAuthentication, verifyRegistration } from "./passkey.ts";
import { COOKIE, type Platform, accessToken, me, openSession } from "./sessions.ts";
import { appAuthPage, homePage } from "./web/home.ts";

export const NONCE_TTL = 600, CHALLENGE_TTL = 300, LOGIN_CODE_TTL = 120;
/** A random id per browser, so a sign-in from a new browser can be told apart (PLAN 2.3, new install or browser). */
export const BROWSER = "__Host-oe_browser", STATE = "__Host-oe_state";
const TEST_KID = "oe-staging-test-idp";
/** Staging test sign-in by email takes only this domain, so it can never reach a real person's account. */
export const TEST_EMAIL_DOMAIN = "test.openentity.org";

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

/** Cloudflare Turnstile siteverify; the token must have been solved on this host. */
export async function turnstileOk(d: Deps, token: unknown, ip: string): Promise<boolean> {
  const t = d.web.turnstile;
  if (!t || typeof token !== "string" || !token || token.length > 2048) return false;
  const r = await (d.fetch ?? fetch)("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
    method: "POST", body: new URLSearchParams({ secret: t.secret, response: token, remoteip: ip }), signal: AbortSignal.timeout(5000),
  }).catch(() => null);
  const v: any = await r?.json().catch(() => null);
  return v?.success === true && v.hostname === d.host;
}

/**
 * Staging only: the test identity provider (PLAN 2.3) signs Apple-shaped and Google-shaped tokens with a staging key, and
 * staging accepts them beside the providers' own keys. Production never has it: webConfig reads no key there, and this
 * returns nothing outside staging even if one were set.
 */
export function testIdpOf(d: Deps) {
  return d.stage === "staging" ? d.web.testIdp : undefined;
}

/** Redeems an Android login code (POST /v1/token grant_type login_code): single use, 120 seconds, same install. */
export async function redeemLoginCode(d: Deps, code: string, installId: string | null): Promise<{ accountId: string; amr: string }> {
  const row = await d.db.first<{ account_id: string; install_id: string; amr: string }>(
    "UPDATE login_codes SET used_at = $2 WHERE hash = $1 AND used_at IS NULL AND expires_at > $2 RETURNING account_id, install_id, amr",
    [createHash("sha256").update(code).digest("hex"), now()]);
  if (!row || row.install_id !== installId) fail(401, "invalid_grant", "the login code is unknown, expired, used, or was issued to another install");
  return { accountId: row!.account_id, amr: row!.amr };
}

export function routes(app: Hono, d: Deps) {
  const did = `did:web:${d.host}`, origin = `https://${d.host}`, callback = `${origin}/v1/auth/apple/callback`;
  const test = testIdpOf(d);
  /** The providers' keys, plus the staging test key in staging only. */
  const keysFor = (provider: "apple" | "google"): JWTVerifyGetKey | undefined => d.providerKeys?.[provider] ?? (test
    ? (header, token) => (header.kid === TEST_KID ? test.publicKey : (provider === "apple" ? appleKeys : googleKeys)(header, token))
    : undefined);

  /** The calling client; a browser must send our Origin (login CSRF) and carries its browser id as its install id. */
  const clientOf = (c: Context, v: unknown): Client => {
    const cl = client(v);
    if (cl.platform !== "web") return cl;
    if (c.req.header("origin") !== origin) fail(403, "bad_origin", "web sign-in must come from this origin");
    let browser = getCookie(c, BROWSER);
    if (!browser || !/^[A-Za-z0-9_-]{22}$/.test(browser)) {
      browser = randomBytes(16).toString("base64url");
      c.header("set-cookie", `${BROWSER}=${browser}; Path=/; Max-Age=31536000; HttpOnly; Secure; SameSite=Lax`, { append: true });
    }
    return { ...cl, install_id: `web:${browser}` };
  };
  /** Web Apple and Google sign-ins prove Turnstile when they ask for a nonce. */
  const human = async (c: Context, token: unknown) => {
    if (!d.web.turnstile) fail(503, "unavailable", "web sign-in is not configured in this environment yet");
    if (typeof token !== "string" || !token) fail(403, "turnstile_required", "complete the human check first");
    if (!(await turnstileOk(d, token, ipOf(c)))) fail(403, "turnstile_invalid", "the human check did not pass; try again");
  };

  app.post("/v1/auth/nonce", async (c) => {
    const b = await json(c);
    const cl = clientOf(c, b.client);
    if (cl.platform === "web") await human(c, b.turnstile_token);
    const flow = b.flow === "apple_web" ? "apple_web" : (b.flow ?? "native") === "native" ? "native" : fail(400, "bad_request", "flow must be native or apple_web");
    if (flow === "apple_web" && cl.platform === "ios") fail(400, "bad_request", "iOS signs in with Apple natively");
    const returnTo = typeof b.return_to === "string" && /^\/(?![/\\])[\x21-\x7e]{0,511}$/.test(b.return_to) ? b.return_to : null;
    const raw = randomBytes(32).toString("base64url"), t = now();
    const state = flow === "apple_web" ? randomBytes(24).toString("base64url") : null;
    await d.db.run("INSERT INTO auth_nonces (hash, platform, install_id, flow, state, return_to, created_at, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
      [nonceHash(raw), cl.platform, cl.install_id, flow, state, returnTo, t, t + NONCE_TTL]);
    if (!state) return c.json({ nonce: raw, expires_at: t + NONCE_TTL });
    const servicesId = d.apple.web[0] ?? fail(503, "unavailable", "Sign in with Apple on the web is not configured in this environment yet");
    if (cl.platform === "web") c.header("set-cookie", `${STATE}=${state}; Path=/; Max-Age=${NONCE_TTL}; HttpOnly; Secure; SameSite=None`, { append: true });
    const authorize = new URL("https://appleid.apple.com/auth/authorize");
    authorize.search = new URLSearchParams({ client_id: servicesId, redirect_uri: callback, response_type: "code id_token", scope: "name email", response_mode: "form_post", state, nonce: nonceHash(raw) }).toString();
    return c.json({ nonce: raw, expires_at: t + NONCE_TTL, state, authorize_url: authorize.href });
  });

  /** The account for a verified identity, created on first sight. A verified email that already has an account is never merged silently. */
  async function accountFor(type: "apple" | "google" | "email" | "passkey", subject: string, email: string | null, emailPrivate: boolean, data: object = {}) {
    const t = now();
    const m = await d.db.first<{ account_id: string; data: string }>("SELECT account_id, data FROM methods WHERE type = $1 AND subject = $2", [type, subject]);
    if (m) {
      await d.db.run("UPDATE methods SET last_used_at = $3, data = $4 WHERE type = $1 AND subject = $2", [type, subject, t, JSON.stringify({ ...JSON.parse(m.data || "{}"), ...data })]);
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
      await tx.run("INSERT INTO methods (id, account_id, type, subject, email, data, created_at, last_used_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $7)",
        [newId("mth"), accountId, type, subject, email, JSON.stringify(data), t]);
    });
    return { accountId, created: true };
  }

  /** A sign-in from an install or browser this account never used is told to its other installs and the account email. */
  const isNew = async (accountId: string, created: boolean, cl: Client) =>
    !created && !!cl.install_id && !(await d.db.first("SELECT 1 FROM sessions WHERE account_id = $1 AND install_id = $2", [accountId, cl.install_id]));
  async function tell(accountId: string, cl: Client, amr: string, id: string) {
    const where = cl.platform === "web" ? "a web browser" : `${cl.platform === "ios" ? "an iPhone" : "an Android phone"}${cl.device_model ? ` (${cl.device_model})` : ""}`;
    await notifyOwner(d, accountId, {
      type: "signin.new", id, exceptInstall: cl.install_id,
      email: {
        subject: "New sign-in to your OpenEntity account",
        text: `Your OpenEntity account was signed in from ${where} with ${amr} on ${new Date().toUTCString()}.\n\nIf this was not you, open the OpenEntity app or https://${d.host}, end that session under Sessions, and remove any sign-in method you do not recognize.`,
      },
    });
  }

  /**
   * Every sign-in opens its session here, and only here. sessions.ts openSession enforces the install's device binding
   * (PLAN 2.4): the `attestation` in the request body over the sign-in's nonce, or for email and passkey the install's
   * newest unused nonce from POST /v1/auth/nonce; an install that attested before proves its key over the body instead.
   */
  async function open(c: Context, accountId: string, created: boolean, cl: Client, amr: string) {
    const fresh = await isNew(accountId, created, cl);
    const s = await openSession(c, d, { accountId, platform: cl.platform, amr, installId: cl.install_id, deviceModel: cl.device_model, appVersion: cl.app_version });
    if (fresh) await tell(accountId, cl, amr, s.sessionId);
    return s;
  }

  async function session(c: Context, accountId: string, created: boolean, cl: Client, amr: string) {
    const s = await open(c, accountId, created, cl, amr);
    const at = await accessToken(d, accountId, did, s.sessionId, cl.platform, now(), amr);
    if (cl.platform === "web") c.header("set-cookie", `${COOKIE}=${s.refreshToken}; Path=/; Max-Age=${s.expiresAt - now()}; HttpOnly; Secure; SameSite=Strict`, { append: true });
    return c.json({
      account: await me(d, accountId), new_account: created, token_type: "Bearer",
      access_token: at.access_token, access_expires_at: at.expires_at,
      ...(cl.platform === "web" ? {} : { refresh_token: s.refreshToken }), refresh_expires_at: s.expiresAt,
    });
  }

  async function signInWith(c: Context, id: Identity, cl: Client, data: object = {}) {
    const { accountId, created } = await accountFor(id.provider, id.sub, id.email, id.emailPrivate, data);
    return session(c, accountId, created, cl, id.provider);
  }

  app.post("/v1/auth/apple", async (c) => {
    const b = await json(c);
    const cl = clientOf(c, b.client), nonce = str(b.nonce, "nonce", 128);
    await useNonce(d, nonce, cl);
    const id = await verifyApple(str(b.identity_token, "identity_token", 8192), { audience: cl.platform === "ios" ? d.apple.native : d.apple.web, nonce, keys: keysFor("apple") });
    // The code Apple sent with the token: its refresh token is what deletion revokes. A staging test IdP token has no real code.
    const code = typeof b.authorization_code === "string" && b.authorization_code ? b.authorization_code : null;
    const data = code && !(test && id.sub.startsWith("test-")) ? await exchangeAppleCode(d, code, id.aud) : null;
    return signInWith(c, id, cl, data ?? {});
  });

  // Apple's form_post return for the web and Android (flow apple_web). Cross-site by design: the state and, on the web,
  // the state cookie stand in for the Origin check. Errors go to the App Link /app/auth, which the web serves as a page.
  app.post("/v1/auth/apple/callback", async (c) => {
    const back = (code: string) => c.redirect(`${origin}/app/auth?error=${code}`, 303);
    const f = await c.req.parseBody().catch(() => ({} as Record<string, unknown>));
    const state = typeof f.state === "string" ? f.state : "";
    const n = state && await d.db.first<{ hash: string; platform: string; install_id: string | null; return_to: string | null }>(
      "UPDATE auth_nonces SET used_at = $2 WHERE state = $1 AND flow = 'apple_web' AND used_at IS NULL AND expires_at > $2 RETURNING hash, platform, install_id, return_to", [state, now()]);
    if (!n || (n.platform === "web" && getCookie(c, STATE) !== state)) return back("state_invalid");
    c.header("set-cookie", `${STATE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=None`, { append: true });
    let id: Identity;
    try {
      id = await verifyApple(String(f.id_token ?? ""), { audience: d.apple.web, nonceHash: n.hash, keys: keysFor("apple") });
    } catch (e) {
      return back((e as { code?: string }).code === "nonce_invalid" ? "nonce_invalid" : "id_token_invalid");
    }
    let accountId: string, created: boolean;
    try {
      const data: AppleData | null = typeof f.code === "string" && f.code ? await exchangeAppleCode(d, f.code, id.aud, callback) : null;
      ({ accountId, created } = await accountFor("apple", id.sub, id.email, id.emailPrivate, data ?? {}));
    } catch (e) {
      return back((e as { code?: string }).code === "account_exists" ? "account_exists" : "provider_error");
    }
    const cl: Client = { platform: n.platform as Platform, install_id: n.install_id, app_version: null, device_model: null };
    if (cl.platform === "android") {
      // The app redeems the code at POST /v1/token (grant login_code), which opens its device-bound session.
      if (await isNew(accountId, created, cl)) await tell(accountId, cl, "apple", n.install_id ?? "android");
      const code = randomBytes(32).toString("base64url"), t = now();
      await d.db.run("INSERT INTO login_codes (hash, account_id, install_id, amr, created_at, expires_at) VALUES ($1, $2, $3, 'apple', $4, $5)",
        [createHash("sha256").update(code).digest("hex"), accountId, n.install_id, t, t + LOGIN_CODE_TTL]);
      return c.redirect(`${origin}/app/auth?login_code=${code}`, 303);
    }
    const s = await open(c, accountId, created, cl, "apple");
    c.header("set-cookie", `${COOKIE}=${s.refreshToken}; Path=/; Max-Age=${s.expiresAt - now()}; HttpOnly; Secure; SameSite=Strict`, { append: true });
    return c.redirect(`${origin}${n.return_to ?? "/"}`, 303);
  });

  // Sign in with Apple server-to-server notifications: email state changes, and consent revoked or account deleted at
  // Apple, which ends every session of that Apple sign-in.
  const appleNotices = createRemoteJWKSet(new URL("https://appleid.apple.com/auth/keys"));
  app.post("/v1/auth/apple/notifications", async (c) => {
    const b = await json(c);
    let p;
    try {
      ({ payload: p } = await jwtVerify(str(b.payload, "payload", 16_384), d.providerKeys?.apple ?? appleNotices, { issuer: "https://appleid.apple.com", audience: [...d.apple.native, ...d.apple.web], algorithms: ["RS256", "ES256"] }));
    } catch (e) {
      if (e instanceof joseErrors.JOSEError) fail(401, "payload_invalid", "the notification is not signed by Apple for this app");
      throw e;
    }
    let ev: any = p!.events;
    if (typeof ev === "string") { try { ev = JSON.parse(ev); } catch { fail(400, "bad_request", "events is not JSON"); } }
    const sub = typeof ev?.sub === "string" ? ev.sub : fail(400, "bad_request", "events.sub is required");
    const m = await d.db.first<{ account_id: string; data: string }>("SELECT account_id, data FROM methods WHERE type = 'apple' AND subject = $1", [sub]);
    if (!m) return c.body(null, 200);
    if (["consent-revoked", "account-delete", "account-deleted"].includes(ev.type)) {
      await d.db.run("UPDATE sessions SET revoked_at = $2, revoke_reason = $3 WHERE account_id = $1 AND amr = 'apple' AND revoked_at IS NULL", [m.account_id, now(), `apple_${String(ev.type).replace(/-/g, "_")}`]);
      await d.db.run("UPDATE methods SET data = '{}' WHERE type = 'apple' AND subject = $1", [sub]); // Apple ended it: nothing left to revoke
    } else if (ev.type === "email-disabled" || ev.type === "email-enabled") {
      // Recorded on the method: a private relay address that Apple stopped (or resumed) forwarding.
      await d.db.run("UPDATE methods SET data = $2 WHERE type = 'apple' AND subject = $1", [sub, JSON.stringify({ ...JSON.parse(m.data || "{}"), email_disabled: ev.type === "email-disabled" })]);
    }
    return c.body(null, 200);
  });

  app.post("/v1/auth/google", async (c) => {
    const b = await json(c);
    const cl = clientOf(c, b.client), nonce = str(b.nonce, "nonce", 128);
    await useNonce(d, nonce, cl);
    return signInWith(c, await verifyGoogle(str(b.id_token, "id_token", 8192), { audience: d.google, nonce, keys: keysFor("google") }), cl);
  });

  app.post("/v1/auth/email/start", async (c) => {
    const b = await json(c);
    const cl = clientOf(c, b.client);
    const email = normalizeEmail(str(b.email, "email", 254));
    const proven = cl.platform !== "web" || await turnstileOk(d, b.turnstile_token, ipOf(c));
    // Web sign-up needs Turnstile. Without it a code goes only to an existing email sign-in; the answer is the same either way.
    if (!proven && !(await d.db.first("SELECT 1 FROM methods m JOIN accounts a ON a.id = m.account_id WHERE m.type = 'email' AND m.subject = $1 AND a.deleted_at IS NULL", [email]))) {
      return c.json({ challenge_id: newId("eml"), expires_at: now() + 600 }, 202);
    }
    // The App Review demo address takes its fixed code (verify below), so nothing is mailed to it.
    const send = email === d.web.appReview?.email ? async () => {} : d.sendCode;
    const r = await startEmail(d.db, { email, installId: cl.install_id, pepper: d.pepper, send, human: proven });
    return c.json({ challenge_id: r.challengeId, expires_at: r.expiresAt }, 202);
  });

  app.post("/v1/auth/email/verify", async (c) => {
    const b = await json(c);
    const cl = clientOf(c, b.client);
    const challengeId = str(b.challenge_id, "challenge_id", 64);
    if (cl.platform === "web") {
      const row = await d.db.first<{ human: boolean }>("SELECT human FROM email_codes WHERE id = $1", [challengeId]);
      if (row && !row.human && !(await turnstileOk(d, b.turnstile_token, ipOf(c)))) fail(403, b.turnstile_token ? "turnstile_invalid" : "turnstile_required", "complete the human check first");
    }
    // App Review (PLAN 2.3): the demo address's fixed code works only while APP_REVIEW_OPEN is on, and every use is logged.
    const review = d.web.appReview?.openSince ? d.web.appReview : undefined;
    const email = await verifyEmailCode(d.db, { challengeId, code: String(b.code ?? ""), pepper: d.pepper, fixed: review && { email: review.email, code: review.code } });
    if (review && email === review.email) console.log(JSON.stringify({ audit: "app_review_sign_in", platform: cl.platform, install: cl.install_id, at: now() }));
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

  // The web pages: sign-in or the account at /, and /app/auth for the Apple return or an App Link opened in a browser.
  const home = (c: Context) => homePage({ serviceDid: did, rpId: d.rp.id, turnstile: d.web.turnstile?.siteKey ?? null, google: d.web.googleWebClientId ?? null, error: c.req.query("error") ?? null, testSignIn: !!test });
  for (const path of ["/", "/signup", "/login"]) app.get(path, home);
  app.get("/app/auth", (c) => appAuthPage({ error: c.req.query("error"), login_code: c.req.query("login_code") }));

  // Staging only (testIdpOf): Apple-shaped and Google-shaped tokens for automated sign-in tests. Absent in production.
  if (test) {
    app.post("/v1/auth/test-idp", async (c) => {
      const b = await json(c);
      // An email code for a test address, returned instead of mailed: web tests sign in without a mailbox or Turnstile.
      if (b.kind === "email") {
        const email = normalizeEmail(str(b.email, "email", 254));
        if (!email.endsWith(`@${TEST_EMAIL_DOMAIN}`)) fail(400, "bad_request", `test sign-in by email takes addresses @${TEST_EMAIL_DOMAIN} only`);
        let code = "";
        const r = await startEmail(d.db, { email, pepper: d.pepper, send: async (_e, sent) => { code = sent; }, human: true });
        return c.json({ challenge_id: r.challengeId, code, expires_at: r.expiresAt });
      }
      const kind = b.kind === "apple" || b.kind === "google" ? b.kind : fail(400, "bad_request", "kind must be apple, google or email");
      const sub = `test-${typeof b.sub === "string" && /^[A-Za-z0-9._-]{1,64}$/.test(b.sub) ? b.sub : randomUUID()}`;
      const t = now();
      const id_token = await new SignJWT({ nonce: nonceHash(str(b.nonce, "nonce", 128)), ...(typeof b.email === "string" ? { email: b.email.toLowerCase(), email_verified: true } : {}) })
        .setProtectedHeader({ alg: "ES256", kid: TEST_KID }).setIssuer(kind === "apple" ? "https://appleid.apple.com" : "https://accounts.google.com")
        .setAudience(kind === "apple" ? (b.client_id === "web" ? d.apple.web[0] ?? "" : d.apple.native[0]) : d.google[0] ?? "")
        .setSubject(sub).setIssuedAt(t).setExpirationTime(t + 600).sign(test.privateKey);
      return c.json({ id_token, sub });
    });
  }
}

export const APP_REVIEW_ALERT_DAYS = 21;
/**
 * jobs.ts: while APP_REVIEW_OPEN is on, publishes how many days it has been on (CloudWatch embedded metric
 * OpenEntity/Account AppReviewOpenDays; the stack alarms at 21) and logs an alert line from day 21 (PLAN 2.3).
 */
export async function appReviewWatch(d: Deps): Promise<void> {
  const since = d.web.appReview?.openSince;
  if (!since) return;
  const days = Math.floor((now() - since) / 86_400);
  console.log(JSON.stringify({
    _aws: { Timestamp: Date.now(), CloudWatchMetrics: [{ Namespace: "OpenEntity/Account", Dimensions: [["Stage"]], Metrics: [{ Name: "AppReviewOpenDays", Unit: "Count" }] }] },
    Stage: d.stage, AppReviewOpenDays: days,
  }));
  if (days >= APP_REVIEW_ALERT_DAYS) console.error(`ALERT: APP_REVIEW_OPEN has been on for ${days} days; turn it off with scripts/app-review.sh off ${d.stage}`);
}

/** A throwaway test IdP key for tests (never a real one). */
export const testIdpKey = () => {
  const k = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return { privateKey: k.privateKey, publicKey: k.publicKey };
};
