// OpenEntity Account HTTP API (account/openapi.yaml). This file holds the error format, well-known documents, the
// sign-in gate, tokens and sessions; every other area is a module with its own routes, registered at the end.
// Core lane: keylog, stepup, pairing, agents, events. Web lane: signin, methods, deletion, notify, store, approve.
import { createHash, type X509Certificate } from "node:crypto";
import { Hono, type Context } from "hono";
import { getCookie } from "hono/cookie";
import type { JWTVerifyGetKey } from "jose";
import * as agents from "./agents.ts";
import * as approve from "./approve.ts";
import { type IntegrityVerdict, checkBinding } from "./binding.ts";
import { type Db, bump, now } from "./db.ts";
import * as deletion from "./deletion.ts";
import type { SendCode } from "./email.ts";
import * as events from "./events.ts";
import type { QueuedEvent } from "./events.ts";
import { HttpError, bearer, fail, ipOf, json, str } from "./http.ts";
import type { SigningKey } from "./keys.ts";
import * as keylog from "./keylog.ts";
import * as methods from "./methods.ts";
import * as notify from "./notify.ts";
import * as pairing from "./pairing.ts";
import type { Rp } from "./passkey.ts";
import { COOKIE, accessToken, me, openSession, revoke, rotate, sessionOf } from "./sessions.ts";
import * as signin from "./signin.ts";
import * as stepup from "./stepup.ts";
import * as store from "./store.ts";
import type { WebConfig } from "./web/config.ts";
import type { WsClient } from "./ws.ts";
import type { Blobs } from "./blobs.ts";
import { PRODUCT_DIDS, aasa, assetlinks, didDocument, jwks, openidConfiguration } from "./wellknown.ts";

export { PRODUCT_DIDS };

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
  /** The web lane's settings (account/src/web/config.ts). */
  web: WebConfig;
  /** Product API base URLs by product DID; default outbound.ts PRODUCT_APIS. */
  products?: Record<string, string>;
  /** Outbound HTTP to products; tests pass a fake. */
  fetch?: typeof fetch;
  /** Frames to agents' open sockets (ws.ts); unset, frames wait in the inbox. */
  ws?: WsClient;
  /** Message attachments in S3 (blobs.ts); unset, uploads answer 503. */
  blobs?: Blobs;
  /** Sends validated analytics events to the forwarder's queue (events.ts); unset, events are dropped with a warning. */
  queue?: (events: QueuedEvent[]) => Promise<void>;
  /** Tests only: stand-in attestation roots. Production pins Apple's and Google's roots (attest.ts). */
  attestRoots?: { apple?: X509Certificate[]; google?: X509Certificate[] };
  /** Decodes a Play Integrity token through Google; unset until this environment has Google credentials. */
  playIntegrity?: (token: string) => Promise<IntegrityVerdict | null>;
  /** Tests only: stand-ins for Apple's and Google's published keys. Production uses the providers' JWKS. */
  providerKeys?: { apple?: JWTVerifyGetKey; google?: JWTVerifyGetKey };
}

type C = Context;

export function createApp(d: Deps) {
  const app = new Hono();
  const did = `did:web:${d.host}`, origin = `https://${d.host}`;
  const audiences = new Set([...PRODUCT_DIDS, did]);

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

  // ---------- sign-in gate: SIGNIN_OPEN and 60 requests a minute per address, before the sign-in routes (signin.ts) ----------
  const open = async (c: C, next: () => Promise<void>) => {
    if (!d.signinOpen) fail(503, "unavailable", "sign-in is not open in this environment yet");
    if ((await bump(d.db, `ip:${createHash("sha256").update(ipOf(c)).digest("hex").slice(0, 32)}`, String(Math.floor(now() / 60)))) > 60) {
      fail(429, "rate_limited", "too many sign-in requests from this address", { retry_after: 60 });
    }
    await next();
  };
  for (const p of ["/v1/auth/*", "/v1/token"]) app.use(p, open);

  // ---------- tokens ----------
  app.post("/v1/token", async (c) => {
    const b = await json(c);
    const aud: string[] = Array.isArray(b.audience) ? b.audience : fail(400, "bad_request", "audience must be an array of 1 to 5 DIDs");
    if (!aud.length || aud.length > 5 || new Set(aud).size !== aud.length || aud.some((a) => !audiences.has(a))) fail(400, "invalid_audience", `audience must be 1 to 5 distinct values from: ${[...audiences].join(", ")}`);
    if (b.grant_type === "login_code" || b.grant_type === "urn:openentity:login_code") {
      // Android Apple sign-in: the code from /v1/auth/apple/callback, single use, 120 s, this install only (signin.ts).
      const platform = b.client?.platform, install = b.client?.install_id;
      if ((platform !== "android" && platform !== "ios") || typeof install !== "string" || !/^[0-9a-fA-F-]{36}$/.test(install)) fail(400, "bad_request", "client with platform and install_id is required");
      const { accountId, amr } = await signin.redeemLoginCode(d, str(b.login_code, "login_code", 128), install);
      const s = await openSession(c, d, { accountId, platform, amr, installId: install, deviceModel: typeof b.client.device_model === "string" ? b.client.device_model.slice(0, 64) : null, appVersion: typeof b.client.app_version === "string" ? b.client.app_version.slice(0, 64) : null });
      const t = now(), tokens = [];
      for (const a of aud) tokens.push(await accessToken(d, accountId, a, s.sessionId, platform, t, amr, t));
      return c.json({ token_type: "Bearer", refresh_token: s.refreshToken, refresh_expires_at: s.expiresAt, tokens });
    }
    if (b.grant_type !== "refresh_token") fail(400, "bad_request", "grant_type must be refresh_token or login_code");
    const web = !b.refresh_token;
    if (web && c.req.header("origin") !== origin) fail(403, "bad_origin", "cookie requests must come from this origin");
    const token = web ? getCookie(c, COOKIE) ?? fail(401, "invalid_grant", "no session cookie") : str(b.refresh_token, "refresh_token", 128);
    // Device binding: an app proves its install's key over this body before the token rotates (binding.ts).
    const s = await sessionOf(d.db, token);
    if (s) await checkBinding(c, d, s, new TextEncoder().encode(await c.req.text()));
    const r = await rotate(d.db, token);
    if ((r.session.platform === "web") !== web) fail(400, "bad_request", "apps send refresh_token in the body; the web uses the cookie");
    const tokens = [];
    for (const a of aud) tokens.push(await accessToken(d, r.session.account_id, a, r.session.id, r.session.platform, Number(r.session.auth_time), r.session.amr));
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
  app.get("/v1/me", async (c) => c.json(await me(d, (await bearer(c, d)).accountId)));

  app.get("/v1/sessions", async (c) => {
    const caller = await bearer(c, d);
    const rows = await d.db.all<any>("SELECT id, platform, device_model, app_version, created_at, last_used_at FROM sessions WHERE account_id = $1 AND revoked_at IS NULL AND expires_at > $2 ORDER BY last_used_at DESC", [caller.accountId, now()]);
    return c.json({ sessions: rows.map((r) => ({ ...r, created_at: Number(r.created_at), last_used_at: Number(r.last_used_at), current: r.id === caller.sid })) });
  });

  app.delete("/v1/sessions/:id", async (c) => {
    const caller = await bearer(c, d);
    const r = await d.db.run("UPDATE sessions SET revoked_at = $3, revoke_reason = 'revoked_by_owner' WHERE id = $1 AND account_id = $2 AND revoked_at IS NULL", [c.req.param("id"), caller.accountId, now()]);
    if (!r.changes) fail(404, "not_found", "no such session");
    return c.body(null, 204);
  });

  for (const m of [signin, methods, deletion, notify, store, approve, keylog, stepup, pairing, agents, events]) m.routes(app, d);
  return app;
}

