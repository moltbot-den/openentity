import { createPrivateKey, generateKeyPairSync, randomUUID, sign as nodeSign } from "node:crypto";
import { createLocalJWKSet, decodeProtectedHeader, exportJWK, generateKeyPair, importJWK, jwtVerify, SignJWT, type JWTPayload } from "jose";
import { expect, test } from "vitest";
import { createApp, type Deps } from "../src/app.ts";
import { nonceHash } from "../src/idtoken.ts";
import { derToJose, publicKey } from "../src/keys.ts";
import { rpFor } from "../src/passkey.ts";
import { pgliteDb, VIEWER } from "./helpers.ts";

// Throwaway keys per run: a P-256 token key and an Ed25519 DID key stand in for the KMS keys; an RSA key stands in
// for Apple's and Google's published keys. None of them is a real key.
const HOST = "staging.account.openentity.org", ORIGIN = `https://${HOST}`, DID = `did:web:${HOST}`;
const tokenPair = generateKeyPairSync("ec", { namedCurve: "P-256" });
const tokenKey = await publicKey(tokenPair.publicKey.export({ format: "jwk" }) as any, async (d) => derToJose(new Uint8Array(nodeSign("sha256", d, { key: tokenPair.privateKey, dsaEncoding: "der" }))));
const didPair = generateKeyPairSync("ed25519");
const didKey = await publicKey(didPair.publicKey.export({ format: "jwk" }) as any, async (d) => new Uint8Array(nodeSign(null, d, didPair.privateKey)));
const closePair = generateKeyPairSync("ec", { namedCurve: "P-256" });
const closeKey = await publicKey(closePair.publicKey.export({ format: "jwk" }) as any, async () => new Uint8Array(64));
const idp = await generateKeyPair("RS256");
const providerKeys = createLocalJWKSet({ keys: [{ ...(await exportJWK(idp.publicKey)), kid: "p1", alg: "RS256" }] });
const outbox: string[] = [];
const base: Deps = {
  stage: "staging", host: HOST, db: await pgliteDb(), keys: { token: tokenKey, did: didKey, close: closeKey }, pepper: "test-pepper",
  sendCode: async (_e, code) => { outbox.push(code); }, rp: rpFor(HOST),
  apple: { native: ["org.openentity.app"], web: ["org.openentity.app.web"] }, google: ["ios-client", "web-client"],
  androidFingerprints: [], signinOpen: true, providerKeys: { apple: providerKeys, google: providerKeys },
  // Turnstile's siteverify stand-in: the token "ok" passes on this host.
  web: { turnstile: { siteKey: "test-site-key", secret: "test-secret" } },
  fetch: (async (url: string, init?: RequestInit) => String(url).includes("turnstile")
    ? Response.json({ success: new URLSearchParams(String(init?.body)).get("response") === "ok", hostname: HOST })
    : new Response(null, { status: 204 })) as typeof fetch,
};
const app = createApp(base);

async function call(method: string, path: string, body?: unknown, headers: Record<string, string> = {}, a = app) {
  const res = await a.request(`${ORIGIN}${path}`, { method, headers: { "content-type": "application/json", "x-oe-viewer-address": VIEWER, ...headers }, body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await res.text();
  let json: any = null;
  try { json = JSON.parse(text); } catch { /* not JSON */ }
  return { status: res.status, body: json, headers: res.headers };
}
const ios = (install = randomUUID()) => ({ platform: "ios", install_id: install, app_version: "1.0 (1)", device_model: "iPhone17,1" });
const web = { platform: "web" };
const bearer = (t: string) => ({ authorization: `Bearer ${t}` });

async function emailSignIn(email: string, client: Record<string, unknown> = ios(), headers: Record<string, string> = {}) {
  const s = await call("POST", "/v1/auth/email/start", { email, client, ...(client.platform === "web" ? { turnstile_token: "ok" } : {}) }, headers);
  expect(s.status).toBe(202);
  return call("POST", "/v1/auth/email/verify", { challenge_id: s.body.challenge_id, code: outbox.at(-1), client }, headers);
}
const now = () => Math.floor(Date.now() / 1000);
const idToken = (claims: JWTPayload) => new SignJWT({ iat: now(), exp: now() + 300, ...claims }).setProtectedHeader({ alg: "RS256", kid: "p1" }).sign(idp.privateKey);

test("well-known: the AASA is JSON with webcredentials and applinks for the app, served without a redirect", async () => {
  const r = await call("GET", "/.well-known/apple-app-site-association");
  expect(r.status).toBe(200);
  expect(r.headers.get("content-type")).toMatch(/^application\/json/);
  expect(r.body.webcredentials.apps).toEqual(["7R835D5LDZ.org.openentity.app"]);
  expect(r.body.applinks.details[0].appIDs).toEqual(["7R835D5LDZ.org.openentity.app"]);
  expect((await call("GET", "/.well-known/assetlinks.json")).status).toBe(404); // until the Play signing fingerprint exists
});

test("well-known: jwks.json publishes the ES256 token key; did.json carries the Ed25519 service key and the P-256 close key", async () => {
  const k = (await call("GET", "/.well-known/jwks.json")).body.keys;
  expect(k).toEqual([{ ...tokenKey.jwk, kid: tokenKey.kid, alg: "ES256", use: "sig" }]);
  const d = (await call("GET", "/.well-known/did.json")).body;
  expect(d.id).toBe(DID);
  const ed = d.verificationMethod.find((v: any) => v.type === "Multikey");
  expect(ed.id).toBe(`${DID}#${didKey.kid}`);
  expect(ed.publicKeyMultibase).toMatch(/^z6Mk/);
  expect(d.authentication).toEqual([ed.id]);
  expect(d.assertionMethod).toEqual([ed.id, `${DID}#${closeKey.kid}`]);
  expect(d.verificationMethod.find((v: any) => v.type === "JsonWebKey").publicKeyJwk).toEqual(closeKey.jwk);
  expect(JSON.stringify(d)).not.toContain(tokenKey.kid); // tokens verify from jwks.json; did.json P-256 keys are close keys only
  expect((await call("GET", "/.well-known/openid-configuration")).body.issuer).toBe(ORIGIN);
});

test("email sign-in end to end: a session, an ES256 at+jwt for the service, /v1/me, rotation, and reuse ends the session at once", async () => {
  const r = await emailSignIn("e2e@example.com");
  expect(r.status).toBe(200);
  expect(r.body).toMatchObject({ new_account: true, token_type: "Bearer", account: { email: "e2e@example.com", has_key_log: false, owner_did: null } });
  expect(decodeProtectedHeader(r.body.access_token)).toEqual({ alg: "ES256", kid: tokenKey.kid, typ: "at+jwt" });
  const { payload } = await jwtVerify(r.body.access_token, await importJWK({ ...tokenKey.jwk, alg: "ES256" }), { issuer: ORIGIN, audience: DID, typ: "at+jwt" });
  expect(payload).toMatchObject({ sub: r.body.account.id, client_id: "org.openentity.app", amr: ["email"] });
  expect(payload.exp! - payload.iat!).toBe(900);
  expect((await call("GET", "/v1/me", undefined, bearer(r.body.access_token))).body.id).toBe(r.body.account.id);

  const t1 = await call("POST", "/v1/token", { grant_type: "refresh_token", refresh_token: r.body.refresh_token, audience: [DID] });
  expect(t1.status).toBe(200);
  expect(t1.body.tokens).toHaveLength(1);
  const t2 = await call("POST", "/v1/token", { grant_type: "refresh_token", refresh_token: t1.body.refresh_token, audience: [DID] });
  expect(t2.status).toBe(200);
  // The first token again, after its successor was used: the family is revoked and live access tokens stop working.
  expect((await call("POST", "/v1/token", { grant_type: "refresh_token", refresh_token: r.body.refresh_token, audience: [DID] })).body.error).toBe("token_reused");
  expect((await call("GET", "/v1/me", undefined, bearer(t2.body.tokens[0].access_token))).status).toBe(401);
});

test("guards: product tokens need an owner DID, audiences come from the list, and a second sign-in returns the same account", async () => {
  const r = await emailSignIn("guard@example.com");
  const ask = (audience: unknown) => call("POST", "/v1/token", { grant_type: "refresh_token", refresh_token: r.body.refresh_token, audience });
  expect((await ask(["did:web:moltbotden.com"])).body.error).toBe("key_log_required");
  for (const a of [[], ["did:web:evil.example"], [DID, DID], "did:web:moltbotden.com"]) expect((await ask(a)).status).toBe(400);
  const again = await emailSignIn("guard@example.com");
  expect(again.body).toMatchObject({ new_account: false, account: { id: r.body.account.id } });
});

test("Apple native: the nonce is single use and bound to its install; a verified email from another provider is never merged", async () => {
  const client = ios();
  const n = (await call("POST", "/v1/auth/nonce", { client })).body.nonce;
  const token = await idToken({ iss: "https://appleid.apple.com", aud: "org.openentity.app", sub: "apple-1", nonce: nonceHash(n), email: "merge@example.com", email_verified: "true" });
  expect((await call("POST", "/v1/auth/apple", { identity_token: token, authorization_code: "c", nonce: n, client: ios() })).body.error).toBe("nonce_invalid");
  const n2 = (await call("POST", "/v1/auth/nonce", { client })).body.nonce;
  const t2 = await idToken({ iss: "https://appleid.apple.com", aud: "org.openentity.app", sub: "apple-1", nonce: nonceHash(n2), email: "merge@example.com", email_verified: "true" });
  const ok = await call("POST", "/v1/auth/apple", { identity_token: t2, authorization_code: "c", nonce: n2, client });
  expect(ok.body).toMatchObject({ new_account: true, account: { email: "merge@example.com" } });
  expect((await call("POST", "/v1/auth/apple", { identity_token: t2, authorization_code: "c", nonce: n2, client })).body.error).toBe("nonce_invalid");
  const n3 = (await call("POST", "/v1/auth/nonce", { client })).body.nonce;
  const g = await idToken({ iss: "https://accounts.google.com", aud: "web-client", sub: "google-1", nonce: nonceHash(n3), email: "merge@example.com", email_verified: true });
  const clash = await call("POST", "/v1/auth/google", { id_token: g, nonce: n3, client });
  expect(clash.status).toBe(409);
  expect(clash.body).toMatchObject({ error: "account_exists", methods: ["apple"] });
});

test("web: the session lives in a __Host- cookie (HttpOnly, Secure, SameSite=Strict), never in the body, and cookie calls need our Origin", async () => {
  expect((await call("POST", "/v1/auth/email/start", { email: "web@example.com", client: web })).body.error).toBe("bad_origin");
  const r = await emailSignIn("web@example.com", web, { origin: ORIGIN });
  expect(r.body.refresh_token).toBeUndefined();
  const cookie = r.headers.getSetCookie().find((v) => v.startsWith("__Host-oe_session="))!;
  expect(cookie).toMatch(/^__Host-oe_session=oert_[A-Za-z0-9_-]{43}; Path=\/; Max-Age=432\d\d; HttpOnly; Secure; SameSite=Strict$/);
  const jar = { cookie: cookie.split(";")[0] };
  expect((await call("POST", "/v1/token", { grant_type: "refresh_token", audience: [DID] }, jar)).body.error).toBe("bad_origin");
  const t = await call("POST", "/v1/token", { grant_type: "refresh_token", audience: [DID] }, { ...jar, origin: ORIGIN });
  expect(t.status).toBe(200);
  expect(t.body.refresh_token).toBeUndefined();
  expect(t.headers.get("set-cookie")).toMatch(/^__Host-oe_session=oert_/);
});

test("sessions: the owner lists them and ends another device's session", async () => {
  const a = await emailSignIn("two@example.com");
  const b = await emailSignIn("two@example.com");
  const list = (await call("GET", "/v1/sessions", undefined, bearer(a.body.access_token))).body.sessions;
  expect(list.filter((s: any) => s.current)).toHaveLength(1);
  const other = list.find((s: any) => !s.current);
  expect((await call("DELETE", `/v1/sessions/${other.id}`, undefined, bearer(a.body.access_token))).status).toBe(204);
  expect((await call("GET", "/v1/me", undefined, bearer(b.body.access_token))).status).toBe(401);
  expect((await call("POST", "/v1/revoke", { refresh_token: a.body.refresh_token })).status).toBe(200);
  expect((await call("GET", "/v1/me", undefined, bearer(a.body.access_token))).status).toBe(401);
});

test("production stays closed: sign-in answers 503 while the well-known documents are served", async () => {
  const closed = createApp({ ...base, stage: "production", host: "account.openentity.org", signinOpen: false });
  expect((await call("POST", "/v1/auth/email/start", { email: "x@example.com", client: ios() }, {}, closed)).status).toBe(503);
  expect((await call("POST", "/v1/token", { grant_type: "refresh_token", refresh_token: "x", audience: ["did:web:account.openentity.org"] }, {}, closed)).status).toBe(503);
  expect((await call("GET", "/.well-known/apple-app-site-association", undefined, {}, closed)).status).toBe(200);
});

test("an Apple-shaped token signed by any key but the provider's is rejected (the staging test identity provider included)", async () => {
  const client = ios();
  const n = (await call("POST", "/v1/auth/nonce", { client })).body.nonce;
  const impostor = await generateKeyPair("RS256");
  const forged = await new SignJWT({ iss: "https://appleid.apple.com", aud: "org.openentity.app", sub: "x", nonce: nonceHash(n), iat: now(), exp: now() + 60 }).setProtectedHeader({ alg: "RS256", kid: "p1" }).sign(impostor.privateKey);
  expect((await call("POST", "/v1/auth/apple", { identity_token: forged, authorization_code: "c", nonce: n, client })).body.error).toBe("id_token_invalid");
});
