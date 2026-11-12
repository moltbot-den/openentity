import { createHash, generateKeyPairSync, randomUUID } from "node:crypto";
import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT } from "jose";
import { describe, expect, test, vi } from "vitest";
import { createApp } from "../src/app.ts";
import { nonceHash } from "../src/idtoken.ts";
import { DECOY_FLOOR_MS, appReviewWatch, redeemLoginCode, testIdpKey } from "../src/signin.ts";
import { webConfig } from "../src/web/config.ts";
import { HOST, ORIGIN, call, webApp } from "./owner.ts";
import { VIEWER } from "./helpers.ts";

// Throwaway stand-ins, none real: an RSA key for Apple's published keys, a Turnstile siteverify, Apple's token and revoke
// endpoints, a KMS vault that only tags values, and an APNs sender that records.
const apple = await generateKeyPair("RS256");
const appleJwks = createLocalJWKSet({ keys: [{ ...(await exportJWK(apple.publicKey)), kid: "a1", alg: "RS256" }] });
const now = () => Math.floor(Date.now() / 1000);
const appleToken = (claims: Record<string, unknown>) => new SignJWT({ iss: "https://appleid.apple.com", iat: now(), exp: now() + 300, ...claims })
  .setProtectedHeader({ alg: "RS256", kid: "a1" }).sign(apple.privateKey);
const pushes: { install: string; type: string }[] = [];
const { d, app, out } = await webApp({
  deps: { apple: { native: ["org.openentity.app"], web: ["org.openentity.web"] }, providerKeys: { apple: appleJwks } },
  web: {
    turnstile: { siteKey: "site", secret: "secret" },
    apple: { teamId: "7R835D5LDZ", keyId: "KEYID12345", privateKey: generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey.export({ format: "pem", type: "pkcs8" }).toString() },
    vault: { seal: async (purpose, text) => `sealed:${purpose}:${text}`, open: async (purpose, s) => s.replace(`sealed:${purpose}:`, "") },
    apns: async (t, m) => { pushes.push({ install: t.token, type: m.type }); return null; },
  },
  answer: (url, init) => {
    if (url.includes("turnstile")) return Response.json({ success: new URLSearchParams(String(init?.body)).get("response") === "ok", hostname: HOST });
    if (url === "https://appleid.apple.com/auth/token") return Response.json({ refresh_token: `rt-${new URLSearchParams(String(init?.body)).get("code")}` });
    return undefined;
  },
});
const web = { platform: "web" }, fromUs = { origin: ORIGIN };
const ios = (install = randomUUID()) => ({ platform: "ios", install_id: install, device_model: "iPhone17,1" });

test("guard: web Apple and Google sign-ins prove Turnstile at the nonce", async () => {
  expect((await call(app, "POST", "/v1/auth/nonce", { client: web }, fromUs)).body.error).toBe("turnstile_required");
  expect((await call(app, "POST", "/v1/auth/nonce", { client: web, turnstile_token: "bad" }, fromUs)).body.error).toBe("turnstile_invalid");
  expect((await call(app, "POST", "/v1/auth/nonce", { client: web, turnstile_token: "ok" }, fromUs)).status).toBe(200);
  expect((await call(app, "POST", "/v1/auth/nonce", { client: ios() })).status).toBe(200); // apps prove themselves with attestation
});

test("guard: a web email start without Turnstile sends a code only to an existing email sign-in, and its verify needs Turnstile", async () => {
  const sent = out.codes.length;
  const decoy = await call(app, "POST", "/v1/auth/email/start", { email: "nobody@example.com", client: web }, fromUs);
  expect(decoy.status).toBe(202);
  expect(out.codes.length).toBe(sent); // nothing went out, and the answer looks the same
  const signup = await call(app, "POST", "/v1/auth/email/start", { email: "web1@example.com", client: web, turnstile_token: "ok" }, fromUs);
  expect((await call(app, "POST", "/v1/auth/email/verify", { challenge_id: signup.body.challenge_id, code: out.codes.at(-1), client: web }, fromUs)).status).toBe(200);
  const again = await call(app, "POST", "/v1/auth/email/start", { email: "web1@example.com", client: web }, fromUs);
  expect(out.codes.length).toBe(sent + 2);
  const body = { challenge_id: again.body.challenge_id, code: out.codes.at(-1), client: web };
  expect((await call(app, "POST", "/v1/auth/email/verify", body, fromUs)).body.error).toBe("turnstile_required");
  expect((await call(app, "POST", "/v1/auth/email/verify", { ...body, turnstile_token: "ok" }, fromUs)).status).toBe(200);
});

async function appleWeb(client: object, headers: Record<string, string> = fromUs) {
  const n = await call(app, "POST", "/v1/auth/nonce", { client, flow: "apple_web", return_to: "/approve", turnstile_token: "ok" }, headers);
  expect(n.status).toBe(200);
  return n;
}
const cookieOf = (r: { headers: Headers }, name: string) => r.headers.getSetCookie().find((v) => v.startsWith(`${name}=`));

test("Apple on the web: authorize URL, state cookie, form_post return with the session cookie, single-use state", async () => {
  const n = await appleWeb(web);
  const u = new URL(n.body.authorize_url);
  expect(Object.fromEntries(u.searchParams)).toEqual({
    client_id: "org.openentity.web", redirect_uri: `${ORIGIN}/v1/auth/apple/callback`, response_type: "code id_token", scope: "name email",
    response_mode: "form_post", state: n.body.state, nonce: nonceHash(n.body.nonce),
  });
  expect(cookieOf(n, "__Host-oe_state")).toMatch(/SameSite=None/);
  const form = new URLSearchParams({ state: n.body.state, code: "c1", id_token: await appleToken({ aud: "org.openentity.web", sub: "apple-web-1", nonce: nonceHash(n.body.nonce), email: "aw@example.com", email_verified: "true" }) });
  const post = (cookie: string) => app.request(`${ORIGIN}/v1/auth/apple/callback`, { method: "POST", body: form, headers: { "x-oe-viewer-address": VIEWER, "content-type": "application/x-www-form-urlencoded", origin: "https://appleid.apple.com", cookie } });
  const noCookie = await post("");
  expect(noCookie.headers.get("location")).toBe(`${ORIGIN}/app/auth?error=state_invalid`); // and the state is spent
  const n2 = await appleWeb(web);
  form.set("state", n2.body.state);
  form.set("id_token", await appleToken({ aud: "org.openentity.web", sub: "apple-web-1", nonce: nonceHash(n2.body.nonce) }));
  const ok = await post(`__Host-oe_state=${n2.body.state}`);
  expect([ok.status, ok.headers.get("location")]).toEqual([303, `${ORIGIN}/approve`]);
  expect(cookieOf(ok, "__Host-oe_session")).toMatch(/^__Host-oe_session=oert_.*SameSite=Strict$/);
  const m = await d.db.first<any>("SELECT data FROM methods WHERE type = 'apple' AND subject = 'apple-web-1'");
  expect(JSON.parse(m.data)).toEqual({ apple_refresh: "sealed:apple-refresh:rt-c1", apple_client_id: "org.openentity.web", apple_token_at: expect.any(Number) });
  expect((await post(`__Host-oe_state=${n2.body.state}`)).headers.get("location")).toBe(`${ORIGIN}/app/auth?error=state_invalid`);
});

test("Apple for Android: the form_post return gives a single-use login code for that install", async () => {
  const install = randomUUID();
  const n = await appleWeb({ platform: "android", install_id: install }, {});
  const form = new URLSearchParams({ state: n.body.state, id_token: await appleToken({ aud: "org.openentity.web", sub: "apple-android-1", nonce: nonceHash(n.body.nonce) }) });
  const r = await app.request(`${ORIGIN}/v1/auth/apple/callback`, { method: "POST", body: form, headers: { "x-oe-viewer-address": VIEWER, "content-type": "application/x-www-form-urlencoded" } });
  const code = new URL(r.headers.get("location")!).searchParams.get("login_code")!;
  expect(code).toMatch(/^[A-Za-z0-9_-]{43}$/);
  await expect(redeemLoginCode(d, code, randomUUID())).rejects.toMatchObject({ code: "invalid_grant" });
  const code2 = await (async () => {
    const n2 = await appleWeb({ platform: "android", install_id: install }, {});
    form.set("state", n2.body.state);
    form.set("id_token", await appleToken({ aud: "org.openentity.web", sub: "apple-android-1", nonce: nonceHash(n2.body.nonce) }));
    const r2 = await app.request(`${ORIGIN}/v1/auth/apple/callback`, { method: "POST", body: form, headers: { "x-oe-viewer-address": VIEWER, "content-type": "application/x-www-form-urlencoded" } });
    return new URL(r2.headers.get("location")!).searchParams.get("login_code")!;
  })();
  expect((await redeemLoginCode(d, code2, install)).amr).toBe("apple");
  await expect(redeemLoginCode(d, code2, install)).rejects.toMatchObject({ code: "invalid_grant" });
});

test("Apple native: the authorization code is exchanged and sealed; deletion revokes that token", async () => {
  const client = ios();
  const n = await call(app, "POST", "/v1/auth/nonce", { client });
  const r = await call(app, "POST", "/v1/auth/apple", {
    client, nonce: n.body.nonce, authorization_code: "c-native",
    identity_token: await appleToken({ aud: "org.openentity.app", sub: "apple-native-1", nonce: nonceHash(n.body.nonce) }),
  });
  expect(r.status).toBe(200);
  const tokenCall = out.calls.filter((c) => c.url === "https://appleid.apple.com/auth/token").at(-1)!;
  expect(Object.fromEntries(new URLSearchParams(tokenCall.body))).toMatchObject({ client_id: "org.openentity.app", code: "c-native", grant_type: "authorization_code" });
  expect((await call(app, "POST", "/v1/account/delete", undefined, { authorization: `Bearer ${r.body.access_token}` })).status).toBe(202);
  const revoke = out.calls.filter((c) => c.url === "https://appleid.apple.com/auth/revoke").at(-1)!;
  expect(Object.fromEntries(new URLSearchParams(revoke.body))).toMatchObject({ client_id: "org.openentity.app", token: "rt-c-native", token_type_hint: "refresh_token" });
});

test("Apple server notifications: consent revoked ends that Apple sign-in's sessions; unknown subjects are fine", async () => {
  const client = ios();
  const n = await call(app, "POST", "/v1/auth/nonce", { client });
  const r = await call(app, "POST", "/v1/auth/apple", { client, nonce: n.body.nonce, identity_token: await appleToken({ aud: "org.openentity.app", sub: "apple-s2s", nonce: nonceHash(n.body.nonce) }) });
  const auth = { authorization: `Bearer ${r.body.access_token}` };
  expect((await call(app, "GET", "/v1/me", undefined, auth)).status).toBe(200);
  const note = async (events: unknown) => call(app, "POST", "/v1/auth/apple/notifications", { payload: await appleToken({ aud: "org.openentity.app", events }) });
  expect((await note(JSON.stringify({ type: "consent-revoked", sub: "nobody" }))).status).toBe(200);
  expect((await note(JSON.stringify({ type: "consent-revoked", sub: "apple-s2s" }))).status).toBe(200);
  expect((await call(app, "GET", "/v1/me", undefined, auth)).status).toBe(401);
  expect((await call(app, "POST", "/v1/auth/apple/notifications", { payload: "x.y.z" })).body.error).toBe("payload_invalid");
});

test("a sign-in from a new install tells the other installs and the email; a known install or a new account does not", async () => {
  const first = ios(), second = ios();
  const signIn = async (client: object) => {
    const s = await call(app, "POST", "/v1/auth/email/start", { email: "devices@example.com", client });
    return call(app, "POST", "/v1/auth/email/verify", { challenge_id: s.body.challenge_id, code: out.codes.at(-1), client });
  };
  const a = await signIn(first);
  await call(app, "PUT", `/v1/push-tokens/${first.install_id}`, { provider: "apns", token: first.install_id, environment: "production" }, { authorization: `Bearer ${a.body.access_token}` });
  const mails = out.mail.length;
  await signIn(first);
  expect(out.mail.length).toBe(mails);
  await signIn(second);
  expect(out.mail.at(-1)).toMatchObject({ to: "devices@example.com", subject: "New sign-in to your OpenEntity account" });
  expect(out.mail.at(-1)!.text).toContain("an iPhone (iPhone17,1)");
  expect(pushes.at(-1)).toEqual({ install: first.install_id, type: "signin.new" });
});

test("guard: the App Review code works only for the demo address and only while APP_REVIEW_OPEN is on", async () => {
  const demo = { email: "review@openentity.org", code: "24681357" };
  const tryCode = async (a: ReturnType<typeof createApp>, email: string) => {
    const client = ios();
    const s = await call(a, "POST", "/v1/auth/email/start", { email, client });
    return call(a, "POST", "/v1/auth/email/verify", { challenge_id: s.body.challenge_id, code: demo.code, client });
  };
  const open = createApp({ ...d, web: { ...d.web, appReview: { ...demo, openSince: now() } } });
  const closed = createApp({ ...d, web: { ...d.web, appReview: { ...demo, openSince: null } } });
  expect((await tryCode(open, demo.email)).status).toBe(200);
  expect((await tryCode(open, "someone@example.com")).body.error).toBe("code_invalid");
  expect((await tryCode(closed, demo.email)).body.error).toBe("code_invalid");
  expect(webConfig({ app_review_email: demo.email, app_review_code: demo.code, app_review_open: "0" }, {}).appReview?.openSince).toBeNull();
});

test("staging test IdP: Apple-shaped tokens for automated sign-in tests", async () => {
  const key = testIdpKey();
  const staging = createApp({ ...d, providerKeys: undefined, web: { ...d.web, testIdp: key } });
  const client = ios();
  const n = await call(staging, "POST", "/v1/auth/nonce", { client });
  const t = await call(staging, "POST", "/v1/auth/test-idp", { kind: "apple", sub: "qa-1", nonce: n.body.nonce });
  expect(t.body.sub).toBe("test-qa-1");
  const r = await call(staging, "POST", "/v1/auth/apple", { client, nonce: n.body.nonce, identity_token: t.body.id_token, authorization_code: "none" });
  expect(r.status).toBe(200);
});

test("guard (PLAN 2.3, production): no test IdP route, and tokens signed by the staging test key are refused", async () => {
  const key = testIdpKey();
  // Even if a test key reached the production config, production neither serves nor trusts it.
  const prod = createApp({ ...d, stage: "production", web: { ...d.web, testIdp: key } });
  expect((await call(prod, "POST", "/v1/auth/test-idp", { kind: "apple", nonce: "x" })).status).toBe(404);
  const client = ios();
  const n = await call(prod, "POST", "/v1/auth/nonce", { client });
  const forged = await new SignJWT({ nonce: nonceHash(n.body.nonce) }).setProtectedHeader({ alg: "ES256", kid: "oe-staging-test-idp" })
    .setIssuer("https://appleid.apple.com").setAudience("org.openentity.app").setSubject("test-x").setIssuedAt().setExpirationTime("10m").sign(key.privateKey);
  expect((await call(prod, "POST", "/v1/auth/apple", { client, nonce: n.body.nonce, identity_token: forged, authorization_code: "none" })).body.error).toBe("id_token_invalid");
  // And the production config never reads the key at all.
  const pem = key.privateKey.export({ format: "pem", type: "pkcs8" }).toString();
  expect(webConfig({ test_idp_key: pem }, { STAGE: "production" }).testIdp).toBeUndefined();
  expect(webConfig({ test_idp_key: pem }, { STAGE: "staging" }).testIdp).toBeDefined();
  expect(createHash("sha256").update(pem).digest("hex")).toHaveLength(64);
});

test("the web pages: / with its config and a hash-only CSP that allows Turnstile and Google; /app/auth escapes what it shows", async () => {
  const { Script } = await import("node:vm");
  const r = await app.request(`${ORIGIN}/`);
  const html = await r.text(), csp = r.headers.get("content-security-policy")!;
  const script = /<script>([\s\S]*)<\/script><\/body>/.exec(html)![1];
  expect(csp).toContain(`script-src 'sha256-${createHash("sha256").update(script).digest("base64")}' https://challenges.cloudflare.com https://accounts.google.com/gsi/client`);
  expect(csp).toMatch(/frame-ancestors 'none'/);
  expect(csp).not.toMatch(/unsafe-inline|unsafe-eval/);
  expect(JSON.parse(/<script type="application\/json" id="cfg">(.*?)<\/script>/.exec(html)![1])).toEqual({ serviceDid: `did:web:${HOST}`, rpId: HOST, turnstile: "site", google: null, error: null, testSignIn: false });
  expect(() => new Script(script)).not.toThrow();
  expect(script).not.toMatch(/__name|require\(/);
  const landing = await (await app.request(`${ORIGIN}/app/auth?error=<script>alert(1)</script>`)).text();
  expect(landing).not.toContain("<script>alert");
  expect(landing).toContain("Sign-in did not finish.");
});

test("App Review watch: a CloudWatch metric of the days open, and an alert line from day 21", async () => {
  const log = vi.spyOn(console, "log").mockImplementation(() => {}), err = vi.spyOn(console, "error").mockImplementation(() => {});
  const at = (days: number) => ({ ...d, web: { appReview: { email: "r@example.com", code: "12345678", openSince: now() - days * 86_400 - 60 } } });
  await appReviewWatch(at(3));
  expect(JSON.parse(String(log.mock.calls.at(-1)![0]))).toMatchObject({ Stage: "staging", AppReviewOpenDays: 3, _aws: { CloudWatchMetrics: [{ Namespace: "OpenEntity/Account" }] } });
  expect(err).not.toHaveBeenCalled();
  await appReviewWatch(at(21));
  expect(String(err.mock.calls.at(-1)![0])).toContain("ALERT: APP_REVIEW_OPEN has been on for 21 days");
  log.mockClear();
  await appReviewWatch({ ...d, web: { appReview: { email: "r@example.com", code: "12345678", openSince: null } } });
  expect(log).not.toHaveBeenCalled();
  log.mockRestore(); err.mockRestore();
});

test("device binding at sign-in (production): an app's email sign-in fetches a nonce first and attests over it", async () => {
  const { fakeAppAttest } = await import("./helpers.ts");
  const fake = fakeAppAttest();
  const prod = createApp({ ...d, stage: "production", attestRoots: { apple: [fake.root] } });
  const client = ios();
  const code = async () => {
    const s = await call(prod, "POST", "/v1/auth/email/start", { email: "bound@example.com", client });
    return { challenge_id: s.body.challenge_id, code: out.codes.at(-1), client };
  };
  expect((await call(prod, "POST", "/v1/auth/email/verify", await code())).body.error).toBe("attestation_required");
  const n = await call(prod, "POST", "/v1/auth/nonce", { client });
  const att = fake.attest(createHash("sha256").update(n.body.nonce).digest(), { aaguid: "appattest\0\0\0\0\0\0\0" });
  const r = await call(prod, "POST", "/v1/auth/email/verify", { ...(await code()), attestation: { type: "app_attest", key_id: att.key_id, attestation_object: att.attestation_object } });
  expect(r.status).toBe(200);
  const s = await d.db.first<{ binding: string }>("SELECT binding FROM sessions WHERE install_id = $1 ORDER BY created_at DESC LIMIT 1", [client.install_id]);
  expect(JSON.parse(s!.binding)).toMatchObject({ type: "app_attest", key_id: att.key_id });
});

describe("gate fixes (Day 6 review)", () => {
  test("hardening: Apple server notices apply in order; a late consent-revoked does not end a newer session", async () => {
    await d.db.run("DELETE FROM rate_events");
    const client = ios();
    const n = await call(app, "POST", "/v1/auth/nonce", { client });
    const r = await call(app, "POST", "/v1/auth/apple", { client, nonce: n.body.nonce, identity_token: await appleToken({ aud: "org.openentity.app", sub: "apple-order", nonce: nonceHash(n.body.nonce) }) });
    const auth = { authorization: `Bearer ${r.body.access_token}` };
    const note = async (events: object) => call(app, "POST", "/v1/auth/apple/notifications", { payload: await appleToken({ aud: "org.openentity.app", events: JSON.stringify(events) }) });
    expect((await note({ type: "consent-revoked", sub: "apple-order", event_time: (now() - 120) * 1000 })).status).toBe(200);
    expect((await call(app, "GET", "/v1/me", undefined, auth)).status).toBe(200); // the session is newer than the revocation
    await note({ type: "email-enabled", sub: "apple-order", event_time: (now() - 10) * 1000 });
    await note({ type: "email-disabled", sub: "apple-order", event_time: (now() - 60) * 1000 }); // older: ignored
    expect(JSON.parse((await d.db.first<{ data: string }>("SELECT data FROM methods WHERE subject = 'apple-order'"))!.data).email_disabled).toBe(false);
    await note({ type: "consent-revoked", sub: "apple-order", event_time: now() + 1 }); // seconds, as in Apple's documented example
    expect((await call(app, "GET", "/v1/me", undefined, auth)).status).toBe(401); // a current revocation still ends it
  });

  test("M2: a session older than 5 minutes cannot register the root passkey before the key log", async () => {
    const { owner: makeOwner, bearer: auth } = await import("./owner.ts");
    const stale = await makeOwner(d, { keyLog: false, authAgo: 600 });
    const opts = await call(app, "POST", "/v1/auth/passkey/options", { mode: "register", client: { platform: "ios", install_id: stale.install } }, auth(stale));
    expect([opts.status, opts.body.error]).toEqual([401, "reauth_required"]);
    const fresh = await makeOwner(d, { keyLog: false });
    expect((await call(app, "POST", "/v1/auth/passkey/options", { mode: "register", client: { platform: "ios", install_id: fresh.install } }, auth(fresh))).status).toBe(200);
    // A challenge issued while fresh cannot be finished once the session is stale.
    await d.db.run("INSERT INTO passkey_challenges (id, challenge, mode, account_id, created_at, expires_at) VALUES ('pkc_stale', 'c', 'register', $1, $2, $3)", [stale.accountId, now(), now() + 300]);
    const verify = await call(app, "POST", "/v1/auth/passkey/verify", { challenge_id: "pkc_stale", response: { id: "x" }, client: { platform: "ios", install_id: stale.install } }, auth(stale));
    expect(verify.body.error).toBe("reauth_required");
  });

  test("lead: a login code of a deleted account is refused, and deletion removes its codes", async () => {
    const install = randomUUID();
    const n = await appleWeb({ platform: "android", install_id: install }, {});
    const form = new URLSearchParams({ state: n.body.state, id_token: await appleToken({ aud: "org.openentity.web", sub: "apple-deleted-1", nonce: nonceHash(n.body.nonce) }) });
    const r = await app.request(`${ORIGIN}/v1/auth/apple/callback`, { method: "POST", body: form, headers: { "content-type": "application/x-www-form-urlencoded" } });
    const code = new URL(r.headers.get("location")!).searchParams.get("login_code")!;
    const accountId = (await d.db.first<{ account_id: string }>("SELECT account_id FROM login_codes WHERE hash = $1", [createHash("sha256").update(code).digest("hex")]))!.account_id;
    await d.db.run("UPDATE accounts SET deleted_at = $2 WHERE id = $1", [accountId, now()]);
    await expect(redeemLoginCode(d, code, install)).rejects.toMatchObject({ code: "invalid_grant" });
    const { deleteAccount } = await import("../src/deletion.ts");
    await d.db.run("UPDATE accounts SET deleted_at = NULL WHERE id = $1", [accountId]);
    await deleteAccount(d, accountId);
    expect(await d.db.first("SELECT 1 FROM login_codes WHERE account_id = $1", [accountId])).toBeNull();
  });

  test("lead: a web email start without Turnstile answers alike for an address with and without an account", async () => {
    await d.db.run("DELETE FROM rate_events"); // this file's calls share one address
    const pass = async (email: string) => {
      const t0 = Date.now();
      const s = await call(app, "POST", "/v1/auth/email/start", { email, client: web }, fromUs);
      const slow = Date.now() - t0 >= DECOY_FLOOR_MS; // mailing or not, the same least time
      const v1 = await call(app, "POST", "/v1/auth/email/verify", { challenge_id: s.body.challenge_id, code: "00000000", client: web }, fromUs);
      const v2 = await call(app, "POST", "/v1/auth/email/verify", { challenge_id: s.body.challenge_id, code: "00000000", client: web, turnstile_token: "ok" }, fromUs);
      return [s.status, slow, v1.status, v1.body.error, v2.status, v2.body.error];
    };
    const k = await call(app, "POST", "/v1/auth/email/start", { email: "known-web@example.com", client: web, turnstile_token: "ok" }, fromUs);
    await call(app, "POST", "/v1/auth/email/verify", { challenge_id: k.body.challenge_id, code: out.codes.at(-1), client: web }, fromUs);
    expect(await pass("known-web@example.com")).toEqual(await pass("unknown-web@example.com"));
    expect(await pass("unknown-web-2@example.com")).toEqual([202, true, 403, "turnstile_required", 401, "code_invalid"]);
  });
});
