import { createHash, randomUUID } from "node:crypto";
import { expect, test } from "vitest";
import { createApp, type Deps } from "../src/app.ts";
import { deviceBinding } from "../src/binding.ts";
import { openSession } from "../src/sessions.ts";
import { account, caller, fakeAndroidKey, fakeAppAttest, testDeps } from "./helpers.ts";

const apple = fakeAppAttest(), google = fakeAndroidKey();
const revoked = new Set<string>();
const statusFetch = (async (url: RequestInfo | URL) => {
  if (String(url) === "https://android.googleapis.com/attestation/status") return Response.json({ entries: Object.fromEntries([...revoked].map((s) => [s, { status: "REVOKED" }])) });
  throw new Error(`unexpected fetch ${url}`);
}) as typeof fetch;
const staging = await testDeps({ attestRoots: { apple: [apple.root], google: [google.root] }, fetch: statusFetch });
const production = await testDeps({ stage: "production", attestRoots: { apple: [apple.root], google: [google.root] }, fetch: statusFetch });

/** A raw nonce issued to an install (what POST /v1/auth/nonce stores: only its SHA-256). */
async function nonceFor(d: Deps, install: string, platform: "ios" | "android") {
  const raw = randomUUID().replace(/-/g, "") + randomUUID().replace(/-/g, "").slice(0, 11);
  await d.db.run("INSERT INTO auth_nonces (hash, platform, install_id, flow, created_at, expires_at) VALUES ($1, $2, $3, 'native', $4, $5)",
    [createHash("sha256").update(raw).digest("hex"), platform, install, Math.floor(Date.now() / 1000), Math.floor(Date.now() / 1000) + 600]);
  return raw;
}
/** An app session with this binding, and a refresh call that signs its body as the app does. */
async function boundSession(d: Deps, platform: "ios" | "android", binding: string | null) {
  const s = await openSession(d.db, { accountId: await account(d.db), platform, amr: "email", installId: randomUUID(), binding });
  return s.refreshToken;
}
const refresh = (d: Deps, token: string, headers: (body: string) => Record<string, string> = () => ({}), extra: object = {}) => {
  const body = JSON.stringify({ grant_type: "refresh_token", refresh_token: token, audience: [`did:web:${d.host}`], ...extra });
  return caller(createApp(d))("POST", "/v1/token", body, headers(body));
};
const sha = (s: string) => createHash("sha256").update(s).digest();

test("iOS: the sign-in attestation over the install's own nonce binds the session; every refresh needs a rising App Attest assertion", async () => {
  const install = randomUUID(), raw = await nonceFor(staging, install, "ios");
  const att = apple.attest(sha(raw));
  // The email and passkey sign-ins carry no nonce: the attestation names one of the install's unused nonces.
  const binding = await deviceBinding(staging, { platform: "ios", installId: install, attestation: { type: "app_attest", key_id: att.key_id, attestation_object: att.attestation_object } });
  expect(JSON.parse(binding!)).toMatchObject({ type: "app_attest", key_id: att.key_id, counter: 0 });
  expect((await staging.db.first<any>("SELECT used_at FROM auth_nonces WHERE hash = $1", [sha(raw).toString("hex")])).used_at).not.toBeNull();
  let token = await boundSession(staging, "ios", binding);
  expect((await refresh(staging, token)).body.error).toBe("binding_required");
  const ok = await refresh(staging, token, (body) => ({ "x-oe-app-attest": att.assertion(sha(body)) }));
  expect(ok.status).toBe(200);
  token = ok.body.refresh_token;
  expect((await refresh(staging, token, (body) => ({ "x-oe-app-attest": att.assertion(sha(body), { counter: 1 }) }))).body.error).toBe("binding_invalid"); // counter did not rise
  expect((await refresh(staging, token, (body) => ({ "x-oe-app-attest": att.assertion(sha(`${body} `)) }))).body.error).toBe("binding_invalid"); // another body
  expect((await refresh(staging, token, (body) => ({ "x-oe-app-attest": apple.attest(sha(raw)).assertion(sha(body)) }))).body.error).toBe("binding_invalid"); // another key
  expect((await refresh(staging, token, (body) => ({ "x-oe-app-attest": att.assertion(sha(body)) }))).status).toBe(200);
});

test("Android: Key Attestation over the nonce binds the Keystore key; refreshes need its signature over the body", async () => {
  const install = randomUUID(), raw = await nonceFor(staging, install, "android");
  const k = google.attest(Buffer.from(raw));
  const binding = await deviceBinding(staging, { platform: "android", installId: install, attestation: { type: "android_key", certificate_chain: k.chain, integrity_token: "t" } });
  expect(JSON.parse(binding!)).toEqual({ type: "android_key", jwk: k.jwk, key_storage: "tee" });
  const token = await boundSession(staging, "android", binding);
  expect((await refresh(staging, token)).body.error).toBe("binding_required");
  expect((await refresh(staging, token, (body) => ({ "x-oe-device-signature": google.attest(Buffer.from(raw)).sign(body) }))).body.error).toBe("binding_invalid");
  const sign = (body: string) => ({ "x-oe-device-signature": k.sign(body) });
  expect((await refresh(staging, token, sign)).body.error).toBe("binding_invalid"); // gate hardening: no device_counter
  const one = await refresh(staging, token, sign, { device_counter: 1 });
  expect(one.status).toBe(200);
  expect((await refresh(staging, one.body.refresh_token, sign, { device_counter: 1 })).body.error).toBe("binding_invalid"); // not above the last
  expect((await refresh(staging, one.body.refresh_token, sign, { device_counter: 2 })).status).toBe(200);
});

test("Android Key Attestation guards: package, hardware level, generated key, revocation, the nonce, Google's chain", async () => {
  const bind = async (attest: (raw: string) => { chain: string[] }) => {
    const install = randomUUID(), raw = await nonceFor(staging, install, "android");
    return deviceBinding(staging, { platform: "android", installId: install, attestation: { type: "android_key", certificate_chain: attest(raw).chain, integrity_token: "t" } }).then(() => "bound", (e) => e.message);
  };
  expect(await bind((raw) => google.attest(Buffer.from(raw), { pkg: "com.evil.app" }))).toMatch(/com\.evil\.app/);
  expect(await bind((raw) => google.attest(Buffer.from(raw), { level: 0 }))).toMatch(/TrustedEnvironment/);
  expect(await bind((raw) => google.attest(Buffer.from(raw), { origin: 2 }))).toMatch(/generated/);
  expect(await bind(() => google.attest(Buffer.from("not the nonce")))).toMatch(/nonce/);
  expect(await bind((raw) => fakeAndroidKey().attest(Buffer.from(raw)))).toMatch(/root/);
  revoked.add("1"); // every test certificate has serial 1
  // The revocation list is cached for an hour; a fresh module copy would refetch, so check the serial path directly.
  const { verifyAndroidKey } = await import("../src/attest.ts");
  expect(() => verifyAndroidKey({ chain: google.attest(Buffer.from("x")).chain, biometric: false, packageName: "org.openentity.app", revoked, roots: [google.root] })).toThrow(/revoked/);
  revoked.clear();
  expect(await bind((raw) => google.attest(Buffer.from(raw)))).toBe("bound");
});

test("production: no app session without a binding; an install that never attested is refused; a later sign-in reuses the binding", async () => {
  expect((await refresh(production, await boundSession(production, "ios", null))).body.error).toBe("binding_required");
  const install = randomUUID();
  await expect(deviceBinding(production, { platform: "ios", installId: install, attestation: undefined })).rejects.toMatchObject({ code: "attestation_required" });
  const raw = await nonceFor(production, install, "ios");
  const att = apple.attest(sha(raw), { aaguid: "appattest\0\0\0\0\0\0\0" });
  const binding = await deviceBinding(production, { platform: "ios", installId: install, attestation: { type: "app_attest", key_id: att.key_id, attestation_object: att.attestation_object }, nonce: raw });
  await openSession(production.db, { accountId: await account(production.db), platform: "ios", amr: "apple", installId: install, binding });
  // A later sign-in from the install (a passkey, say) proves the same key over its own body, with no nonce.
  await expect(deviceBinding(production, { platform: "ios", installId: install, attestation: undefined })).rejects.toMatchObject({ code: "attestation_required" });
  const body = new TextEncoder().encode('{"challenge_id":"pkc_1"}');
  const proof = (h: string) => ({ header: (n: string) => (n === "x-oe-app-attest" ? h : undefined), body });
  const again = await deviceBinding(production, { platform: "ios", installId: install, attestation: undefined, proof: proof(att.assertion(sha(Buffer.from(body).toString()))) });
  expect(JSON.parse(again!)).toMatchObject({ key_id: att.key_id, counter: 1 });
  await expect(deviceBinding(production, { platform: "ios", installId: install, attestation: undefined, proof: proof(apple.attest(sha(raw)).assertion(sha(Buffer.from(body).toString()))) })).rejects.toMatchObject({ code: "attestation_invalid" });
  // Android in production: Play Integrity must be checked, and no decoder is configured here.
  const a = randomUUID(), r2 = await nonceFor(production, a, "android");
  await expect(deviceBinding(production, { platform: "android", installId: a, attestation: { type: "android_key", certificate_chain: google.attest(Buffer.from(r2)).chain, integrity_token: "t" } })).rejects.toMatchObject({ code: "unavailable" });
});

test("Play Integrity, when configured: the token must be for this request and app, and the device must meet integrity", async () => {
  const verdicts = new Map<string, any>();
  const d = await testDeps({ attestRoots: { google: [google.root] }, fetch: statusFetch, playIntegrity: async (t) => verdicts.get(t) ?? null });
  const install = randomUUID(), raw = await nonceFor(d, install, "android");
  const k = google.attest(Buffer.from(raw));
  const hash = sha(raw).toString("hex");
  verdicts.set("good", { requestHash: hash, packageName: "org.openentity.app", deviceIntegrity: ["MEETS_DEVICE_INTEGRITY"], appRecognition: "PLAY_RECOGNIZED" });
  verdicts.set("weak", { requestHash: hash, packageName: "org.openentity.app", deviceIntegrity: [], appRecognition: "PLAY_RECOGNIZED" });
  verdicts.set("other", { requestHash: "0".repeat(64), packageName: "org.openentity.app", deviceIntegrity: ["MEETS_DEVICE_INTEGRITY"], appRecognition: "PLAY_RECOGNIZED" });
  const bind = (token: string) => deviceBinding(d, { platform: "android", installId: install, attestation: { type: "android_key", certificate_chain: k.chain, integrity_token: token }, nonce: raw }).then(() => "bound", (e) => e.message);
  expect(await bind("weak")).toMatch(/device integrity/);
  expect(await bind("other")).toMatch(/not for this request/);
  expect(await bind("good")).toBe("bound");
});

test("openSession from a sign-in route reads the body's attestation and stores the binding", async () => {
  const app = createApp(staging), call = caller(app);
  const accountId = await account(staging.db);
  app.post("/test/open", async (c) => c.json(await openSession(c, staging, { accountId, platform: "ios", amr: "email", installId: c.req.query("install")! })));
  const install = randomUUID(), raw = await nonceFor(staging, install, "ios");
  const att = apple.attest(sha(raw));
  const r = await call("POST", `/test/open?install=${install}`, { code: "12345678", attestation: { type: "app_attest", key_id: att.key_id, attestation_object: att.attestation_object } });
  const row = await staging.db.first<any>("SELECT binding FROM sessions WHERE id = $1", [r.body.sessionId]);
  expect(JSON.parse(row.binding)).toMatchObject({ type: "app_attest", key_id: att.key_id });
});

test("login_code (Android Apple sign-in): redeemed once, by its install only, into a bound session and tokens", async () => {
  const call = caller(createApp(staging));
  const accountId = await account(staging.db), install = randomUUID(), t = Math.floor(Date.now() / 1000);
  for (const code of ["lc-1", "lc-2"]) await staging.db.run("INSERT INTO login_codes (hash, account_id, install_id, amr, created_at, expires_at) VALUES ($1, $2, $3, 'apple', $4, $5)",
    [sha(code).toString("hex"), accountId, install, t, t + 120]);
  const raw = await nonceFor(staging, install, "android");
  const k = google.attest(Buffer.from(raw));
  const redeem = (installId: string, code = "lc-1") => call("POST", "/v1/token", { grant_type: "urn:openentity:login_code", login_code: code, client: { platform: "android", install_id: installId }, audience: [`did:web:${staging.host}`], attestation: { type: "android_key", certificate_chain: k.chain, integrity_token: "t" } });
  expect((await redeem(randomUUID(), "lc-2")).body.error).toBe("invalid_grant"); // another install (the code is spent too)
  const ok = await redeem(install);
  expect(ok.status).toBe(200);
  expect(ok.body).toMatchObject({ token_type: "Bearer", refresh_token: expect.stringMatching(/^oert_/), tokens: [{ audience: `did:web:${staging.host}` }] });
  const s = await staging.db.first<any>("SELECT s.binding FROM sessions s JOIN refresh_tokens r ON r.session_id = s.id WHERE r.hash = $1", [createHash("sha256").update(ok.body.refresh_token).digest("hex")]);
  expect(JSON.parse(s.binding)).toMatchObject({ type: "android_key", jwk: k.jwk });
  expect((await redeem(install)).body.error).toBe("invalid_grant"); // single use
});
