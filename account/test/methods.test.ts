import { createLocalJWKSet, exportJWK, generateKeyPair, jwtVerify, SignJWT, importJWK } from "jose";
import { expect, test } from "vitest";
import { nonceHash } from "../src/idtoken.ts";
import { SERVICE, approvalHeader, approve, bearer, call, owner, stepUp, webApp, type Owner } from "./owner.ts";

// A throwaway RSA key stands in for Google's published keys.
const idp = await generateKeyPair("RS256");
const providerKeys = createLocalJWKSet({ keys: [{ ...(await exportJWK(idp.publicKey)), kid: "g1", alg: "RS256" }] });
const { d, app, out } = await webApp({ deps: { google: ["web-client"], providerKeys: { google: providerKeys } } });
const now = () => Math.floor(Date.now() / 1000);

async function emailProof(email: string) {
  const s = await call(app, "POST", "/v1/auth/email/start", { email, client: { platform: "ios", install_id: crypto.randomUUID() } });
  expect(s.status).toBe(202);
  return { challenge_id: s.body.challenge_id, code: out.codes.at(-1) };
}
async function googleProof(o: Owner, sub: string) {
  const n = await call(app, "POST", "/v1/auth/nonce", { client: { platform: "ios", install_id: o.install } });
  const id_token = await new SignJWT({ iss: "https://accounts.google.com", aud: "web-client", sub, nonce: nonceHash(n.body.nonce), iat: now(), exp: now() + 300 })
    .setProtectedHeader({ alg: "RS256", kid: "g1" }).sign(idp.privateKey);
  return { id_token, nonce: n.body.nonce };
}
async function emailMethod(o: Owner, email = `${o.accountId}@example.com`) {
  await d.db.run("INSERT INTO methods (id, account_id, type, subject, email, created_at) VALUES ($1, $2, 'email', $3, $3, $4)", [`mth_${o.accountId.slice(5)}`, o.accountId, email, now()]);
  return `mth_${o.accountId.slice(5)}`;
}

test("guard: adding a sign-in method needs step-up method.add; a session alone and a no-key-log account are refused", async () => {
  const none = await owner(d, { keyLog: false });
  expect((await call(app, "POST", "/v1/account/methods", { type: "email", proof: await emailProof("a1@example.com") }, bearer(none))).body.error).toBe("key_log_required");
  const o = await owner(d);
  expect((await call(app, "POST", "/v1/account/methods", { type: "email", proof: await emailProof("a2@example.com") }, bearer(o))).status).toBe(428);
  const r = await call(app, "POST", "/v1/account/methods", { type: "google", proof: await googleProof(o, "g-123") }, await stepUp(app, o, "method.add", { type: "google", subject: "g-123" }));
  expect(r.status).toBe(201);
  expect(r.body).toMatchObject({ type: "google" });
  expect((await call(app, "GET", "/v1/account/methods", undefined, bearer(o))).body.methods.map((m: any) => m.type)).toEqual(["google"]);
  // The same Google account cannot join a second account: accounts never merge.
  const other = await owner(d);
  const again = await call(app, "POST", "/v1/account/methods", { type: "google", proof: await googleProof(other, "g-123") }, await stepUp(app, other, "method.add", { type: "google", subject: "g-123" }));
  expect(again.body.error).toBe("method_exists");
});

test("guard: an approval for one method type does not add another", async () => {
  const o = await owner(d);
  const forGoogle = await stepUp(app, o, "method.add", { type: "google", subject: "a3@example.com" });
  expect((await call(app, "POST", "/v1/account/methods", { type: "email", proof: await emailProof("a3@example.com") }, forGoogle)).body.error).toBe("approval_invalid");
});

test("guard: removing a method needs step-up method.remove for that method; never the last one", async () => {
  const o = await owner(d);
  const keep = await emailMethod(o);
  expect((await call(app, "DELETE", `/v1/account/methods/${keep}`, undefined, bearer(o))).body.error).toBe("last_method");
  await call(app, "POST", "/v1/account/methods", { type: "google", proof: await googleProof(o, "g-remove") }, await stepUp(app, o, "method.add", { type: "google", subject: "g-remove" }));
  expect((await call(app, "DELETE", `/v1/account/methods/${keep}`, undefined, bearer(o))).status).toBe(428);
  expect((await call(app, "DELETE", "/v1/account/methods/mth_nope", undefined, bearer(o))).status).toBe(404);
  const r = await call(app, "DELETE", `/v1/account/methods/${keep}`, undefined, await stepUp(app, o, "method.remove", { method_id: keep }));
  expect(r.status).toBe(204);
  expect((await call(app, "GET", "/v1/account/methods", undefined, bearer(o))).body.methods.map((m: any) => m.type)).toEqual(["google"]);
});

test("guard: changing the email needs step-up email.change for that address and a code sent to it", async () => {
  const o = await owner(d);
  expect((await call(app, "PUT", "/v1/account/email", await emailProof("new1@example.com"), bearer(o))).status).toBe(428);
  const wrong = await stepUp(app, o, "email.change", { email: "someone-else@example.com" });
  expect((await call(app, "PUT", "/v1/account/email", await emailProof("new2@example.com"), wrong)).body.error).toBe("approval_invalid");
  const r = await call(app, "PUT", "/v1/account/email", await emailProof("New3@Example.com"), await stepUp(app, o, "email.change", { email: "new3@example.com" }));
  expect([r.status, r.body.email]).toEqual([200, "new3@example.com"]);
  const none = await owner(d, { keyLog: false });
  expect((await call(app, "PUT", "/v1/account/email", await emailProof("new4@example.com"), bearer(none))).body.error).toBe("key_log_required");
});

test("guard: a passkey registered after the key log is an approver key, not a sign-in method", async () => {
  const o = await owner(d);
  await d.db.run("INSERT INTO methods (id, account_id, type, subject, data, created_at) VALUES ('mth_pending1', $1, 'passkey', 'cGVuZGluZw', '{\"pending\":true}', 1)", [o.accountId]);
  expect((await call(app, "GET", "/v1/account/methods", undefined, bearer(o))).body.methods).toEqual([]);
  const opts = await call(app, "POST", "/v1/auth/passkey/options", { mode: "authenticate", client: { platform: "ios", install_id: o.install } });
  const r = await call(app, "POST", "/v1/auth/passkey/verify", { challenge_id: opts.body.challenge_id, client: { platform: "ios", install_id: o.install }, response: { id: "cGVuZGluZw", rawId: "cGVuZGluZw", type: "public-key", response: {} } });
  expect([r.status, r.body.error]).toEqual([401, "passkey_invalid"]);
});

test("guard: product links need step-up product.link; the envelope is EdDSA by the service key, single use", async () => {
  const none = await owner(d, { keyLog: false });
  expect((await call(app, "POST", "/v1/account/links", { product: "did:web:api.clawgrc.com" }, bearer(none))).body.error).toBe("key_log_required");
  const o = await owner(d);
  expect((await call(app, "POST", "/v1/account/links", { product: "did:web:evil.example" }, bearer(o))).body.error).toBe("unknown_product");
  expect((await call(app, "POST", "/v1/account/links", { product: "did:web:api.clawgrc.com" }, bearer(o))).status).toBe(428);
  const h = await stepUp(app, o, "product.link", { product: "did:web:api.clawgrc.com" });
  expect((await call(app, "POST", "/v1/account/links", { product: "did:web:moltbotden.com" }, h)).body.error).toBe("approval_invalid");
  const r = await call(app, "POST", "/v1/account/links", { product: "did:web:api.clawgrc.com" }, h);
  expect(r.status).toBe(200);
  expect(r.body.link_url).toBe(`https://clawgrc.com/oe/link#envelope=${r.body.envelope}`);
  const { payload, protectedHeader } = await jwtVerify(r.body.envelope, await importJWK({ ...d.keys.did.jwk, alg: "EdDSA" }), { typ: "oe-link-owner+jwt", audience: "did:web:api.clawgrc.com", issuer: SERVICE });
  expect(protectedHeader).toMatchObject({ alg: "EdDSA", kid: `${SERVICE}#${d.keys.did.kid}` });
  expect(payload).toMatchObject({ sub: o.ownerDid, purpose: "link-owner" });
  expect(payload.exp! - payload.iat!).toBe(600);
  expect(String(payload.jti)).toMatch(/^lnk_[A-Za-z0-9]{26}$/);
  expect((await call(app, "POST", "/v1/account/links", { product: "did:web:api.clawgrc.com" }, h)).body.error).toBe("approval_reused");
});

test("guard: a deny decision never passes a step-up", async () => {
  const o = await owner(d);
  const r = await call(app, "POST", "/v1/step-up", { action: "product.link", params: { product: "did:web:api.clawgrc.com" } }, bearer(o));
  const denied = approvalHeader(approve(o.approver!, r.body, "deny"));
  expect((await call(app, "POST", "/v1/account/links", { product: "did:web:api.clawgrc.com" }, { ...bearer(o), ...denied })).body.error).toBe("approval_invalid");
});

test("guard matrix (PLAN 2.4): every web step-up action refuses a session alone and an account with no key log", async () => {
  const withLog = await owner(d), noLog = await owner(d, { keyLog: false, authAgo: 600 });
  const mth = await emailMethod(withLog), mthNoLog = await emailMethod(noLog);
  await d.db.run("INSERT INTO methods (id, account_id, type, subject, created_at) VALUES ($1, $2, 'google', $3, 1), ($4, $5, 'google', $6, 1)",
    [`${mth}g`, withLog.accountId, `g-${withLog.accountId}`, `${mthNoLog}g`, noLog.accountId, `g-${noLog.accountId}`]);
  const actions: [string, string, (o: Owner, m: string) => Promise<unknown> | unknown, string][] = [
    ["POST", "/v1/account/methods", async () => ({ type: "email", proof: await emailProof(`m-${Math.random()}@example.com`) }), "key_log_required"],
    ["DELETE", "/v1/account/methods/{m}", () => undefined, "key_log_required"],
    ["PUT", "/v1/account/email", async () => emailProof(`e-${Math.random()}@example.com`), "key_log_required"],
    ["POST", "/v1/account/links", () => ({ product: "did:web:moltbotden.com" }), "key_log_required"],
    ["POST", "/v1/account/delete", () => undefined, "reauth_required"],
  ];
  for (const [method, path, body, noLogError] of actions) {
    const session = await call(app, method, path.replace("{m}", mth), await body(withLog, mth), bearer(withLog));
    expect([path, session.status, session.body.error]).toEqual([path, 428, "approval_required"]);
    const none = await call(app, method, path.replace("{m}", mthNoLog), await body(noLog, mthNoLog), bearer(noLog));
    expect([path, none.body.error]).toEqual([path, noLogError]);
  }
  const cancel = await call(app, "POST", "/v1/account/deletion-request/cancel", undefined, bearer(withLog));
  expect(cancel.body.error).toBe("not_found"); // nothing to cancel; with a request waiting it is 428 (deletion.test.ts)
});

test("gate hardening: the method.add approval names the new sign-in; a proof for another one is refused", async () => {
  const o = await owner(d);
  const forA = await stepUp(app, o, "method.add", { type: "google", subject: "g-approved" });
  const r = await call(app, "POST", "/v1/account/methods", { type: "google", proof: await googleProof(o, "g-other") }, forA);
  expect([r.status, r.body.error]).toEqual([403, "approval_invalid"]);
  expect((await call(app, "POST", "/v1/step-up", { action: "method.add", params: { type: "google" } }, bearer(o))).status).toBe(400); // no subject
  const ok = await call(app, "POST", "/v1/account/methods", { type: "google", proof: await googleProof(o, "g-approved") }, await stepUp(app, o, "method.add", { type: "google", subject: "g-approved" }));
  expect(ok.status).toBe(201);
});
