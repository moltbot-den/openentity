import { generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import { payloadDigest } from "@openentity/sdk";
import { expect, test } from "vitest";
import { createApp } from "../src/app.ts";
import { ENVELOPE_TYP, TEST_PRODUCTS, testProductDid } from "../src/approve.ts";
import { webConfig } from "../src/web/config.ts";
import { HOST, ORIGIN, call, owner, webApp } from "./owner.ts";

// Staging test product identities (did:web:<staging host>:test-products:<name>) and the staging email test sign-in.
// Throwaway keys per run, never real ones: the harness holds the private keys, the service only the public ones.
const priv: Record<string, KeyObject> = Object.fromEntries(Object.keys(TEST_PRODUCTS).map((n) => [n, generateKeyPairSync("ed25519").privateKey]));
const pubs = JSON.stringify(Object.fromEntries(Object.entries(priv).map(([n, k]) => [n, (k.export({ format: "jwk" }) as { x: string }).x])));
const keys = webConfig({ test_product_keys: pubs }, { STAGE: "staging" }).testProducts!;
const { d, app } = await webApp({ web: { testProducts: keys, testIdp: { privateKey: generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey, publicKey: generateKeyPairSync("ec", { namedCurve: "P-256" }).publicKey } } });
const prod = createApp({ ...d, stage: "production" });
const ASS = testProductDid(HOST, "ass");
const now = () => Math.floor(Date.now() / 1000);

function envelope(ownerDid: string, o: { name?: string; returnUrl?: string; key?: KeyObject } = {}) {
  const did = testProductDid(HOST, o.name ?? "ass"), payload = { action: "vault.read", path: "staging/test" };
  const seg = (v: object) => Buffer.from(JSON.stringify(v)).toString("base64url");
  const input = `${seg({ alg: "EdDSA", kid: `${did}#key-1`, typ: ENVELOPE_TYP })}.${seg({ iss: did, aud: `did:web:${HOST}`, iat: now(), exp: now() + 600, request_id: "req_t1", owner_did: ownerDid, payload, payload_digest: payloadDigest(payload), return_url: o.returnUrl ?? "https://agentsecretstore.com/approve/return" })}`;
  return `${input}.${sign(null, Buffer.from(input), o.key ?? priv[o.name ?? "ass"]).toString("base64url")}`;
}

test("staging: each test product's DID document is served where did:web resolves it, with its Ed25519 key", async () => {
  for (const name of Object.keys(TEST_PRODUCTS)) {
    const r = await call(app, "GET", `/test-products/${name}/did.json`);
    expect(r.body).toMatchObject({ id: testProductDid(HOST, name), assertionMethod: [`${testProductDid(HOST, name)}#key-1`], authentication: [`${testProductDid(HOST, name)}#key-1`] });
    expect(r.body.verificationMethod[0].publicKeyMultibase).toMatch(/^z6Mk/);
  }
  expect((await call(app, "GET", "/test-products/evil/did.json")).status).toBe(404);
});

test("staging: an envelope signed by a test product checks, returning to the real product's site or to localhost", async () => {
  const o = await owner(d, { rootOnly: true });
  for (const url of ["https://agentsecretstore.com/approve/return", "https://staging.agentsecretstore.com/x", "http://localhost:3000/dashboard/approve/return", "http://127.0.0.1:8787/r"]) {
    const r = await call(app, "POST", "/v1/approve/check", { request: envelope(o.ownerDid, { returnUrl: url }) });
    expect([url, r.status, r.body.verifier_did]).toEqual([url, 200, ASS]);
  }
  for (const url of ["https://evil.example/x", "https://clawgrc.com/x", "http://agentsecretstore.com/x"]) {
    expect((await call(app, "POST", "/v1/approve/check", { request: envelope(o.ownerDid, { returnUrl: url }) })).body.error, url).toBe("envelope_invalid");
  }
  expect((await call(app, "POST", "/v1/approve/check", { request: envelope(o.ownerDid, { key: priv.sma }) })).body.error).toBe("envelope_invalid"); // another test product's key
  const csp = (await app.request(`${ORIGIN}/approve`)).headers.get("content-security-policy")!;
  expect(csp).toContain("http://localhost:*");
});

test("guard (production): no test products, no test sign-in; their envelopes are unknown verifiers", async () => {
  const o = await owner(d, { rootOnly: true });
  expect((await call(prod, "GET", "/test-products/ass/did.json")).status).toBe(404);
  expect((await call(prod, "POST", "/v1/approve/check", { request: envelope(o.ownerDid) })).body.error).toBe("unknown_verifier");
  expect((await prod.request(`${ORIGIN}/approve`)).headers.get("content-security-policy")).not.toContain("localhost");
  expect((await call(prod, "POST", "/v1/auth/test-idp", { kind: "email", email: "qa@test.openentity.org" })).status).toBe(404);
  expect(webConfig({ test_product_keys: pubs }, { STAGE: "production" }).testProducts).toBeUndefined();
});

test("staging test sign-in by email: a code for a test.openentity.org address, a web session without a mailbox or Turnstile", async () => {
  expect((await call(app, "POST", "/v1/auth/test-idp", { kind: "email", email: "someone@example.com" })).status).toBe(400);
  const t = await call(app, "POST", "/v1/auth/test-idp", { kind: "email", email: "QA-1@test.openentity.org" });
  expect(t.body.code).toMatch(/^\d{8}$/);
  const r = await call(app, "POST", "/v1/auth/email/verify", { challenge_id: t.body.challenge_id, code: t.body.code, client: { platform: "web" } }, { origin: ORIGIN });
  expect([r.status, r.body.account.email]).toEqual([200, "qa-1@test.openentity.org"]);
  expect(r.headers.getSetCookie().some((v) => v.startsWith("__Host-oe_session="))).toBe(true);
  for (const path of ["/signup", "/login"]) expect((await app.request(`${ORIGIN}${path}`)).status).toBe(200);
  expect(await (await app.request(`${ORIGIN}/login`)).text()).toContain('"testSignIn":true');
  expect(await (await prod.request(`${ORIGIN}/login`)).text()).toContain('"testSignIn":false');
});
