// /approve in a real browser (PLAN 3.5): Chrome with a CDP virtual authenticator holding the owner's passkey approver,
// the page served by the account app on localhost, the product's return_url caught in the browser. The product side
// then verifies the posted Approval2 with verifyApproval, exactly as Agent Secret Store and ClawGRC do.
import { createHash, createPublicKey, generateKeyPairSync, randomBytes, sign, type KeyObject } from "node:crypto";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { canonicalize, didKeyFromPublicKey, payloadDigest, verifyApproval } from "@openentity/sdk";
import { calculateJwkThumbprint } from "jose";
import { chromium } from "playwright-core";
import { afterAll, expect, test } from "vitest";
import { createApp } from "../src/app.ts";
import { ENVELOPE_TYP } from "../src/approve.ts";
import { base32, keyLogState, lowS } from "../src/keylog.ts";
import { rpFor } from "../src/passkey.ts";
import { testDeps } from "../test/helpers.ts";

// Throwaway keys, none real: the product's Ed25519 envelope key, the owner's device approver, the passkey approver
// that the virtual authenticator holds, and the root passkey.
const HOST = "localhost", SERVICE = `did:web:${HOST}`, PRODUCT = "did:web:api.agentsecretstore.com";
const product = generateKeyPairSync("ed25519");
const productX = (product.publicKey.export({ format: "jwk" }) as any).x;
const d = await testDeps({
  host: HOST, rp: rpFor(HOST),
  fetch: (async () => Response.json({ id: PRODUCT, verificationMethod: [{ id: `${PRODUCT}#key-1`, type: "Multikey", controller: PRODUCT, publicKeyMultibase: didKeyFromPublicKey(Buffer.from(productX, "base64url")).slice(8) }], assertionMethod: [`${PRODUCT}#key-1`] })) as typeof fetch,
});
const app = createApp(d);
const server = createServer(async (req, res) => {
  const chunks: Buffer[] = [];
  for await (const ch of req) chunks.push(ch as Buffer);
  const r = await app.fetch(new Request(`http://${HOST}${req.url}`, { method: req.method, headers: req.headers as Record<string, string>, body: chunks.length ? Buffer.concat(chunks) : undefined }));
  res.writeHead(r.status, Object.fromEntries(r.headers));
  res.end(Buffer.from(await r.arrayBuffer()));
});
await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
const origin = `http://${HOST}:${(server.address() as AddressInfo).port}`;
const browser = await chromium.launch({ channel: "chrome", headless: true });
afterAll(async () => { await browser.close(); server.close(); });

const cred = async (k: KeyObject, type: "p256" | "webauthn", credentialId?: Buffer) => {
  const { x, y } = createPublicKey(k).export({ format: "jwk" }) as any;
  const jwk = { kty: "EC", crv: "P-256", x, y };
  const kid = await calculateJwkThumbprint(jwk as any, "sha256");
  return type === "webauthn" ? { kid, type, jwk, credential_id: credentialId!.toString("base64url"), rp_id: HOST, label: "Passkey", platform: "web" } : { kid, type, jwk, label: "iPhone", platform: "ios" };
};
const p256 = () => generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey;
const signed = (unsigned: object, by: KeyObject, kid: string) =>
  canonicalize({ ...unsigned, auth: { kid, form: "p256", signature: Buffer.from(lowS(new Uint8Array(sign("sha256", Buffer.from(canonicalize(unsigned)), { key: by, dsaEncoding: "ieee-p1363" })))).toString("base64url") } });

test("the owner approves an Agent Secret Store request with a passkey on /approve; the product verifies the Approval2", async () => {
  // The owner's key log: genesis (root passkey + iPhone approver), then the iPhone adds the web passkey approver.
  const device = p256(), root = p256(), webKey = p256(), webCredId = randomBytes(16);
  const deviceCred = await cred(device, "p256"), webCred = await cred(webKey, "webauthn", webCredId);
  const t = Math.floor(Date.now() / 1000);
  const genesis = signed({ v: 1, seq: 1, prev: null, op: "genesis", ts: t, body: { root: await cred(root, "webauthn", randomBytes(16)), approver: deviceCred } }, device, deviceCred.kid);
  const add = signed({ v: 1, seq: 2, prev: createHash("sha256").update(genesis).digest("hex"), op: "add_approver", ts: t, body: { approver: webCred } }, device, deviceCred.kid);
  const id = base32(createHash("sha256").update(genesis).digest()), ownerDid = `${SERVICE}:o:${id}`;
  for (const [seq, line, op] of [[1, genesis, "genesis"], [2, add, "add_approver"]] as const) {
    await d.db.run("INSERT INTO keylog_entries (owner_id, seq, line, hash, op, first_seen_at, effective_at) VALUES ($1, $2, $3, $4, $5, $6, $6)", [id, seq, line, createHash("sha256").update(line).digest("hex"), op, t]);
  }
  await d.db.run("INSERT INTO accounts (id, app_account_token, owner_did, created_at) VALUES ('acct_e2e', $1, $2, $3)", [crypto.randomUUID(), ownerDid, t]);

  // The product's envelope, as a console builds it.
  const payload = { action: "vault.read", path: "prod/stripe/key", agent: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK" };
  const seg = (o: object) => Buffer.from(JSON.stringify(o)).toString("base64url");
  const input = `${seg({ alg: "EdDSA", kid: `${PRODUCT}#key-1`, typ: ENVELOPE_TYP })}.${seg({ iss: PRODUCT, aud: SERVICE, iat: t, exp: t + 600, request_id: "req_e2e", owner_did: ownerDid, payload, payload_digest: payloadDigest(payload), return_url: "https://agentsecretstore.com/dashboard/approve/return", state: "s-1" })}`;
  const envelope = `${input}.${sign(null, Buffer.from(input), product.privateKey).toString("base64url")}`;

  const page = await browser.newPage();
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
  await cdp.send("WebAuthn.addCredential", { authenticatorId, credential: { credentialId: webCredId.toString("base64"), isResidentCredential: true, rpId: HOST, privateKey: webKey.export({ format: "der", type: "pkcs8" }).toString("base64"), signCount: 0, userHandle: Buffer.from("e2e").toString("base64") } });
  const errors: string[] = [];
  page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });
  page.on("pageerror", (e) => errors.push(e.message));
  const posted = new Promise<URLSearchParams>((resolve) => page.route("https://agentsecretstore.com/**", async (route) => {
    resolve(new URLSearchParams(route.request().postData() ?? ""));
    await route.fulfill({ status: 200, contentType: "text/plain", body: "ok" });
  }));

  await page.goto(`${origin}/approve#request=${envelope}`);
  await page.locator("#request:not([hidden])").waitFor();
  expect(await page.locator("#title").textContent()).toBe("Agent Secret Store asks for your approval");
  expect(await page.locator("#summary").textContent()).toContain("prod/stripe/key");
  await page.click("#approve");
  const form = await posted;
  expect(errors).toEqual([]); // the CSP let the page's own script run and blocked nothing it needs
  expect(form.get("request_id")).toBe("req_e2e");
  expect(form.get("state")).toBe("s-1");
  const approval = JSON.parse(form.get("approval")!);
  const r = verifyApproval(approval, {
    keyLog: (await keyLogState(d, ownerDid))!, verifierDid: PRODUCT, ownerDid, requestId: "req_e2e", payloadDigest: payloadDigest(payload),
    rpId: HOST, origins: [origin],
  });
  expect(r).toMatchObject({ ok: true, kid: webCred.kid });
  expect(approval).toMatchObject({ decision: "approve", form: "webauthn", device_id: webCred.kid });
  await page.close();
});
