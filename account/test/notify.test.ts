import { generateKeyPairSync } from "node:crypto";
import { createServer, type IncomingHttpHeaders } from "node:http2";
import type { AddressInfo } from "node:net";
import { jwtVerify } from "jose";
import { afterAll, expect, test } from "vitest";
import { apnsBody, apnsSender, fcmDisabled, pushData } from "../src/notify.ts";

// A local cleartext HTTP/2 server stands in for APNs; the key is a throwaway P-256 key, not the team's.
const key = generateKeyPairSync("ec", { namedCurve: "P-256" });
const seen: { headers: IncomingHttpHeaders; body: any }[] = [];
const server = createServer((req, res) => {
  let text = "";
  req.on("data", (c) => (text += c));
  req.on("end", () => {
    seen.push({ headers: req.headers, body: JSON.parse(text) });
    const token = String(req.headers[":path"]).split("/").pop();
    if (token === "dead") { res.writeHead(410); res.end(JSON.stringify({ reason: "Unregistered" })); return; }
    if (token === "wrongtopic") { res.writeHead(400); res.end(JSON.stringify({ reason: "DeviceTokenNotForTopic" })); return; }
    if (token === "busy") { res.writeHead(429); res.end(JSON.stringify({ reason: "TooManyRequests" })); return; }
    res.writeHead(200);
    res.end();
  });
});
await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
afterAll(() => server.close());

const send = apnsSender({
  keyPem: key.privateKey.export({ format: "pem", type: "pkcs8" }).toString(), keyId: "KEY1234567", teamId: "7R835D5LDZ", topic: "org.openentity.app",
  hosts: { production: base, sandbox: base },
});
const ASS = "did:web:api.agentsecretstore.com";

test("APNs: provider JWT, topic, push type and priority; the body carries ids and fixed text only", async () => {
  expect(await send({ provider: "apns", token: "abc123", environment: "production" }, { sender: ASS, type: "approval.requested", id: "apr_1", agent: "did:key:z6Mkagent", collapseKey: "apr_1" })).toBeNull();
  const { headers, body } = seen.at(-1)!;
  expect(headers[":path"]).toBe("/3/device/abc123");
  expect(headers).toMatchObject({ "apns-topic": "org.openentity.app", "apns-push-type": "alert", "apns-priority": "10", "apns-collapse-id": "apr_1" });
  const { payload, protectedHeader } = await jwtVerify(String(headers.authorization).slice("bearer ".length), key.publicKey);
  expect(protectedHeader).toEqual({ alg: "ES256", kid: "KEY1234567" });
  expect(payload.iss).toBe("7R835D5LDZ");
  expect(body).toEqual({
    aps: { alert: { title: "Agent Secret Store", body: "Approval requested. Open OpenEntity to review it." }, sound: "default", "interruption-level": "time-sensitive", "thread-id": ASS },
    oe: { product: ASS, type: "approval.requested", id: "apr_1", agent: "did:key:z6Mkagent" },
  });
});

test("APNs: approval.resolved and refresh are silent background pushes", async () => {
  for (const type of ["approval.resolved", "refresh"]) {
    expect(await send({ provider: "apns", token: "abc123", environment: "sandbox" }, { sender: ASS, type, id: "x1" })).toBeNull();
    const { headers, body } = seen.at(-1)!;
    expect(headers).toMatchObject({ "apns-push-type": "background", "apns-priority": "5" });
    expect(body).toEqual({ aps: { "content-available": 1 }, oe: { product: ASS, type, id: "x1" } });
  }
});

test("APNs: a dead token is gone, other failures are reasons, and the provider JWT is reused", async () => {
  const auth = String(seen.at(-1)!.headers.authorization);
  expect(await send({ provider: "apns", token: "dead", environment: "production" }, { sender: ASS, type: "alert", id: "a" })).toBe("gone");
  expect(await send({ provider: "apns", token: "wrongtopic", environment: "production" }, { sender: ASS, type: "alert", id: "a" })).toBe("gone");
  expect(await send({ provider: "apns", token: "busy", environment: "production" }, { sender: ASS, type: "alert", id: "a" })).toBe("TooManyRequests");
  expect(String(seen.at(-1)!.headers.authorization)).toBe(auth);
});

test("guard: no product text reaches a push; unknown senders and types get the generic text", () => {
  const body = apnsBody({ sender: "did:web:evil.example", type: "alert", id: "Your vault is locked, tap to unlock" });
  expect(body.aps).toMatchObject({ alert: { title: "OpenEntity", body: "New alert. Open OpenEntity to see it." } });
  expect(Object.keys(pushData({ sender: ASS, type: "alert", id: "a" }).oe)).toEqual(["product", "type", "id"]);
});

test("FCM is off until Workload Identity Federation exists: tokens are skipped, not sent", async () => {
  expect(await fcmDisabled({ provider: "fcm", token: "t" }, { sender: ASS, type: "alert", id: "a" })).toBe("fcm_disabled");
});

// ---------------------------------------------------------------- routes: push tokens and POST /v1/notify

import { signRequest } from "@openentity/sdk";
import { notifyOwner, type PushMessage, type PushTarget } from "../src/notify.ts";
import { HOST, ORIGIN, bearer as auth, call, owner, webApp } from "./owner.ts";

const GRC = "did:web:api.clawgrc.com";
const grcKey = generateKeyPairSync("ed25519");
const grcJwk = grcKey.publicKey.export({ format: "jwk" }) as any;
const sent: { t: PushTarget; m: PushMessage }[] = [];
const { d, app } = await webApp({
  web: { apns: async (t, m) => { sent.push({ t, m }); return t.token === "dead" ? "gone" : null; } },
  answer: (url) => url === "https://api.clawgrc.com/.well-known/did.json"
    ? Response.json({ id: GRC, verificationMethod: [{ id: `${GRC}#key-1`, type: "JsonWebKey", controller: GRC, publicKeyJwk: { kty: "OKP", crv: "Ed25519", x: grcJwk.x } }], authentication: [`${GRC}#key-1`], assertionMethod: [`${GRC}#key-1`] })
    : new Response(null, { status: 404 }),
});
const seed = Buffer.from((grcKey.privateKey.export({ format: "jwk" }) as any).d, "base64url");
async function notify(body: object, o: { did?: string; key?: Uint8Array } = {}) {
  const raw = new TextEncoder().encode(JSON.stringify(body));
  const h = await signRequest({ method: "POST", url: `${ORIGIN}/v1/notify`, body: raw, privateKey: o.key ?? seed, did: o.did ?? `${GRC}#key-1` });
  return app.request(`${ORIGIN}/v1/notify`, { method: "POST", body: raw, headers: { "content-type": "application/json", ...h } });
}
const token = (o: { install: string }, t: string, environment = "production") => call(app, "PUT", `/v1/push-tokens/${o.install}`, { provider: "apns", token: t, environment }, {});

test("push tokens: a session registers its own install only", async () => {
  const o = await owner(d);
  expect((await call(app, "PUT", `/v1/push-tokens/${o.install}`, { provider: "apns", token: "tok-a", environment: "sandbox" }, auth(o))).status).toBe(204);
  expect((await call(app, "PUT", `/v1/push-tokens/${crypto.randomUUID()}`, { provider: "apns", token: "tok-b", environment: "sandbox" }, auth(o))).status).toBe(403);
  expect((await call(app, "PUT", `/v1/push-tokens/${o.install}`, { provider: "apns", token: "tok-a" }, auth(o))).status).toBe(400);
  expect((await call(app, "PUT", `/v1/push-tokens/${o.install}`, { provider: "webpush", token: "x" }, auth(o))).status).toBe(400);
  expect((await token(o, "tok-c")).status).toBe(401);
});

test("POST /v1/notify: product-signed, ids only, to the owner's live installs; dead tokens are dropped", async () => {
  const o = await owner(d);
  await call(app, "PUT", `/v1/push-tokens/${o.install}`, { provider: "apns", token: "tok-live", environment: "production" }, auth(o));
  const r = await notify({ owner_did: o.ownerDid, type: "approval.requested", id: "pol_1", collapse_key: "pol_1" });
  expect([r.status, await r.json()]).toEqual([202, { queued: true }]);
  expect(sent.at(-1)).toEqual({ t: { provider: "apns", token: "tok-live", environment: "production" }, m: { sender: GRC, type: "approval.requested", id: "pol_1", agent: undefined, collapseKey: "pol_1", ttl: undefined } });
  const dead = await owner(d);
  await call(app, "PUT", `/v1/push-tokens/${dead.install}`, { provider: "apns", token: "dead", environment: "production" }, auth(dead));
  expect((await notify({ owner_did: dead.ownerDid, type: "alert", id: "a1" })).status).toBe(202);
  expect(await d.db.first("SELECT 1 FROM push_tokens WHERE install_id = $1", [dead.install])).toBeNull();
});

test("guard: /v1/notify refuses unsigned, foreign and replayed calls, unknown owners, bad types, and more than 600 a minute", async () => {
  const o = await owner(d);
  expect([401, 403]).toContain((await app.request(`${ORIGIN}/v1/notify`, { method: "POST", body: JSON.stringify({ owner_did: o.ownerDid, type: "alert", id: "x" }) })).status); // unsigned
  expect((await notify({ owner_did: o.ownerDid, type: "alert", id: "x" }, { did: "did:web:evil.example#key-1" })).status).toBe(403);
  expect((await notify({ owner_did: o.ownerDid, type: "alert", id: "x" }, { key: new Uint8Array(32).fill(7) })).status).toBe(401);
  expect((await notify({ owner_did: `${o.ownerDid.slice(0, -4)}aaaa`, type: "alert", id: "x" })).status).toBe(404);
  expect((await notify({ owner_did: o.ownerDid, type: "pay.now", id: "x" })).status).toBe(400);
  expect((await notify({ owner_did: o.ownerDid, type: "alert", id: "<b>Tap here</b>" })).status).toBe(400);
  const raw = new TextEncoder().encode(JSON.stringify({ owner_did: o.ownerDid, type: "alert", id: "x" }));
  const h = await signRequest({ method: "POST", url: `${ORIGIN}/v1/notify`, body: raw, privateKey: seed, did: `${GRC}#key-1` });
  const send = () => app.request(`${ORIGIN}/v1/notify`, { method: "POST", body: raw, headers: { "content-type": "application/json", ...h } });
  expect((await send()).status).toBe(202);
  expect((await send()).status).toBe(401); // the same nonce again
  await d.db.run("UPDATE rate_events SET count = 600 WHERE key = $1", [`notify:${GRC}`]);
  const limited = await notify({ owner_did: o.ownerDid, type: "alert", id: "x" });
  expect([limited.status, limited.headers.get("retry-after")]).toEqual([429, "60"]);
  await d.db.run("DELETE FROM rate_events WHERE key = $1", [`notify:${GRC}`]);
});

test("products reach live sessions only; the service's notices also reach installs signed out in the last 7 days", async () => {
  const o = await owner(d);
  await call(app, "PUT", `/v1/push-tokens/${o.install}`, { provider: "apns", token: "tok-out", environment: "production" }, auth(o));
  await d.db.run("UPDATE sessions SET revoked_at = $2 WHERE id = $1", [o.sid, Math.floor(Date.now() / 1000) - 3600]);
  const before = sent.length;
  await notify({ owner_did: o.ownerDid, type: "alert", id: "a2" });
  expect(sent.length).toBe(before);
  await notifyOwner(d, o.accountId, { type: "keylog.revoke", id: "3", email: { subject: "An approver was removed", text: "..." } });
  expect(sent.at(-1)!.m).toMatchObject({ sender: `did:web:${HOST}`, type: "keylog.revoke", id: "3" });
  await d.db.run("UPDATE sessions SET revoked_at = $2 WHERE id = $1", [o.sid, Math.floor(Date.now() / 1000) - 8 * 86_400]);
  await notifyOwner(d, o.accountId, { type: "keylog.revoke", id: "4" });
  expect(sent.at(-1)!.m.id).toBe("3");
});

test("removing a push token stops product pushes at once", async () => {
  const o = await owner(d);
  await call(app, "PUT", `/v1/push-tokens/${o.install}`, { provider: "apns", token: "tok-rm", environment: "production" }, auth(o));
  expect((await call(app, "DELETE", `/v1/push-tokens/${o.install}`, undefined, auth(o))).status).toBe(204);
  const before = sent.length;
  await notify({ owner_did: o.ownerDid, type: "alert", id: "a3" });
  expect(sent.length).toBe(before);
});
