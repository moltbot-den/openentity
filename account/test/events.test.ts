import { createPublicKey, randomUUID } from "node:crypto";
import { generateKeyPair, signRequest } from "@openentity/sdk";
import { expect, test } from "vitest";
import { createApp } from "../src/app.ts";
import type { QueuedEvent } from "../src/events.ts";
import { track, userId } from "../src/events.ts";
import { HOST, caller, signIn, testDeps } from "./helpers.ts";

// A stand-in product key published in a fake did.json (throwaway, generated per run).
const den = await generateKeyPair();
const DEN = "did:web:moltbotden.com";
const denDoc = { id: DEN, verificationMethod: [{ id: `${DEN}#k1`, type: "Multikey", controller: DEN, publicKeyMultibase: den.did.slice(8) }], authentication: [`${DEN}#k1`] };
const queued: QueuedEvent[] = [];
const d = await testDeps({ queue: async (events) => { queued.push(...events); }, fetch: (async () => Response.json(denDoc)) as typeof fetch });
const app = createApp(d), call = caller(app);
const event = (name: string, properties: Record<string, unknown> = {}) => ({ name, time: Date.now(), insert_id: randomUUID(), properties });

test("before sign-up: an install token lets the app send client events; the install stands in for the person", async () => {
  const install = randomUUID();
  const t = await call("POST", "/v1/installs", { install_id: install, platform: "ios", app_version: "1.0" });
  expect(t.status).toBe(201);
  queued.length = 0;
  const r = await call("POST", "/v1/events", { install_id: install, events: [event("onboarding_viewed"), event("sign_in_started", { method: "apple" }), event("sign_in_completed", { method: "apple", new_account: true })] }, { "x-oe-install-token": t.body.install_token });
  expect(r.status).toBe(202);
  expect(r.body).toEqual({ accepted: 2, rejected: [{ index: 2, error: expect.stringMatching(/source server not allowed/) }] });
  expect(queued.map((q) => [q.event, q.install_id, q.platform, q.user_id])).toEqual([["onboarding_viewed", install, "ios", undefined], ["sign_in_started", install, "ios", undefined]]);
  // A token for another install, or none, is refused.
  expect((await call("POST", "/v1/events", { install_id: randomUUID(), events: [event("onboarding_viewed")] }, { "x-oe-install-token": t.body.install_token })).status).toBe(401);
  expect((await call("POST", "/v1/events", { install_id: install, events: [event("onboarding_viewed")] })).status).toBe(401);
});

test("signed in: user_id is an HMAC of the owner, never the DID or the email; forbidden properties never reach the queue", async () => {
  const me = await signIn(call, d);
  queued.length = 0;
  const r = await call("POST", "/v1/events", { install_id: me.install, events: [event("push_permission_answered", { granted: true }), event("sign_in_started", { method: "apple", email: "x@example.com" })] }, me.auth);
  expect(r.body.accepted).toBe(1);
  expect(r.body.rejected[0]).toMatchObject({ index: 1, error: expect.stringMatching(/email/) });
  expect(queued[0].user_id).toBe(userId(d, me.accountId));
  expect(JSON.stringify(queued)).not.toContain("example.com");
  const many = Array.from({ length: 51 }, () => event("app_opened"));
  expect((await call("POST", "/v1/events", { install_id: me.install, events: many }, me.auth)).status).toBe(400);
});

test("products: signed ingest of server events only, with the owner as an HMAC", async () => {
  const owner = `did:web:${HOST}:o:${"a".repeat(52)}`;
  const body = JSON.stringify({ events: [{ ...event("checkup_completed", { score_band: "high", judged: true }), owner_did: owner }, { ...event("app_opened"), owner_did: owner }] });
  const url = `https://${HOST}/v1/events/ingest`;
  queued.length = 0;
  const r = await call("POST", "/v1/events/ingest", body, await signRequest({ method: "POST", url, body: new TextEncoder().encode(body), privateKey: den, did: `${DEN}#k1` }));
  expect(r.status).toBe(202);
  expect(r.body.accepted).toBe(1);
  expect(queued[0]).toMatchObject({ event: "checkup_completed", platform: "server", user_id: userId(d, owner) });
  expect((await call("POST", "/v1/events/ingest", body)).status).toBe(401);
});

test("the service's own server events go through the same catalog check; a bad one is dropped, never thrown", async () => {
  queued.length = 0;
  const owner = `did:web:${HOST}:o:${"b".repeat(52)}`, agent = "did:key:z6MkneMkZqwqRiU5mJzSG3kDwzt9P8C59N4NGTfBLfSGE7c7";
  await track(d, "agent_paused", { source: "control" }, { owner, agent });
  await track(d, "agent_paused", {}, { owner }); // missing its required source
  await track(d, "no_such_event", {}, { owner });
  expect(queued).toMatchObject([{ event: "agent_paused", platform: "server", user_id: userId(d, owner), props: { source: "control", agent_did: agent } }]);
});

test("insert_id: a resent batch is accepted again and queued once; the same id from another product is its own event", async () => {
  // A staging test product (approve.ts TEST_PRODUCTS) signs as the product it stands in for, with a throwaway key.
  const sma = await generateKeyPair(), SMA_TEST = `did:web:${HOST}:test-products:sma`;
  const testProducts = { sma: createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: Buffer.from(sma.publicKey).toString("base64url") }, format: "jwk" }) };
  const sd = { ...d, web: { ...d.web, testProducts } }, staging = caller(createApp(sd)), production = caller(createApp({ ...sd, stage: "production" }));
  const url = `https://${HOST}/v1/events/ingest`;
  const owner_did = `did:web:${HOST}:o:${"c".repeat(52)}`;
  const body = JSON.stringify({ events: [{ ...event("checkup_completed", { score_band: "high", judged: true }), owner_did }, { ...event("checkup_completed", { score_band: "low", judged: false }), owner_did }] });
  const as = async (kp: typeof den, keyid: string) => signRequest({ method: "POST", url, body: new TextEncoder().encode(body), privateKey: kp, did: keyid });
  queued.length = 0;
  const first = await staging("POST", "/v1/events/ingest", body, await as(sma, `${SMA_TEST}#key-1`));
  expect(first).toMatchObject({ status: 202, body: { accepted: 2, rejected: [] } });
  expect(queued).toHaveLength(2);
  const again = await staging("POST", "/v1/events/ingest", body, await as(sma, `${SMA_TEST}#key-1`));
  expect(again).toMatchObject({ status: 202, body: { accepted: 2, rejected: [] } });
  expect(queued).toHaveLength(2); // the resend queued nothing
  expect((await call("POST", "/v1/events/ingest", body, await as(den, `${DEN}#k1`))).status).toBe(202);
  expect(queued).toHaveLength(4); // Moltbot Den's events with the same ids are its own
  // Production trusts no test product.
  expect(await production("POST", "/v1/events/ingest", body, await as(sma, `${SMA_TEST}#key-1`))).toMatchObject({ status: 403, body: { error: "unknown_signer" } });
});
