import { buildPresentation, generateKeyPair, signRequest, type KeyPair } from "@openentity/sdk";
import { expect, test } from "vitest";
import { createApp } from "../src/app.ts";
import type { Blobs } from "../src/blobs.ts";
import { HOST, SERVICE_DID, approval, approvalHeader, caller, entry, ownerId, p256Key, registerRoot, signIn, testDeps } from "./helpers.ts";

// A stand-in for S3: presigned URLs are plain strings, and `stored` is what an agent actually uploaded.
const stored = new Map<string, number>();
const blobs: Blobs = {
  putUrl: async (key, contentType, size) => ({ url: `https://blobs.test/${key}?put`, headers: { "content-type": contentType, "content-length": String(size) } }),
  size: async (key) => stored.get(key) ?? null,
  getUrl: async (key, name) => `https://blobs.test/${key}?get&name=${encodeURIComponent(name)}`,
};
const d = await testDeps({ blobs });
const app = createApp(d), call = caller(app);

async function pairedAgent(permissions = ["owner.message"]) {
  const me = await signIn(call, d);
  const root = p256Key({ type: "webauthn" }), approver = p256Key();
  await registerRoot(d.db, me.accountId, root);
  const genesis = entry(approver, { seq: 1, prev: null, op: "genesis", body: { root: root.credential, approver: approver.credential } });
  await call("POST", `/o/${ownerId(genesis)}/log`, { line: genesis }, me.auth);
  const kp = await generateKeyPair();
  const p = (await call("POST", "/v1/pairings", undefined, me.auth)).body;
  const body = JSON.stringify({ code: p.code, presentation: await buildPresentation(kp, { audience: SERVICE_DID, nonce: `pair:${p.code}` }), framework: "x", sdk: "x", sdk_version: "1" });
  await call("POST", "/v1/pair", body, await signRequest({ method: "POST", url: `https://${HOST}/v1/pair`, body: new TextEncoder().encode(body), privateKey: kp, did: kp.did }));
  const req = (await call("GET", `/v1/pairings/${p.id}`, undefined, me.auth)).body.approval_request;
  await call("POST", `/v1/pairings/${p.id}/confirm`, { permissions }, { ...me.auth, ...approvalHeader(approval(approver, req)) });
  return { ...me, kp };
}
const asAgent = async (kp: KeyPair, method: string, path: string, body?: unknown) => {
  const raw = body === undefined ? undefined : JSON.stringify(body);
  return call(method, path, raw, await signRequest({ method, url: `https://${HOST}${path}`, body: raw ? new TextEncoder().encode(raw) : undefined, privateKey: kp, did: kp.did }));
};

test("upload: a 5-minute presigned PUT with the size and type signed, at most 10 MiB, for a paired agent with owner.message", async () => {
  const a = await pairedAgent();
  const r = await asAgent(a.kp, "POST", "/v1/agent/uploads", { name: "report.pdf", content_type: "application/pdf", size: 1234 });
  expect(r.status).toBe(201);
  expect(r.body).toMatchObject({ upload_id: expect.stringMatching(/^upl_/), method: "PUT", headers: { "content-type": "application/pdf", "content-length": "1234" } });
  expect(r.body.expires_at - Math.floor(Date.now() / 1000)).toBeLessThanOrEqual(300);
  expect((await asAgent(a.kp, "POST", "/v1/agent/uploads", { name: "big.bin", content_type: "application/octet-stream", size: 10 * 1024 * 1024 + 1 })).status).toBe(413);
  expect((await asAgent(a.kp, "POST", "/v1/agent/uploads", { name: "x", content_type: "not a type", size: 1 })).status).toBe(400);
  expect((await asAgent(await generateKeyPair(), "POST", "/v1/agent/uploads", { name: "x", content_type: "text/plain", size: 1 })).body.error).toBe("not_paired");
  const quiet = await pairedAgent(["owner.status"]);
  expect((await asAgent(quiet.kp, "POST", "/v1/agent/uploads", { name: "x", content_type: "text/plain", size: 1 })).body.error).toBe("permission_denied");
});

test("a message carries an upload once, only after it is stored at its size, and only the agent's own; the owner downloads it", async () => {
  const a = await pairedAgent(), other = await pairedAgent();
  const up = (await asAgent(a.kp, "POST", "/v1/agent/uploads", { name: "build log.txt", content_type: "text/plain", size: 20 })).body;
  const theirs = (await asAgent(other.kp, "POST", "/v1/agent/uploads", { name: "x.txt", content_type: "text/plain", size: 5 })).body;
  stored.set(`uploads/${theirs.upload_id}`, 5);
  const send = (ids: string[]) => asAgent(a.kp, "POST", "/v1/agent/messages", { text: "see attached", attachments: ids });
  expect((await send([up.upload_id])).body.error).toBe("upload_unknown"); // not uploaded yet
  stored.set(`uploads/${up.upload_id}`, 19);
  expect((await send([up.upload_id])).body.error).toBe("upload_unknown"); // not the declared size
  stored.set(`uploads/${up.upload_id}`, 20);
  expect((await send([theirs.upload_id])).body.error).toBe("upload_unknown"); // another agent's upload
  const ok = await send([up.upload_id]);
  expect(ok.status).toBe(201);
  expect((await send([up.upload_id])).body.error).toBe("upload_unknown"); // used once
  const thread = (await call("GET", `/v1/agents/${a.kp.did}/messages`, undefined, a.auth)).body.messages;
  expect(thread[0].attachments).toEqual([{ id: up.upload_id, name: "build log.txt", content_type: "text/plain", size: 20 }]);
  const dl = await app.request(`https://${HOST}/v1/attachments/${up.upload_id}`, { headers: a.auth, redirect: "manual" });
  expect(dl.status).toBe(302);
  expect(dl.headers.get("location")).toBe(`https://blobs.test/uploads/${up.upload_id}?get&name=build%20log.txt`);
  expect((await call("GET", `/v1/attachments/${up.upload_id}`, undefined, other.auth)).status).toBe(404); // another owner
  expect((await call("GET", `/v1/attachments/${theirs.upload_id}`, undefined, other.auth)).status).toBe(404); // not in a message
  expect((await call("GET", `/v1/attachments/${up.upload_id}`)).status).toBe(401);
});
