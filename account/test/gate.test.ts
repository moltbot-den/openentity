// Regression tests for the Day 6 review gate (docs/mobile/review/GATE-REPORT.md in the meta repo), Account-core part.
// Each fails without its fix; GATE-FIXES.md names them.
import { randomUUID } from "node:crypto";
import { afterEach, expect, test, vi } from "vitest";
import { createApp } from "../src/app.ts";
import { deleteAccount } from "../src/deletion.ts";
import { accessToken, openSession, rotate } from "../src/sessions.ts";
import { HOST, ORIGIN, caller, entry, noticeRecorder, ownerId, p256Key, registerRoot, signIn, testDeps } from "./helpers.ts";

const notices = noticeRecorder();
const d = await testDeps({ web: notices.web });
const app = createApp(d), call = caller(app);
afterEach(() => vi.useRealTimers());

test("gate M3: ipOf refuses a request without the viewer address, and each address has its own bucket", async () => {
  const install = () => JSON.stringify({ install_id: randomUUID(), platform: "ios" });
  const bare = await app.request(`${ORIGIN}/v1/installs`, { method: "POST", headers: { "content-type": "application/json" }, body: install() });
  expect([bare.status, (await bare.json()).error]).toEqual([503, "unavailable"]);
  const from = (ip: string) => call("POST", "/v1/installs", install(), { "x-oe-viewer-address": ip });
  for (let i = 0; i < 30; i++) expect((await from("198.51.100.1")).status).toBe(201);
  expect((await from("198.51.100.1")).status).toBe(429);
  expect((await from("198.51.100.2")).status).toBe(201); // another caller is not held by the first one's limit
});

/** A signed-in owner with a registered root passkey, a push token and a genesis line ready to post. */
async function ready(email = `${randomUUID()}@example.com`) {
  const me = await signIn(call, d, email);
  const root = p256Key({ type: "webauthn" }), approver = p256Key();
  await registerRoot(d.db, me.accountId, root);
  await notices.device(d.db, me.accountId, me.install);
  const line = entry(approver, { seq: 1, prev: null, op: "genesis", body: { root: root.credential, approver: approver.credential } });
  return { ...me, line, id: ownerId(line), email };
}

test("gate M2: genesis needs a sign-in at most 5 minutes old, and the owner is told by push and email", async () => {
  const o = await ready();
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(Date.now() + 301_000); // the access token is still valid (15 minutes); the sign-in is not fresh
  expect(await call("POST", `/o/${o.id}/log`, { line: o.line }, o.auth)).toMatchObject({ status: 401, body: { error: "reauth_required" } });
  vi.useRealTimers();
  const again = await signIn(call, d, o.email); // a fresh sign-in of the same account
  notices.pushes.length = 0; notices.mail.length = 0;
  expect((await call("POST", `/o/${o.id}/log`, { line: o.line }, again.auth)).status).toBe(201);
  expect(notices.pushes).toContainEqual({ type: "keylog.genesis", id: "1" });
  expect(notices.mail).toEqual([{ to: o.email, subject: "A change to your OpenEntity approvers" }]);
});

test("gate M2: in production genesis needs a device-bound app session", async () => {
  const prod = caller(createApp({ ...d, stage: "production" }));
  const o = await ready(); // an app session without a device binding
  expect(await prod("POST", `/o/${o.id}/log`, { line: o.line }, o.auth)).toMatchObject({ status: 403, body: { error: "binding_required" } });
  const sid = (await d.db.first<{ id: string }>("SELECT id FROM sessions WHERE install_id = $1", [o.install]))!.id;
  await d.db.run("UPDATE sessions SET binding = $2 WHERE id = $1", [sid, JSON.stringify({ type: "app_attest" })]);
  expect((await prod("POST", `/o/${o.id}/log`, { line: o.line }, o.auth)).status).toBe(201);
});

test("gate lead: a deleted account mints no token and rotates no refresh token, even from a session that raced the deletion", async () => {
  const me = await signIn(call, d);
  const s = (await d.db.first<{ id: string; platform: string; auth_time: number; amr: string }>("SELECT id, platform, auth_time, amr FROM sessions WHERE account_id = $1", [me.accountId]))!;
  await deleteAccount(d, me.accountId);
  // A sign-in that found the account before the deletion opens its session after it.
  const { refreshToken } = await openSession(d.db, { accountId: me.accountId, platform: "ios", amr: "email", installId: randomUUID() });
  await expect(accessToken(d, me.accountId, `did:web:${HOST}`, s.id, s.platform, Number(s.auth_time), s.amr)).rejects.toMatchObject({ status: 401, code: "invalid_grant" });
  await expect(rotate(d.db, refreshToken)).rejects.toMatchObject({ status: 401, code: "invalid_grant" });
});

test("hardening: the function refuses to start on an unknown STAGE (never acts as staging)", async () => {
  const before = process.env.STAGE;
  process.env.STAGE = "prod";
  try {
    const { handler } = await import("../src/lambda.ts");
    await expect(handler({ source: "aws.events" }, {})).rejects.toThrow(/STAGE must be production or staging/);
  } finally {
    process.env.STAGE = before;
  }
});
