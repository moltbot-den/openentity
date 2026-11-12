import { createHash, randomUUID } from "node:crypto";
import { compactVerify, importJWK } from "jose";
import { expect, test } from "vitest";
import { createApp } from "../src/app.ts";
import { HOST, type Key, caller, entry, fakeAppAttest, lineHash, noticeRecorder, ownerId, p256Key, registerRoot, signIn, testDeps } from "./helpers.ts";

const apple = fakeAppAttest(), notices = noticeRecorder();
const d = await testDeps({ attestRoots: { apple: [apple.root] }, web: notices.web });
const app = createApp(d), call = caller(app);

/** A signed-in owner with a key log (root passkey plus a device approver). */
async function owner() {
  const me = await signIn(call, d);
  const root = p256Key({ type: "webauthn" }), approver = p256Key();
  await registerRoot(d.db, me.accountId, root);
  const genesis = entry(approver, { seq: 1, prev: null, op: "genesis", body: { root: root.credential, approver: approver.credential } });
  const id = ownerId(genesis);
  expect((await call("POST", `/o/${id}/log`, { line: genesis }, me.auth)).status).toBe(201);
  return { ...me, root, approver, id, head: lineHash(genesis), seq: 1 };
}
const nonce = async (install: string, platform = "ios") => (await call("POST", "/v1/auth/nonce", { client: { platform, install_id: install } })).body.nonce as string;
const cdh = (n: string, kid: string) => createHash("sha256").update(`${n}|${kid}`).digest();

/** A receipt for `key` from the attestation route, put into its credential as the app does. */
async function attested(o: { install: string; auth: Record<string, string> }, key: Key) {
  const n = await nonce(o.install);
  const r = await call("POST", "/v1/keylog/attestations", { nonce: n, platform: "ios", jwk: key.jwk, app_attest: apple.attest(cdh(n, key.kid)) }, o.auth);
  expect(r.body).toMatchObject({ receipt: expect.any(String) });
  key.credential.attestation = { type: "app_attest", verified: true, receipt: r.body.receipt };
  return r.body;
}

test("App Attest receipts: signed by the service key, bound to the key's kid; every broken part is refused", async () => {
  const o = await owner(), key = p256Key();
  const r = await attested(o, key);
  expect(r.claims).toMatchObject({ iss: `did:web:${HOST}`, kid: key.kid, platform: "ios", type: "app_attest", key_storage: "secure_enclave", verified: true, integrity: null });
  const { protectedHeader, payload } = await compactVerify(r.receipt, await importJWK({ ...d.keys.did.jwk, alg: "EdDSA" }));
  expect(protectedHeader).toEqual({ alg: "EdDSA", kid: `did:web:${HOST}#${d.keys.did.kid}`, typ: "oe-key-attestation+jwt" });
  expect(JSON.parse(new TextDecoder().decode(payload))).toEqual(r.claims);

  const refused = async (tweak: Parameters<typeof apple.attest>[1], n?: string, kidFor = key.kid) => {
    const fresh = n ?? await nonce(o.install);
    return (await call("POST", "/v1/keylog/attestations", { nonce: fresh, platform: "ios", jwk: key.jwk, app_attest: apple.attest(cdh(fresh, kidFor), tweak) }, o.auth)).body;
  };
  expect((await refused({}, undefined, p256Key().kid)).message).toMatch(/nonce extension/); // attests another kid
  expect((await refused({ aaguid: "appattest\0\0\0\0\0\0\0" })).message).toMatch(/AAGUID/); // production key in staging
  expect((await refused({ counter: 1 })).message).toMatch(/counter/);
  expect((await refused({ appId: "TEAM.com.other.app" })).message).toMatch(/RP ID/);
  expect((await refused({ keyId: Buffer.alloc(32, 7) })).message).toMatch(/key_id/);
  const used = await nonce(o.install);
  await refused({}, used);
  expect((await refused({}, used)).error).toBe("nonce_invalid"); // single use
  expect((await refused({}, await nonce(randomUUID()))).error).toBe("nonce_invalid"); // issued to another install
  const other = fakeAppAttest(); // a chain that does not end at the pinned root
  const n = await nonce(o.install);
  expect((await call("POST", "/v1/keylog/attestations", { nonce: n, platform: "ios", jwk: key.jwk, app_attest: other.attest(cdh(n, key.kid)) }, o.auth)).body.message).toMatch(/root/);
});

test("enrollment: a receipted device key, a code on both screens, then add_approver by an approver completes it", async () => {
  const o = await owner(), ipad = p256Key({ label: "iPad" });
  expect((await call("GET", "/v1/me", undefined, o.auth)).body.backup_needed).toBe(true); // one approver device only
  expect((await call("POST", "/v1/keylog/enrollments", { purpose: "approver", credential: ipad.credential }, o.auth)).body.error).toBe("attestation_invalid");
  await attested(o, ipad);
  await notices.device(d.db, o.accountId, o.install);
  notices.pushes.length = 0;
  const e = await call("POST", "/v1/keylog/enrollments", { purpose: "approver", credential: ipad.credential }, o.auth);
  expect(e.status).toBe(201);
  expect(e.body).toMatchObject({ purpose: "approver", code: expect.stringMatching(/^\d{6}$/), state: "pending", credential: ipad.credential, seq: null });
  expect(notices.pushes).toEqual([{ type: "enrollment.pending", id: e.body.enrollment_id }]);
  expect((await call("GET", "/v1/keylog/enrollments", undefined, o.auth)).body.enrollments.map((x: any) => x.enrollment_id)).toEqual([e.body.enrollment_id]);
  const add = entry(o.approver, { seq: 2, prev: o.head, op: "add_approver", body: { approver: ipad.credential } });
  expect((await call("POST", `/o/${o.id}/log`, { line: add })).status).toBe(201);
  expect((await call("GET", `/v1/keylog/enrollments/${e.body.enrollment_id}`, undefined, o.auth)).body).toMatchObject({ state: "completed", seq: 2 });
  expect((await call("GET", "/v1/me", undefined, o.auth)).body.backup_needed).toBe(false); // a second approver device
  expect(notices.pushes.at(-1)).toEqual({ type: "enrollment.completed", id: e.body.enrollment_id });
  // The same key cannot enroll again: a key enters a log once.
  expect((await call("POST", "/v1/keylog/enrollments", { purpose: "approver", credential: ipad.credential }, o.auth)).body.error).toBe("key_reused");
  expect((await call("DELETE", `/v1/keylog/enrollments/${e.body.enrollment_id}`, undefined, o.auth)).body.error).toBe("not_pending");
  const stranger = await signIn(call, d);
  expect((await call("GET", `/v1/keylog/enrollments/${e.body.enrollment_id}`, undefined, stranger.auth)).status).toBe(404);
});

test("replace root: a registered passkey waits 24 hours after the entry, and a cancel by an approver cancels the enrollment", async () => {
  const o = await owner(), next = p256Key({ type: "webauthn" });
  expect((await call("POST", "/v1/keylog/enrollments", { purpose: "root", credential: next.credential }, o.auth)).status).toBe(400); // not registered yet
  const signInPasskey = p256Key({ type: "webauthn" });
  await registerRoot(d.db, o.accountId, signInPasskey); // a sign-in passkey (not pending) is not an enrollment candidate
  expect((await call("POST", "/v1/keylog/enrollments", { purpose: "root", credential: signInPasskey.credential }, o.auth)).status).toBe(400);
  await registerRoot(d.db, o.accountId, next, { pending: true });
  const e = (await call("POST", "/v1/keylog/enrollments", { purpose: "root", credential: next.credential }, o.auth)).body;
  const replace = entry(o.approver, { seq: 2, prev: o.head, op: "replace_root", body: { root: next.credential } });
  const r = await call("POST", `/o/${o.id}/log`, { line: replace });
  expect((await call("GET", `/v1/keylog/enrollments/${e.enrollment_id}`, undefined, o.auth)).body).toMatchObject({ state: "waiting", seq: 2, effective_at: r.body.first_seen_at + 86_400 });
  const cancel = entry(o.approver, { seq: 3, prev: lineHash(replace), op: "cancel", body: { target: lineHash(replace) } });
  expect((await call("POST", `/o/${o.id}/log`, { line: cancel })).status).toBe(201);
  expect((await call("GET", `/v1/keylog/enrollments/${e.enrollment_id}`, undefined, o.auth)).body.state).toBe("cancelled");
});

test("enrollment limits: a key log first, three pending at most, withdrawal of a pending one", async () => {
  expect((await call("POST", "/v1/keylog/enrollments", { purpose: "approver", credential: p256Key().credential }, (await signIn(call, d)).auth)).body.error).toBe("key_log_required");
  const o = await owner();
  const ids = [];
  for (let i = 0; i < 3; i++) {
    const k = p256Key();
    await attested(o, k);
    ids.push((await call("POST", "/v1/keylog/enrollments", { purpose: "approver", credential: k.credential }, o.auth)).body.enrollment_id);
  }
  const fourth = p256Key();
  await attested(o, fourth);
  expect((await call("POST", "/v1/keylog/enrollments", { purpose: "approver", credential: fourth.credential }, o.auth)).body.error).toBe("too_many_pending");
  expect((await call("DELETE", `/v1/keylog/enrollments/${ids[0]}`, undefined, o.auth)).status).toBe(204);
  expect((await call("POST", "/v1/keylog/enrollments", { purpose: "approver", credential: fourth.credential }, o.auth)).status).toBe(201);
});

test("a genesis device key with the service's receipt is accepted as verified", async () => {
  const me = await signIn(call, d);
  const root = p256Key({ type: "webauthn" }), approver = p256Key();
  await registerRoot(d.db, me.accountId, root);
  await attested(me, approver);
  const genesis = entry(approver, { seq: 1, prev: null, op: "genesis", body: { root: root.credential, approver: approver.credential } });
  expect((await call("POST", `/o/${ownerId(genesis)}/log`, { line: genesis }, me.auth)).status).toBe(201);
});
