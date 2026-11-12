import { expect, test, vi } from "vitest";
import { createApp } from "../src/app.ts";
import { closeKeyLog, keyLogState } from "../src/keylog.ts";
import { notifyOwner } from "../src/notify.ts";
import { type Key, caller, entry, lineHash, ownerId, p256Key, registerRoot, signIn, testDeps } from "./helpers.ts";

vi.mock("../src/notify.ts", async (orig) => ({ ...(await orig<typeof import("../src/notify.ts")>()), notifyOwner: vi.fn(async () => {}) }));

const d = await testDeps();
const app = createApp(d), call = caller(app);

/** A signed-in owner whose root passkey is registered, and a genesis line by a device approver. */
async function owner() {
  const me = await signIn(call, d);
  const root = p256Key({ type: "webauthn" }), approver = p256Key();
  await registerRoot(d.db, me.accountId, root);
  const genesis = entry(approver, { seq: 1, prev: null, op: "genesis", body: { root: root.credential, approver: approver.credential } });
  const id = ownerId(genesis);
  return { ...me, root, approver, genesis, id, did: `did:web:${d.host}:o:${id}` };
}
const post = (id: string, line: string, headers: Record<string, string> = {}) => call("POST", `/o/${id}/log`, { line }, headers);

test("genesis: the owner's bearer, the account's own root passkey, then the log, its first_seen_at and did.json are served", async () => {
  const o = await owner();
  expect((await post(o.id, o.genesis)).status).toBe(401);
  const stranger = await signIn(call, d);
  expect((await post(o.id, o.genesis, stranger.auth)).body.error).toBe("invalid_entry"); // not that account's passkey
  expect((await post(ownerId("x"), o.genesis, o.auth)).status).toBe(400); // the id is not the genesis hash
  const r = await post(o.id, o.genesis, o.auth);
  expect(r.status).toBe(201);
  expect(r.body).toMatchObject({ seq: 1, hash: lineHash(o.genesis), effective_at: r.body.first_seen_at });
  expect((await call("GET", "/v1/me", undefined, o.auth)).body).toMatchObject({ owner_did: o.did, has_key_log: true });
  const log = await call("GET", `/o/${o.id}/log`);
  expect(log.text).toBe(`${o.genesis}\n`);
  expect(log.headers.get("content-type")).toMatch(/^application\/jsonl/);
  expect(log.headers.get("x-oe-log-head")).toBe("1");
  expect(log.headers.get("x-oe-first-seen-at")).toBe(String(r.body.first_seen_at));
  const doc = (await call("GET", `/o/${o.id}/did.json`)).body;
  expect(doc.id).toBe(o.did);
  expect(doc.verificationMethod.map((v: any) => v.id)).toEqual([`${o.did}#${o.root.kid}`, `${o.did}#${o.approver.kid}`]);
  expect(doc.assertionMethod).toEqual([`${o.did}#${o.approver.kid}`]); // the root passkey is not an approver once one exists
  expect(doc.service[0]).toMatchObject({ type: "OpenEntityKeyLog", serviceEndpoint: `https://${d.host}/o/${o.id}/log` });
  // One log per account; the same line again is answered as stored.
  expect((await post(o.id, o.genesis, o.auth)).body.seq).toBe(1);
  const root2 = p256Key({ type: "webauthn" }), approver2 = p256Key();
  await registerRoot(d.db, o.accountId, root2);
  const second = entry(approver2, { seq: 1, prev: null, op: "genesis", body: { root: root2.credential, approver: approver2.credential } });
  expect((await post(ownerId(second), second, o.auth)).body.error).toBe("log_exists");
});

test("appends verify through the SDK: a current approver adds one, a stranger key cannot, stale seqs conflict, tampering is refused", async () => {
  const o = await owner();
  await post(o.id, o.genesis, o.auth);
  const second = p256Key({ label: "iPad" }), stranger = p256Key();
  const add = entry(o.approver, { seq: 2, prev: lineHash(o.genesis), op: "add_approver", body: { approver: second.credential } });
  const forged = entry(stranger, { seq: 2, prev: lineHash(o.genesis), op: "add_approver", body: { approver: second.credential } });
  expect((await post(o.id, forged)).body).toMatchObject({ error: "invalid_entry", message: expect.stringMatching(/^unauthorized/) });
  expect((await post(o.id, add.replace('"iPad"', '"iPod"'))).body.message).toMatch(/^bad_signature/);
  expect((await post(o.id, add)).status).toBe(201); // no token needed: the entry authenticates itself
  expect((await post(o.id, add)).status).toBe(201); // a retry of the same line
  const late = entry(o.approver, { seq: 2, prev: lineHash(o.genesis), op: "revoke", body: { kid: second.kid } });
  expect((await post(o.id, late)).body.error).toBe("seq_conflict");
  expect((await keyLogState(d, o.did))!.approvers.map((a) => a.kid)).toEqual([o.approver.kid, second.kid]);
});

test("revoke and recover notify the owner; recover takes effect 24 hours after the service first saw it", async () => {
  const o = await owner();
  await post(o.id, o.genesis, o.auth);
  const second = p256Key();
  const add = entry(o.approver, { seq: 2, prev: lineHash(o.genesis), op: "add_approver", body: { approver: second.credential } });
  await post(o.id, add);
  vi.mocked(notifyOwner).mockClear();
  const revoke = entry(o.approver, { seq: 3, prev: lineHash(add), op: "revoke", body: { kid: second.kid } });
  const r = await post(o.id, revoke);
  expect(r.body.effective_at).toBe(r.body.first_seen_at);
  const fresh = p256Key();
  const recover = entry(o.root, { seq: 4, prev: lineHash(revoke), op: "recover", body: { approvers: [fresh.credential] } });
  const rec = await post(o.id, recover);
  expect(rec.status).toBe(201);
  expect(rec.body.effective_at).toBe(rec.body.first_seen_at + 86_400);
  const sent = vi.mocked(notifyOwner).mock.calls.map(([, account, n]) => [account, n.type, !!n.email]);
  expect(sent).toEqual([[o.accountId, "keylog.revoke", true], [o.accountId, "keylog.recover", true]]);
  expect((await keyLogState(d, o.did))!.pending).toMatchObject([{ seq: 4, op: "recover" }]);
});

test("a device key that claims a verified attestation needs this service's receipt", async () => {
  const me = await signIn(call, d);
  const root = p256Key({ type: "webauthn" }), approver: Key = p256Key();
  approver.credential.attestation = { type: "app_attest", verified: true };
  await registerRoot(d.db, me.accountId, root);
  const genesis = entry(approver, { seq: 1, prev: null, op: "genesis", body: { root: root.credential, approver: approver.credential } });
  expect((await post(ownerId(genesis), genesis, me.auth)).body).toMatchObject({ error: "invalid_entry", message: expect.stringMatching(/^attestation/) });
});

test("close: only the service writes it, low-S with the close key; then nothing more is accepted and did.json lists no keys", async () => {
  const o = await owner();
  await post(o.id, o.genesis, o.auth);
  const imposter = entry(o.approver, { seq: 2, prev: lineHash(o.genesis), op: "close", body: {} });
  expect((await post(o.id, imposter)).status).toBe(403);
  for (let i = 0; i < 4; i++) {
    // Several closes on fresh logs, so a high s from the signer would show up as a refused entry.
    const x = await owner();
    await post(x.id, x.genesis, x.auth);
    await closeKeyLog(d, x.did);
    expect((await keyLogState(d, x.did))!.closed).toBe(true);
  }
  await closeKeyLog(d, o.did);
  const add = entry(o.approver, { seq: 3, prev: "0".repeat(64), op: "add_approver", body: { approver: p256Key().credential } });
  expect((await post(o.id, add)).body.error).toBe("log_closed");
  const doc = (await call("GET", `/o/${o.id}/did.json`)).body;
  expect(doc.verificationMethod).toEqual([]);
  expect((await call("GET", `/o/${o.id}/log`)).text.split("\n").filter(Boolean)).toHaveLength(2);
});

test("unknown logs are 404 everywhere, and keyLogState is null for a DID that is not an owner DID here", async () => {
  expect((await call("GET", `/o/${"a".repeat(52)}/log`)).status).toBe(404);
  expect((await call("GET", `/o/${"a".repeat(52)}/did.json`)).status).toBe(404);
  expect((await call("GET", "/o/NOT-AN-ID/log")).status).toBe(404);
  expect(await keyLogState(d, "did:web:example.com:o:abc")).toBeNull();
});
