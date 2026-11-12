import { expect, test } from "vitest";
import { createApp } from "../src/app.ts";
import { bearer } from "../src/http.ts";
import { requireApproval } from "../src/stepup.ts";
import { SERVICE_DID, approval, approvalHeader, caller, entry, lineHash, ownerId, p256Key, registerRoot, signIn, testDeps } from "./helpers.ts";

const d = await testDeps();
const app = createApp(d), call = caller(app);
const AGENT = "did:key:z6MkneMkZqwqRiU5mJzSG3kDwzt9P8C59N4NGTfBLfSGE7c7";
// A route that runs the gate, as the action routes do.
app.post("/test/resume", async (c) => {
  const o = await bearer(c, d);
  await requireApproval(c, d, { accountId: o.accountId, ownerDid: o.ownerDid, action: "agent.resume", params: { agent_did: c.req.query("agent") ?? AGENT } });
  return c.json({ ok: true });
});

app.post("/test/cancel", async (c) => {
  const o = await bearer(c, d);
  await requireApproval(c, d, { accountId: o.accountId, ownerDid: o.ownerDid, action: "deletion.cancel", params: {}, allowRoot: c.req.query("root") === "1" });
  return c.json({ ok: true });
});

async function ownerWithLog() {
  const me = await signIn(call, d);
  const root = p256Key({ type: "webauthn" }), approver = p256Key(), second = p256Key();
  await registerRoot(d.db, me.accountId, root);
  const genesis = entry(approver, { seq: 1, prev: null, op: "genesis", body: { root: root.credential, approver: approver.credential } });
  const id = ownerId(genesis);
  expect((await call("POST", `/o/${id}/log`, { line: genesis }, me.auth)).status).toBe(201);
  const add = entry(approver, { seq: 2, prev: lineHash(genesis), op: "add_approver", body: { approver: second.credential } });
  const revoke = entry(approver, { seq: 3, prev: lineHash(add), op: "revoke", body: { kid: second.kid } });
  for (const line of [add, revoke]) expect((await call("POST", `/o/${id}/log`, { line })).status).toBe(201);
  return { ...me, root, approver, revoked: second, did: `did:web:${d.host}:o:${id}` };
}
const ask = (o: { auth: Record<string, string> }, params: unknown = { agent_did: AGENT }) => call("POST", "/v1/step-up", { action: "agent.resume", params }, o.auth);

test("step-up needs a key log and a known action; the request names this service as verifier and expires in 600 s", async () => {
  const bare = await signIn(call, d);
  expect((await ask(bare)).body.error).toBe("key_log_required");
  const o = await ownerWithLog();
  expect((await call("POST", "/v1/step-up", { action: "account.takeover", params: {} }, o.auth)).body.error).toBe("unknown_action");
  expect((await ask(o, { agent_did: "nope" })).status).toBe(400);
  const r = (await ask(o)).body;
  expect(r).toMatchObject({ verifier_did: SERVICE_DID, owner_did: o.did, action: "agent.resume", payload: { action: "agent.resume", agent_did: AGENT }, decisions: ["approve"] });
  expect(r.expires_at - Math.floor(Date.now() / 1000)).toBeLessThanOrEqual(600);
});

test("requireApproval: 428 without a signature, then a current approver's approval works exactly once", async () => {
  const o = await ownerWithLog();
  const req = (await ask(o)).body;
  expect((await call("POST", "/test/resume", {}, o.auth)).status).toBe(428);
  const good = approvalHeader(approval(o.approver, req));
  expect((await call("POST", "/test/resume", {}, { ...o.auth, ...good })).status).toBe(200);
  expect((await call("POST", "/test/resume", {}, { ...o.auth, ...good })).body.error).toBe("approval_reused");
});

test("requireApproval refuses: another action's params, a deny, another verifier, a revoked approver, the root passkey, an expired approval, another account", async () => {
  const o = await ownerWithLog();
  const refused = async (sign: (req: any) => unknown, query = "", who = o.auth) => {
    const req = (await ask(o)).body;
    return (await call("POST", `/test/resume${query}`, {}, { ...who, ...approvalHeader(sign(req)) })).body.error;
  };
  expect(await refused((r) => approval(o.approver, r), `?agent=did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK`)).toBe("approval_invalid");
  expect(await refused((r) => approval(o.approver, { ...r, decision: "deny" }))).toBe("approval_invalid");
  expect(await refused((r) => approval(o.approver, { ...r, verifier_did: "did:web:moltbotden.com" }))).toBe("approval_invalid");
  expect(await refused((r) => approval(o.revoked, r))).toBe("approval_invalid");
  expect(await refused((r) => approval(o.root, r))).toBe("approval_invalid");
  expect(await refused((r) => approval(o.approver, { ...r, expires_at: Math.floor(Date.now() / 1000) - 1 }))).toBe("approval_expired");
  const other = await signIn(call, d);
  expect(await refused((r) => approval(o.approver, r), "", other.auth)).toBe("key_log_required");
});

test("allowRoot: the root passkey signs where the caller allows it (cancelling a deletion), as a WebAuthn assertion", async () => {
  const o = await ownerWithLog();
  const cancel = async (q: string) => {
    const req = (await call("POST", "/v1/step-up", { action: "deletion.cancel", params: {} }, o.auth)).body;
    return call("POST", `/test/cancel${q}`, {}, { ...o.auth, ...approvalHeader(approval(o.root, req)) });
  };
  expect((await cancel("")).body.error).toBe("approval_invalid");
  expect((await cancel("?root=1")).status).toBe(200);
});
