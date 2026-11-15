// Fixtures for the org tests and the org end-to-end: people with their own key logs, an org made by one of them, members
// whose devices are in the org key log, the org's step-ups and a paired org agent. `d` and `call` are the test app's.
import { buildPresentation, generateKeyPair, signRequest, type KeyPair } from "@openentity/sdk";
import { expect } from "vitest";
import type { Deps } from "../src/app.ts";
import { HOST, SERVICE_DID, approval, approvalHeader, entry, lineHash, ownerId, p256Key, registerRoot, signIn, type Call, type Key } from "./helpers.ts";

export type Person = Awaited<ReturnType<ReturnType<typeof orgWorld>["person"]>>;
export type Org = Awaited<ReturnType<ReturnType<typeof orgWorld>["newOrg"]>>;
export function orgWorld(d: Deps & { codes: string[] }, call: Call) {
  interface Person { accountId: string; auth: { authorization: string }; email: string; root: Key; approver: Key; did: string; log: string[] }
  /** A signed-in person with their own key log (a passkey root and one device). */
  async function person(): Promise<Person> {
    const email = `${crypto.randomUUID()}@example.com`, me = await signIn(call, d, email);
    const root = p256Key({ type: "webauthn" }), approver = p256Key();
    await registerRoot(d.db, me.accountId, root);
    const genesis = entry(approver, { seq: 1, prev: null, op: "genesis", body: { root: root.credential, approver: approver.credential } });
    expect((await call("POST", `/o/${ownerId(genesis)}/log`, { line: genesis }, me.auth)).status).toBe(201);
    return { accountId: me.accountId, auth: me.auth, email, root, approver, did: `did:web:${HOST}:o:${ownerId(genesis)}`, log: [genesis] };
  }

  interface Org { id: string; did: string; log: string[]; admin: Person }
  /** An org created by `admin`: genesis with the admin's passkey as root and the admin's device as first approver, and that device registered. */
  async function newOrg(admin: Person, name = "Acme"): Promise<Org> {
    const line = entry(admin.approver, { seq: 1, prev: null, op: "genesis", body: { root: admin.root.credential, approver: admin.approver.credential } });
    const r = await call("POST", "/v1/orgs", { name, line }, admin.auth);
    expect(r.status, JSON.stringify(r.body)).toBe(201);
    const org = { id: r.body.id as string, did: r.body.did as string, log: [line], admin };
    expect(org.did).toBe(`did:web:${HOST}:o:${ownerId(line)}`);
    expect((await call("PUT", `/v1/orgs/${org.id}/device`, { kid: admin.approver.kid }, admin.auth)).status).toBe(200);
    return org;
  }
  /** Puts `p`'s device into the org key log (an add_approver entry signed by `by`) without registering it. */
  async function logDevice(org: Org, p: Person, by: Key = org.admin.approver) {
    const line = entry(by, { seq: org.log.length + 1, prev: lineHash(org.log.at(-1)!), op: "add_approver", body: { approver: p.approver.credential } });
    expect((await call("POST", `/o/${org.id}/log`, { line })).status).toBe(201);
    org.log.push(line);
  }
  /** The org's step-up for `action`, asked by `who` (an admin) and signed by `by`: the headers that go on the action's own call. */
  async function stepUp(org: Org, who: Person, by: Key, action: string, params: object) {
    const req = await call("POST", "/v1/step-up", { org_id: org.id, action, params }, who.auth);
    expect(req.status, JSON.stringify(req.body)).toBe(200);
    expect(req.body.owner_did).toBe(org.did);
    return approvalHeader(approval(by, { verifier_did: SERVICE_DID, owner_did: org.did, request_id: req.body.request_id, payload_digest: req.body.payload_digest }));
  }
  /** Adds `p` to the org with `role` (a step-up for admin and approver), logs their device and registers it when they sign for the org. */
  async function join(org: Org, p: Person, role: "admin" | "approver" | "viewer", device = role !== "viewer") {
    const body = { email: p.email, role };
    const h = role === "viewer" ? {} : await stepUp(org, org.admin, org.admin.approver, "org.member.set", { org_id: org.id, account_id: p.accountId, role });
    const r = await call("POST", `/v1/orgs/${org.id}/members`, body, { ...org.admin.auth, ...h });
    expect(r.status, JSON.stringify(r.body)).toBe(201);
    if (device) {
      await logDevice(org, p);
      expect((await call("PUT", `/v1/orgs/${org.id}/device`, { kid: p.approver.kid }, p.auth)).status).toBe(200);
    }
  }
  const policy = async (org: Org) => (await call("GET", `/o/${org.id}/policy`)).body;

  async function asAgent(kp: KeyPair, method: string, path: string, body?: unknown) {
    const raw = body === undefined ? undefined : JSON.stringify(body);
    const h = await signRequest({ method, url: `https://${HOST}${path}`, body: raw ? new TextEncoder().encode(raw) : undefined, privateKey: kp, did: kp.did });
    return call(method, path, raw, h);
  }
  /** An agent paired to the org by `org.admin`: the org's DID is its owner, the admin's registered device confirms. */
  async function pairAgent(org: Org, permissions = ["owner.message", "owner.approval"]) {
    const kp = await generateKeyPair(), who = org.admin;
    const p = (await call("POST", "/v1/pairings", { org_id: org.id }, who.auth)).body;
    const c = await asAgent(kp, "POST", "/v1/pair", { code: p.code, presentation: await buildPresentation(kp, { audience: SERVICE_DID, nonce: `pair:${p.code}` }), framework: "x", sdk: "openentity", sdk_version: "1.1.0", host: "h" });
    expect(c.status).toBe(201);
    const detail = (await call("GET", `/v1/pairings/${p.id}?permissions=${encodeURIComponent(permissions.join(","))}`, undefined, who.auth)).body;
    expect(detail.approval_request.owner_did).toBe(org.did);
    const r = await call("POST", `/v1/pairings/${p.id}/confirm`, { permissions }, { ...who.auth, ...approvalHeader(approval(who.approver, detail.approval_request)) });
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    expect(r.body.org_id).toBe(org.id);
    return kp;
  }
  const agentUrl = (org: Org, kp: KeyPair, rest = "") => `/v1/orgs/${org.id}/agents/${encodeURIComponent(kp.did)}${rest}`;

  return { person, newOrg, logDevice, stepUp, join, policy, asAgent, pairAgent, agentUrl };
}
