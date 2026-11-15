// C5 organisations: roles, the org key log, step-ups under the org, quorum approvals, budgets as org-signed mandates, the
// org pause, cost centres, and every way a person who is not (or no longer) the org's could reach what is the org's.
import { buildPresentation, canonicalize, generateKeyPair, mandateDigest, verifyMandate, verifyQuorum } from "@openentity/sdk";
import { expect, test } from "vitest";
import { createApp } from "../src/app.ts";
import { keyLogState } from "../src/keylog.ts";
import { SERVICE_DID, approval, approvalHeader, caller, entry, lineHash, p256Key, testDeps, type Key } from "./helpers.ts";
import { orgWorld } from "./org-fixtures.ts";

const events: { product: string; type: string; data: any }[] = [];
const fakeFetch = (async (input: RequestInfo | URL, init: RequestInit = {}) => {
  const url = new URL(String(input)), body = JSON.parse(new TextDecoder().decode(init.body as Uint8Array));
  if (url.pathname === "/v1/oe/credentials/renew") return Response.json({ product: "x", kind: "bearer", key: "k", expires_at: 1_900_000_000, previous_valid_until: 1 });
  events.push({ product: url.origin, type: body.type, data: body.data });
  return new Response(null, { status: 204 });
}) as typeof fetch;
const d = await testDeps({ fetch: fakeFetch, ws: { post: async () => true, close: async () => {} } });
const app = createApp(d), call = caller(app);
const sentTo = (type: string, agent?: string) => events.filter((e) => e.type === type && (!agent || e.data.agent_did === agent));

const { person, newOrg, logDevice, stepUp, join, policy, asAgent, pairAgent, agentUrl } = orgWorld(d, call);

test("an org is an owner: its DID has a key log, the creator is its admin, and only registered devices are in the policy", async () => {
  const a = await person(), org = await newOrg(a);
  const log = await keyLogState(d, org.did);
  expect(log?.approvers.map((k) => k.kid)).toEqual([a.approver.kid]);
  expect((await policy(org)).quorum).toEqual({ m: 1, of: [a.approver.kid] });
  expect((await call("GET", `/v1/orgs/${org.id}`, undefined, a.auth)).body).toMatchObject({ role: "admin", did: org.did, state: "active" });
  // Sending the genesis again changes nothing, and someone else sending it (it is public in the log) gets nothing; a line that is not a genesis is refused.
  expect((await call("POST", "/v1/orgs", { name: "again", line: org.log[0] }, a.auth)).status).toBe(201);
  expect((await call("GET", "/v1/orgs", undefined, a.auth)).body.orgs).toHaveLength(1);
  expect((await call("POST", "/v1/orgs", { name: "mine", line: org.log[0] }, (await person()).auth)).status).toBe(404);
  const add = entry(a.approver, { seq: 2, prev: lineHash(org.log[0]), op: "add_approver", body: { approver: p256Key().credential } });
  expect((await call("POST", "/v1/orgs", { name: "x", line: add }, a.auth)).status).toBe(400);
  // The signed policy is the service's, not the log's alone: the same answer a product's feed check would get.
  const res = await call("GET", `/o/${org.id}/policy`);
  expect(res.headers.get("signature")).toMatch(/^sig1=:/);
  expect(res.headers.get("content-digest")).toMatch(/^sha-256=:/);
});

test("roles: a stranger sees nothing, a viewer reads and cannot change, admin and approver changes are step-ups signed by the admin's own device", async () => {
  const a = await person(), org = await newOrg(a), v = await person(), stranger = await person();
  await join(org, v, "viewer");
  expect((await call("GET", `/v1/orgs/${org.id}`, undefined, stranger.auth)).status).toBe(404);
  expect((await call("GET", `/v1/orgs/${org.id}/members`, undefined, v.auth)).body.members).toHaveLength(2);
  for (const [m, path, body] of [["POST", `/v1/orgs/${org.id}/pause`, { source: "web" }], ["PUT", `/v1/orgs/${org.id}/budgets`, {}], ["PATCH", `/v1/orgs/${org.id}`, { name: "x" }], ["POST", `/v1/orgs/${org.id}/members`, { email: stranger.email, role: "viewer" }]] as const) {
    const r = await call(m, path, body, v.auth);
    expect([r.status, r.body.error], `${m} ${path}`).toEqual([403, "forbidden_role"]);
  }
  // Promoting the viewer to approver: no approval, 428; the viewer's own device signs, 403; the admin's registered device, 200.
  const up = { role: "approver" };
  expect((await call("PATCH", `/v1/orgs/${org.id}/members/${v.accountId}`, up, a.auth)).status).toBe(428);
  const wrong = await stepUp(org, a, v.approver, "org.member.set", { org_id: org.id, account_id: v.accountId, role: "approver" });
  await logDevice(org, v);
  const bad = await call("PATCH", `/v1/orgs/${org.id}/members/${v.accountId}`, up, { ...a.auth, ...wrong });
  expect([bad.status, bad.body.error]).toEqual([403, "device_not_registered"]);
  const good = await stepUp(org, a, a.approver, "org.member.set", { org_id: org.id, account_id: v.accountId, role: "approver" });
  expect((await call("PATCH", `/v1/orgs/${org.id}/members/${v.accountId}`, up, { ...a.auth, ...good })).status).toBe(200);
  // The same approval is single use, and it names this member and role only.
  expect((await call("PATCH", `/v1/orgs/${org.id}/members/${v.accountId}`, { role: "admin" }, { ...a.auth, ...good })).status).toBe(403);
  expect((await call("PATCH", `/v1/orgs/${org.id}/members/${v.accountId}`, up, { ...a.auth, ...good })).status).toBe(200); // no-op role, nothing consumed
  const other = await stepUp(org, a, a.approver, "org.member.set", { org_id: org.id, account_id: stranger.accountId, role: "approver" });
  expect((await call("PATCH", `/v1/orgs/${org.id}/members/${v.accountId}`, { role: "admin" }, { ...a.auth, ...other })).status).toBe(403);
  // An org step-up cannot be asked for by a personal flow, nor a personal one used for the org.
  expect((await call("POST", "/v1/step-up", { action: "org.resume", params: { org_id: org.id } }, a.auth)).status).toBe(400);
  expect((await call("POST", "/v1/step-up", { org_id: org.id, action: "account.delete", params: {} }, a.auth)).status).toBe(400);
  expect((await call("POST", "/v1/step-up", { org_id: org.id, action: "org.resume", params: { org_id: org.id } }, v.auth)).status).toBe(403);
});

test("devices: a key must be an approver of both logs, one member per key, and a demoted member's key must leave the log first", async () => {
  const a = await person(), org = await newOrg(a), b = await person();
  await join(org, b, "approver", false);
  // Not in the org log yet.
  expect((await call("PUT", `/v1/orgs/${org.id}/device`, { kid: b.approver.kid }, b.auth)).body.error).toBe("device_not_approver");
  // In the org log but not the member's own key log.
  const stray = p256Key();
  await logDevice(org, { ...b, approver: stray });
  expect((await call("PUT", `/v1/orgs/${org.id}/device`, { kid: stray.kid }, b.auth)).body.error).toBe("device_not_approver");
  await logDevice(org, b);
  expect((await call("PUT", `/v1/orgs/${org.id}/device`, { kid: b.approver.kid }, b.auth)).status).toBe(200);
  expect((await policy(org)).quorum.of.sort()).toEqual([a.approver.kid, b.approver.kid].sort());
  // Another member cannot take b's key.
  const c = await person();
  await join(org, c, "approver", false);
  expect((await call("PUT", `/v1/orgs/${org.id}/device`, { kid: b.approver.kid }, c.auth)).status).toBe(403);
  // Demoting b while its key is an approver in the org log is refused; after a revoke entry it goes through and the key leaves the policy.
  const down = await stepUp(org, a, a.approver, "org.member.set", { org_id: org.id, account_id: b.accountId, role: "viewer" });
  const refused = await call("PATCH", `/v1/orgs/${org.id}/members/${b.accountId}`, { role: "viewer" }, { ...a.auth, ...down });
  expect([refused.status, refused.body.error]).toEqual([409, "device_in_log"]);
  const revoke = entry(a.approver, { seq: org.log.length + 1, prev: lineHash(org.log.at(-1)!), op: "revoke", body: { kid: b.approver.kid } });
  expect((await call("POST", `/o/${org.id}/log`, { line: revoke })).status).toBe(201);
  org.log.push(revoke);
  expect((await policy(org)).quorum.of).toEqual([a.approver.kid]); // a revoked key counts at once, before anyone demotes anyone
  const down2 = await stepUp(org, a, a.approver, "org.member.set", { org_id: org.id, account_id: b.accountId, role: "viewer" });
  expect((await call("PATCH", `/v1/orgs/${org.id}/members/${b.accountId}`, { role: "viewer" }, { ...a.auth, ...down2 })).status).toBe(200);
  // The last admin stays.
  const last = await stepUp(org, a, a.approver, "org.member.set", { org_id: org.id, account_id: a.accountId, role: "viewer" });
  expect((await call("PATCH", `/v1/orgs/${org.id}/members/${a.accountId}`, { role: "viewer" }, { ...a.auth, ...last })).body.error).toBe("last_admin");
  // The refusal comes before the step-up, so it does not need (or burn) an approval.
  expect((await call("PATCH", `/v1/orgs/${org.id}/members/${a.accountId}`, { role: "viewer" }, a.auth)).body.error).toBe("last_admin");
});


test("quorum: m devices of m members approve, each once; the bundle verifies with the SDK against the org's policy; a second org's or a replayed approval does not", async () => {
  const a = await person(), org = await newOrg(a), b = await person(), v = await person();
  await join(org, b, "approver");
  await join(org, v, "viewer");
  const q = await stepUp(org, a, a.approver, "org.quorum.set", { org_id: org.id, quorum_m: 2 });
  expect((await call("PATCH", `/v1/orgs/${org.id}`, { quorum_m: 2 }, { ...a.auth, ...q })).status).toBe(200);
  expect((await policy(org)).quorum).toMatchObject({ m: 2 });
  const agent = await pairAgent(org);
  const ask = await asAgent(agent, "POST", "/v1/agent/approvals", { title: "Buy dataset", summary: "$30 at shop.example", risk: "medium", expires_in: 300 });
  expect(ask.status, JSON.stringify(ask.body)).toBe(201);
  expect(ask.body.quorum).toMatchObject({ m: 2 });
  const pending = (await call("GET", `/v1/orgs/${org.id}/approvals`, undefined, b.auth)).body.approvals;
  expect(pending).toHaveLength(1);
  const [req] = pending, rq = req.approval_request, sign = (k: Key, o: object = {}) => approvalHeader(approval(k, { verifier_did: rq.verifier_did, owner_did: rq.owner_did, request_id: rq.request_id, payload_digest: rq.payload_digest, ...o }));
  const url = `/v1/orgs/${org.id}/approvals/${req.id}/decision`;
  // The creator's personal routes never see an org's approval.
  expect((await call("GET", "/v1/approvals", undefined, a.auth)).body.approvals).toEqual([]);
  expect((await call("POST", `/v1/approvals/${req.id}/decision`, {}, { ...a.auth, ...sign(a.approver) })).status).toBe(404);
  // A viewer cannot decide, and a device that is not a member's registered one does not count.
  expect((await call("POST", url, {}, { ...v.auth, ...sign(v.approver) })).status).toBe(403);
  expect((await call("POST", url, {}, { ...b.auth, ...sign(a.approver) })).body.error).toBe("device_not_registered"); // a's key under b's session
  expect((await call("POST", url, {}, { ...a.auth, ...sign(p256Key()) })).status).toBe(403);
  // One approval is not enough; the same device twice does not count twice.
  const one = await call("POST", url, {}, { ...a.auth, ...sign(a.approver) });
  expect([one.status, one.body.state, one.body.votes.length]).toEqual([200, "pending", 1]);
  expect((await call("POST", url, {}, { ...a.auth, ...sign(a.approver, { }) })).body.error).toBe("already_voted");
  // The agent still holds no approval.
  expect((await asAgent(agent, "GET", `/v1/agent/approvals/${req.id}`)).body.state).toBe("pending");
  const two = await call("POST", url, {}, { ...b.auth, ...sign(b.approver) });
  expect([two.status, two.body.state]).toEqual([200, "approved"]);
  const seen = (await asAgent(agent, "GET", `/v1/agent/approvals/${req.id}`)).body;
  expect(seen.state).toBe("approved");
  expect(seen.approvals).toHaveLength(2);
  // What a product does: the policy from the service, the org's key log, verifyQuorum over the bundle.
  const log = (await keyLogState(d, org.did))!, p = await policy(org);
  const check = (approvals: unknown, over: object = {}) => verifyQuorum(approvals, { keyLog: log, verifierDid: rq.verifier_did, ownerDid: org.did, requestId: rq.request_id, payloadDigest: rq.payload_digest, m: p.quorum.m, of: p.quorum.of, ...over });
  expect(check(seen.approvals)).toMatchObject({ ok: true });
  expect(check([seen.approvals[0]])).toMatchObject({ ok: false, error: "quorum_not_met" });
  expect(check([seen.approvals[0], seen.approvals[0]])).toMatchObject({ ok: false, error: "duplicate_device" });
  expect(check(seen.approvals, { payloadDigest: "0".repeat(64) })).toMatchObject({ ok: false, error: "wrong_payload" });
  expect(check(seen.approvals, { requestId: "aar_other" })).toMatchObject({ ok: false, error: "wrong_request" });
  expect(check(seen.approvals, { ownerDid: a.did, keyLog: (await keyLogState(d, a.did))! })).toMatchObject({ ok: false });
  expect(check(seen.approvals, { of: [a.approver.kid] })).toMatchObject({ ok: false });
  // Decided is decided.
  expect((await call("POST", url, {}, { ...b.auth, ...sign(b.approver) })).body.error).toBe("already_decided");
});

test("quorum: more denies than the quorum can overcome deny; a device added after the request does not count; a revoked device's vote is dropped", async () => {
  const a = await person(), org = await newOrg(a), b = await person();
  await join(org, b, "approver");
  await call("PATCH", `/v1/orgs/${org.id}`, { quorum_m: 2 }, { ...a.auth, ...(await stepUp(org, a, a.approver, "org.quorum.set", { org_id: org.id, quorum_m: 2 })) });
  const agent = await pairAgent(org);
  const ask = async () => {
    await asAgent(agent, "POST", "/v1/agent/approvals", { title: "t", summary: "s", risk: "low", expires_in: 300 });
    const [r] = (await call("GET", `/v1/orgs/${org.id}/approvals`, undefined, a.auth)).body.approvals;
    return { r, url: `/v1/orgs/${org.id}/approvals/${r.id}/decision`, sign: (k: Key, decision = "approve") => approvalHeader(approval(k, { verifier_did: r.approval_request.verifier_did, owner_did: org.did, request_id: r.approval_request.request_id, payload_digest: r.approval_request.payload_digest, decision })) };
  };
  // 2 of 2: one deny already cannot be overcome.
  const x = await ask();
  const denied = await call("POST", x.url, {}, { ...b.auth, ...x.sign(b.approver, "deny") });
  expect([denied.body.state]).toEqual(["denied"]);
  expect((await asAgent(agent, "GET", `/v1/agent/approvals/${x.r.id}`)).body.state).toBe("denied");
  // A device registered after the request is not in its quorum.
  const y = await ask(), c = await person();
  await join(org, c, "approver");
  const late = await call("POST", y.url, {}, { ...c.auth, ...y.sign(c.approver) });
  expect([late.status, late.body.error]).toEqual([403, "not_in_quorum"]);
  // a votes, then a's device is revoked from the log: the vote no longer counts, so b's approval alone does not approve.
  await call("POST", y.url, {}, { ...a.auth, ...y.sign(a.approver) });
  const revoke = entry(b.approver, { seq: org.log.length + 1, prev: lineHash(org.log.at(-1)!), op: "revoke", body: { kid: a.approver.kid } });
  expect((await call("POST", `/o/${org.id}/log`, { line: revoke })).status).toBe(201);
  const after = await call("POST", y.url, {}, { ...b.auth, ...y.sign(b.approver) });
  expect([after.status, after.body.state]).toEqual([200, "pending"]);
});

test("budgets: narrower stay inside wider, mandates are org-signed by a registered device and inside every budget, lowering ends them", async () => {
  const a = await person(), org = await newOrg(a), b = await person();
  await join(org, b, "approver");
  const agent = await pairAgent(org), other = await pairAgent(org);
  const base = { period: "P1D", rails: ["credits", "x402"], merchants: [] as string[] };
  const put = (body: object, who = a) => call("PUT", `/v1/orgs/${org.id}/budgets`, body, who.auth);
  expect((await put({ scope: "org", per_tx_max: 5000, period_max: 20000, ...base })).status).toBe(200);
  expect((await put({ scope: "org", per_tx_max: 5.5, period_max: 20000, ...base })).status).toBe(400);
  expect((await put({ scope: "team", ref: "growth", per_tx_max: 6000, period_max: 10000, ...base })).body.error).toBe("exceeds_parent");
  expect((await put({ scope: "team", ref: "growth", per_tx_max: 2000, period_max: 8000, ...base })).status).toBe(200);
  expect((await put({ scope: "org", per_tx_max: 5000, period_max: 20000, ...base, rails: ["credits"] })).body.error).toBe("children_exceed");
  // The agent joins the team: its effective budget is the team's.
  expect((await call("PATCH", agentUrl(org, agent), { team: "growth", cost_centre: "CC-42" }, a.auth)).status).toBe(200);
  const draft = (await call("POST", `/v1/orgs/${org.id}/mandates/draft`, { agent_did: agent.did }, a.auth)).body;
  expect(draft.mandate).toMatchObject({ issuer_did: org.did, agent_did: agent.did, limits: { per_tx_max: 2000, period_max: 8000 }, step_up_over: 1000 });
  expect(Buffer.from(mandateDigest(draft.mandate)).toString("hex")).toBe(draft.digest);
  const signed = (m: any, by: Key) => ({ ...m, signature: { device_id: by.kid, form: "p256", signature: by.sign("mandate/1|*|" + canonicalize(m)) } });
  const issue = (m: any, by: Key, who = a) => call("POST", `/v1/orgs/${org.id}/mandates`, signed(m, by), who.auth);
  // A person's own device is not the org's: a key that is in the org log but registered by nobody, or in no log, is refused.
  const loose = p256Key(); await logDevice(org, { ...b, approver: loose });
  expect((await issue(draft.mandate, loose)).body.error).toBe("device_not_registered");
  expect((await issue(draft.mandate, p256Key())).body.error).toBe("mandate_invalid");
  // Over the budget, even when signed by a registered device.
  const wide = { ...draft.mandate, limits: { ...draft.mandate.limits, per_tx_max: 2001 } };
  expect((await issue(wide, a.approver)).body.error).toBe("over_budget");
  const open = { ...draft.mandate, scope: { merchants: [], rails: ["credits", "x402", "card"] } };
  expect((await issue(open, a.approver)).body.error).toBe("over_budget");
  const r = await issue(draft.mandate, b.approver);
  expect(r.status, JSON.stringify(r.body)).toBe(201);
  // The org's SDK check, the way a merchant does it: against the org's key log and the status URL.
  const log = (await keyLogState(d, org.did))!, id = draft.mandate.mandate_id;
  const status = (await call("GET", `/v1/mandates/${id}/status`)).body;
  expect(status.status).toBe("active");
  expect(verifyMandate(r.body.mandate, { keyLog: log, agentDid: agent.did, status, origins: d.rp.origins, rpId: d.rp.id })).toMatchObject({ ok: true });
  expect(sentTo("agent.mandates", agent.did).at(-1)!.data).toMatchObject({ owner_did: org.did, team: "growth", cost_centre: "CC-42" });
  // Not the creator's personal mandates, and the org's list holds it.
  expect((await call("GET", "/v1/mandates", undefined, a.auth)).body.mandates).toEqual([]);
  expect((await call("DELETE", `/v1/mandates/${id}`, undefined, a.auth)).status).toBe(404);
  expect((await call("GET", `/v1/orgs/${org.id}/mandates`, undefined, b.auth)).body.mandates).toHaveLength(1);
  // The other agent has the org budget; the team's cap does not apply to it.
  const d2 = (await call("POST", `/v1/orgs/${org.id}/mandates/draft`, { agent_did: other.did }, a.auth)).body;
  expect(d2.mandate.limits.per_tx_max).toBe(5000);
  // Lowering the team's budget below the mandate revokes it at once; the status URL says so.
  expect((await put({ scope: "team", ref: "growth", per_tx_max: 1500, period_max: 8000, ...base })).status).toBe(200);
  expect((await call("GET", `/v1/mandates/${id}/status`)).body.status).toBe("revoked");
  expect((await call("DELETE", `/v1/orgs/${org.id}/budgets/${(await call("GET", `/v1/orgs/${org.id}/budgets`, undefined, a.auth)).body.budgets.find((x: any) => x.scope === "team").budget_id}`, undefined, a.auth)).status).toBe(204);
  // Moving the agent out of its team: org budget again.
  expect((await call("PATCH", agentUrl(org, agent), { team: null }, a.auth)).status).toBe(200);
  expect((await call("POST", `/v1/orgs/${org.id}/mandates/draft`, { agent_did: agent.did }, a.auth)).body.mandate.limits.per_tx_max).toBe(5000);
});

test("org pause stops every org agent at once, blocks pairing and per-agent resume, and resume is the org's step-up", async () => {
  const a = await person(), org = await newOrg(a), b = await person();
  await join(org, b, "approver");
  const one = await pairAgent(org), two = await pairAgent(org);
  await call("PUT", `/v1/orgs/${org.id}/budgets`, { scope: "org", per_tx_max: 5000, period: "P1D", period_max: 20000, rails: ["credits"] }, a.auth);
  const dr = (await call("POST", `/v1/orgs/${org.id}/mandates/draft`, { agent_did: one.did }, a.auth)).body;
  const sg = { ...dr.mandate, signature: { device_id: a.approver.kid, form: "p256", signature: a.approver.sign("mandate/1|*|" + canonicalize(dr.mandate)) } };
  expect((await call("POST", `/v1/orgs/${org.id}/mandates`, sg, a.auth)).status).toBe(201);
  events.length = 0;
  // A viewer cannot; an approver can, and needs no biometrics.
  const v = await person(); await join(org, v, "viewer");
  expect((await call("POST", `/v1/orgs/${org.id}/pause`, { source: "web" }, v.auth)).status).toBe(403);
  const t0 = Date.now(), r = await call("POST", `/v1/orgs/${org.id}/pause`, { source: "web" }, b.auth);
  expect(r.body).toMatchObject({ state: "paused", paused: 2 });
  // Both agents' products were told in the same request (the 60-second bound is the product's poll of the feed; events are the fast path).
  for (const k of [one, two]) expect(sentTo("agent.paused", k.did).length, k.did).toBeGreaterThanOrEqual(4);
  expect(Date.now() - t0).toBeLessThan(5000);
  expect((await policy(org)).state).toBe("paused");
  expect((await call("GET", `/v1/mandates/${dr.mandate.mandate_id}/status`)).body.status).toBe("revoked");
  expect((await call("GET", `/v1/orgs/${org.id}/agents`, undefined, a.auth)).body.agents.map((x: any) => x.state)).toEqual(["paused", "paused"]);
  // No new agent, no mandate, no single resume while the org is paused.
  expect((await call("POST", "/v1/pairings", { org_id: org.id }, a.auth)).body.error).toBe("org_paused");
  expect((await call("POST", `/v1/orgs/${org.id}/mandates`, sg, a.auth)).body.error).toBe("org_paused");
  const res = await stepUp(org, a, a.approver, "agent.resume", { agent_did: one.did });
  expect((await call("POST", agentUrl(org, one, "/resume"), {}, { ...a.auth, ...res })).body.error).toBe("org_paused");
  // Resuming needs the org step-up by an admin's registered device.
  expect((await call("POST", `/v1/orgs/${org.id}/resume`, {}, a.auth)).status).toBe(428);
  const okh = await stepUp(org, a, a.approver, "org.resume", { org_id: org.id });
  expect((await call("POST", `/v1/orgs/${org.id}/resume`, {}, { ...a.auth, ...okh })).body).toMatchObject({ state: "active", resumed: 2 });
  expect((await policy(org)).state).toBe("active");
  expect((await call("GET", `/v1/mandates/${dr.mandate.mandate_id}/status`)).body.status).toBe("revoked"); // mandates stay revoked: the org signs again
});

test("the pairer has no bypass: personal routes never reach an org's agent, and removal passes the pairer's seat on", async () => {
  const a = await person(), org = await newOrg(a), b = await person();
  await join(org, b, "admin");
  const agent = await pairAgent(org);
  expect((await call("GET", "/v1/agents", undefined, a.auth)).body.agents).toEqual([]);
  expect((await call("GET", `/v1/agents/${encodeURIComponent(agent.did)}`, undefined, a.auth)).status).toBe(404);
  expect((await call("POST", `/v1/agents/${encodeURIComponent(agent.did)}/pause`, { source: "web" }, a.auth)).status).toBe(404);
  expect((await call("PATCH", `/v1/agents/${encodeURIComponent(agent.did)}`, { permissions: ["owner.message", "den.post"] }, a.auth)).status).toBe(404);
  expect((await call("DELETE", `/v1/agents/${encodeURIComponent(agent.did)}`, undefined, a.auth)).status).toBe(404);
  expect((await call("POST", "/v1/agents/pause-all", { source: "web" }, a.auth)).body.paused).toBe(0);
  // The pairer cannot take the agent back as a person's: the agent's claim of a personal code of A's is refused until the org unlinks it.
  const personal = (await call("POST", "/v1/pairings", undefined, a.auth)).body;
  const claim = await asAgent(agent, "POST", "/v1/pair", { code: personal.code, presentation: await buildPresentation(agent, { audience: SERVICE_DID, nonce: `pair:${personal.code}` }), framework: "x", sdk: "openentity", sdk_version: "1.1.0", host: "h" });
  expect([claim.status, claim.body.error]).toEqual([409, "agent_linked"]);
  // A has no personal spend ceiling over it either: widening the org agent is the org's step-up.
  const widen = ["den.post", "owner.approval", "owner.message"];
  expect((await call("PATCH", agentUrl(org, agent), { permissions: widen }, b.auth)).status).toBe(428);
  const h = await stepUp(org, b, b.approver, "agent.permissions.widen", { agent_did: agent.did, permissions: widen });
  expect((await call("PATCH", agentUrl(org, agent), { permissions: widen }, { ...b.auth, ...h })).status).toBe(200);
  // a is removed (step-up by b, who is an admin with a device): a's key is in the org log, so first it is revoked.
  const revoke = entry(b.approver, { seq: org.log.length + 1, prev: lineHash(org.log.at(-1)!), op: "revoke", body: { kid: a.approver.kid } });
  await call("POST", `/o/${org.id}/log`, { line: revoke });
  const rm = await stepUp(org, b, b.approver, "org.member.set", { org_id: org.id, account_id: a.accountId, role: "none" });
  expect((await call("DELETE", `/v1/orgs/${org.id}/members/${a.accountId}`, undefined, { ...b.auth, ...rm })).status).toBe(204);
  expect((await call("GET", `/v1/orgs/${org.id}`, undefined, a.auth)).status).toBe(404);
  expect((await call("POST", agentUrl(org, agent, "/pause"), { source: "web" }, a.auth)).status).toBe(404);
  expect((await call("GET", `/v1/orgs/${org.id}/agents`, undefined, b.auth)).body.agents).toHaveLength(1);
  // Deleting an account that is still in an org waits until it leaves.
  const c = await person(); await join({ ...org, admin: b }, c, "viewer");
  const del = await call("POST", "/v1/account/delete", undefined, c.auth);
  expect(del.status).toBeGreaterThanOrEqual(400);
});

test("cost centres and the CSV: tags ride with the mandates, rows are per period, and a formula in a tag cannot run in a spreadsheet", async () => {
  const a = await person(), org = await newOrg(a);
  const agent = await pairAgent(org);
  const tags = await call("PATCH", agentUrl(org, agent), { team: "ops", cost_centre: "=HYPERLINK(\"http://evil\")" }, a.auth);
  expect(tags.body).toMatchObject({ team: "ops" });
  expect((await call("PATCH", agentUrl(org, agent), { cost_centre: "x".repeat(65) }, a.auth)).status).toBe(400);
  expect((await call("PATCH", agentUrl(org, agent), { team: "bad\u0007" }, a.auth)).status).toBe(400);
  await call("PUT", `/v1/orgs/${org.id}/budgets`, { scope: "org", per_tx_max: 1000, period: "P1D", period_max: 3000, rails: ["credits"] }, a.auth);
  const dr = (await call("POST", `/v1/orgs/${org.id}/mandates/draft`, { agent_did: agent.did }, a.auth)).body;
  await call("POST", `/v1/orgs/${org.id}/mandates`, { ...dr.mandate, signature: { device_id: a.approver.kid, form: "p256", signature: a.approver.sign("mandate/1|*|" + canonicalize(dr.mandate)) } }, a.auth);
  const csv = await call("GET", `/v1/orgs/${org.id}/export.csv`, undefined, a.auth);
  expect(csv.headers.get("content-type")).toContain("text/csv");
  const lines = csv.text.trim().split("\r\n");
  expect(lines[0]).toBe("kind,id,at,agent_did,team,cost_centre,state,period,period_max_cents,per_tx_max_cents,approvals,detail");
  expect(lines).toHaveLength(2);
  expect(lines[1]).toContain(`"'=HYPERLINK(""http://evil"")"`);
  expect(lines[1]).toContain(",ops,");
  expect(lines[1]).toContain(",active,P1D,3000,1000,");
  expect((await call("GET", `/v1/orgs/${org.id}/export.csv?from=${Math.floor(Date.now() / 1000) + 1000}`, undefined, a.auth)).text.trim().split("\r\n")).toHaveLength(1);
  expect((await call("GET", `/v1/orgs/${org.id}/export.csv?from=5&to=1`, undefined, a.auth)).status).toBe(400);
  expect((await call("GET", `/v1/orgs/${org.id}/export.csv`, undefined, (await person()).auth)).status).toBe(404);
});
