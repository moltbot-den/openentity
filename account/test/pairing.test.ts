import { createPublicKey, verify as nodeVerify } from "node:crypto";
import { buildPresentation, generateKeyPair, pairSas, signRequest, verifyResponse, type KeyPair } from "@openentity/sdk";
import { afterEach, expect, test, vi } from "vitest";
import { createApp } from "../src/app.ts";
import { runJobs } from "../src/jobs.ts";
import { wsEvent } from "../src/ws.ts";
import { HOST, SERVICE_DID, approval, approvalHeader, caller, entry, ownerId, p256Key, registerRoot, signIn, testDeps } from "./helpers.ts";

const PRODUCTS = ["did:web:moltbotden.com", "did:web:securemyagent.ai", "did:web:api.agentsecretstore.com", "did:web:api.clawgrc.com"];
const API: Record<string, string> = { "https://api.moltbotden.com": PRODUCTS[0], "https://api.securemyagent.ai": PRODUCTS[1], "https://api.agentsecretstore.com": PRODUCTS[2], "https://api.clawgrc.com": PRODUCTS[3] };

// Fake products: record every signed call; renew answers a key, events answer 204.
const calls: { product: string; path: string; body: any }[] = [];
const den = await generateKeyPair();
const denDoc = { id: PRODUCTS[0], verificationMethod: [{ id: `${PRODUCTS[0]}#k1`, type: "Multikey", controller: PRODUCTS[0], publicKeyMultibase: den.did.slice(8) }], authentication: [`${PRODUCTS[0]}#k1`] };
const fakeFetch = (async (input: RequestInfo | URL, init: RequestInit = {}) => {
  const url = new URL(String(input));
  if (url.href === "https://moltbotden.com/.well-known/did.json") return Response.json(denDoc);
  const product = API[url.origin], body = JSON.parse(new TextDecoder().decode(init.body as Uint8Array));
  calls.push({ product, path: url.pathname, body });
  if (url.pathname === "/v1/oe/credentials/renew") return Response.json({ product, kind: "bearer", key: `key-${product}-${body.request_id}`, expires_at: 1_900_000_000, previous_valid_until: 1 });
  return new Response(null, { status: 204 });
}) as typeof fetch;
// A fake API Gateway: frames per connection, and closed connections.
const frames = new Map<string, any[]>(), closed: string[] = [];
const ws = { post: async (id: string, f: unknown) => (frames.set(id, [...(frames.get(id) ?? []), f]), !closed.includes(id)), close: async (id: string) => { closed.push(id); } };

const d = await testDeps({ fetch: fakeFetch, ws });
const app = createApp(d), call = caller(app);
afterEach(() => vi.useRealTimers());

/** An owner with a key log (root passkey plus a device approver). */
async function owner() {
  const me = await signIn(call, d);
  const root = p256Key({ type: "webauthn" }), approver = p256Key();
  await registerRoot(d.db, me.accountId, root);
  const genesis = entry(approver, { seq: 1, prev: null, op: "genesis", body: { root: root.credential, approver: approver.credential } });
  expect((await call("POST", `/o/${ownerId(genesis)}/log`, { line: genesis }, me.auth)).status).toBe(201);
  return { ...me, approver, did: `did:web:${HOST}:o:${ownerId(genesis)}` };
}
type Owner = Awaited<ReturnType<typeof owner>>;

/** An agent request signed with its did:key (agentSignature). */
async function asAgent(kp: KeyPair, method: string, path: string, body?: unknown) {
  const raw = body === undefined ? undefined : JSON.stringify(body);
  const h = await signRequest({ method, url: `https://${HOST}${path}`, body: raw ? new TextEncoder().encode(raw) : undefined, privateKey: kp, did: kp.did });
  return call(method, path, raw, h);
}
const claim = async (kp: KeyPair, code: string) =>
  asAgent(kp, "POST", "/v1/pair", { code, presentation: await buildPresentation(kp, { audience: SERVICE_DID, nonce: `pair:${code}` }), framework: "openclaw", sdk: "openentity", sdk_version: "1.1.0", host: "laptop" });
/** Advances the clock by `s` seconds (the 2 s and 15 s poll limits). */
const later = (s: number) => { vi.useFakeTimers({ toFake: ["Date"] }); vi.setSystemTime(Date.now() + s * 1000); };

/** The whole pairing: code, claim, owner confirms with the approver. */
async function paired(o: Owner, permissions = ["owner.message", "owner.status", "owner.approval"], kp?: KeyPair) {
  kp ??= await generateKeyPair();
  const p = (await call("POST", "/v1/pairings", undefined, o.auth)).body;
  const c = await claim(kp, p.code);
  expect(c.status).toBe(201);
  const detail = (await call("GET", `/v1/pairings/${p.id}?permissions=${permissions.join(",")}`, undefined, o.auth)).body;
  const r = await call("POST", `/v1/pairings/${p.id}/confirm`, { permissions }, { ...o.auth, ...approvalHeader(approval(o.approver, detail.approval_request)) });
  expect(r.status).toBe(200);
  return { kp, pairing: p, claim: c.body, detail, agent: r.body };
}

test("M1 path: code, claim with a Presentation, the same match string on both sides, Face ID confirm, agent.paired, keys once", async () => {
  const o = await owner();
  const kp = await generateKeyPair();
  const p = await call("POST", "/v1/pairings", undefined, o.auth);
  expect(p.status).toBe(201);
  expect(p.body).toMatchObject({ code: expect.stringMatching(/^OE-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$/), url: `https://openentity.org/pair#${p.body.code}`, state: "waiting" });
  const c = await claim(kp, p.body.code.toLowerCase());
  expect(c.status).toBe(201);
  expect(c.body).toMatchObject({ pairing_id: p.body.id, poll_interval: 2, sas: { version: "pair-sas/1", names: pairSas(p.body.code, kp.did) } });
  const bare = (await call("GET", `/v1/pairings/${p.body.id}`, undefined, o.auth)).body;
  const detail = (await call("GET", `/v1/pairings/${p.body.id}?permissions=owner.status,owner.message`, undefined, o.auth)).body;
  expect(detail).toMatchObject({ state: "claimed", agent: { did: kp.did, framework: "openclaw", host: "laptop" }, sas: c.body.sas });
  expect(detail.approval_request).toMatchObject({ verifier_did: SERVICE_DID, owner_did: o.did, action: "pairing.confirm", payload: { agent_did: kp.did, match: c.body.sas.names, permissions: ["owner.message", "owner.status"] } });
  expect((await asAgent(kp, "GET", `/v1/pair/${p.body.id}`)).body).toEqual({ state: "claimed", owner_did: null, permissions: [] });

  calls.length = 0;
  const confirm = (h: Record<string, string>) => call("POST", `/v1/pairings/${p.body.id}/confirm`, { permissions: ["owner.status", "owner.message"] }, { ...o.auth, ...h });
  expect((await confirm({})).status).toBe(428);
  expect((await confirm(approvalHeader(approval(o.approver, { ...detail.approval_request, payload_digest: "0".repeat(64) })))).body.error).toBe("approval_invalid");
  // Gate lead: the owner's approval covers the permission list, so one signed for none does not grant two.
  expect((await confirm(approvalHeader(approval(o.approver, bare.approval_request)))).body.error).toBe("approval_invalid");
  const ok = await confirm(approvalHeader(approval(o.approver, detail.approval_request)));
  expect(ok.status).toBe(200);
  expect(ok.body).toMatchObject({ did: kp.did, state: "active", permissions: ["owner.message", "owner.status"], products: [...PRODUCTS].sort() });
  expect((await confirm(approvalHeader(approval(o.approver, detail.approval_request)))).body.error).toBe("not_claimed");
  expect(calls.map((x) => [x.product, x.path, x.body.type])).toEqual(PRODUCTS.map((pr) => [pr, "/v1/oe/events", "agent.paired"]));
  expect(calls[0].body.data).toEqual({ agent_did: kp.did, owner_did: o.did, permissions: ["owner.message", "owner.status"], framework: "openclaw", seq: 1, link_epoch: 1 });

  later(2);
  const first = (await asAgent(kp, "GET", `/v1/pair/${p.body.id}`)).body;
  expect(first).toMatchObject({ state: "confirmed", owner_did: o.did, permissions: ["owner.message", "owner.status"] });
  expect(first.credentials.map((k: any) => k.product).sort()).toEqual([...PRODUCTS].sort());
  expect(calls.filter((x) => x.path === "/v1/oe/credentials/renew").map((x) => x.body)).toContainEqual({ request_id: `pair:${p.body.id}`, agent_did: kp.did, owner_did: o.did, kind: "bearer", permissions: ["owner.message", "owner.status"] });
  later(2);
  expect((await asAgent(kp, "GET", `/v1/pair/${p.body.id}`)).body.credentials).toBeUndefined(); // once
  expect(JSON.stringify(await d.db.all("SELECT * FROM pairings"))).not.toContain("key-did:web"); // never stored
});

test("pairing guards: key log, signatures, Presentation, single use, other owners, poll limits, 10 codes a day", async () => {
  expect((await call("POST", "/v1/pairings", undefined, (await signIn(call, d)).auth)).body.error).toBe("key_log_required");
  const o = await owner(), kp = await generateKeyPair(), other = await generateKeyPair();
  const p = (await call("POST", "/v1/pairings", undefined, o.auth)).body;
  // A Presentation for another nonce, or by another key, is refused; so is an unsigned call.
  const bad = await asAgent(kp, "POST", "/v1/pair", { code: p.code, presentation: await buildPresentation(kp, { audience: SERVICE_DID, nonce: "pair:OE-0000-0000" }), framework: "x", sdk: "x", sdk_version: "1" });
  expect(bad.body.error).toBe("presentation_invalid");
  const borrowed = await asAgent(kp, "POST", "/v1/pair", { code: p.code, presentation: await buildPresentation(other, { audience: SERVICE_DID, nonce: `pair:${p.code}` }), framework: "x", sdk: "x", sdk_version: "1" });
  expect(borrowed.body.error).toBe("presentation_invalid");
  expect((await call("POST", "/v1/pair", { code: p.code })).body.error).toBe("signature_invalid");
  expect((await claim(kp, "OE-ZZZZ-ZZZZ")).body.error).toBe("code_unknown");
  expect((await claim(kp, p.code)).status).toBe(201);
  expect((await claim(other, p.code)).body.error).toBe("code_used");
  expect((await asAgent(other, "GET", `/v1/pair/${p.id}`)).status).toBe(404); // only the claimer reads it
  expect((await asAgent(kp, "GET", `/v1/pair/${p.id}`)).status).toBe(200);
  expect((await asAgent(kp, "GET", `/v1/pair/${p.id}`)).body.error).toBe("rate_limited");
  // An agent paired with one owner cannot be claimed by another.
  const first = await paired(o);
  const o2 = await owner();
  const p2 = (await call("POST", "/v1/pairings", undefined, o2.auth)).body;
  expect((await claim(first.kp, p2.code)).body.error).toBe("agent_linked");
  // Ten codes a day per owner.
  const o3 = await owner();
  for (let i = 0; i < 10; i++) expect((await call("POST", "/v1/pairings", undefined, o3.auth)).status).toBe(201);
  expect((await call("POST", "/v1/pairings", undefined, o3.auth)).body.error).toBe("rate_limited");
});

test("agent channel over HTTP: messages both ways, status, the 15 s inbox poll, acknowledgements, permissions", async () => {
  const o = await owner();
  const { kp } = await paired(o, ["owner.message", "owner.status"]);
  expect((await asAgent(kp, "POST", "/v1/agent/messages", { text: "build is green" })).status).toBe(201);
  expect((await asAgent(kp, "POST", "/v1/agent/messages", { text: "x".repeat(4097) })).status).toBe(413);
  expect((await asAgent(kp, "POST", "/v1/agent/status", { state: "running", summary: "tests", progress: 0.5 })).status).toBe(204);
  const self = (await call("GET", `/v1/agents/${kp.did}`, undefined, o.auth)).body;
  expect(self.status).toMatchObject({ state: "running", summary: "tests", progress: 0.5 });
  const sent = await call("POST", `/v1/agents/${kp.did}/messages`, { text: "ship it" }, o.auth);
  expect(sent.status).toBe(201);
  const inbox = (await asAgent(kp, "GET", "/v1/agent/messages")).body;
  expect(inbox.items).toMatchObject([{ type: "message", id: sent.body.id, text: "ship it" }]);
  expect((await asAgent(kp, "GET", "/v1/agent/messages")).body.error).toBe("rate_limited");
  expect((await asAgent(kp, "POST", "/v1/agent/messages/ack", { ids: [sent.body.id] })).status).toBe(204);
  later(15);
  expect((await asAgent(kp, "GET", "/v1/agent/messages")).body.items).toEqual([]);
  const thread = (await call("GET", `/v1/agents/${kp.did}/messages`, undefined, o.auth)).body.messages;
  expect(thread.map((m: any) => [m.from, m.text])).toEqual([["owner", "ship it"], ["agent", "build is green"]]);
  expect(thread[0].acked_at).toEqual(expect.any(Number));
  expect((await asAgent(kp, "POST", "/v1/agent/approvals", { title: "t", summary: "s", risk: "low", expires_in: 60 })).body.error).toBe("permission_denied");
  expect((await asAgent(await generateKeyPair(), "GET", "/v1/agent")).body.error).toBe("not_paired");
});

test("agent-written approvals: the service is the verifier; the owner decides once and the agent gets the result", async () => {
  const o = await owner();
  const { kp } = await paired(o);
  const created = await asAgent(kp, "POST", "/v1/agent/approvals", { title: "Deploy", summary: "Deploy v2 to production", risk: "medium", expires_in: 300 });
  expect(created.status).toBe(201);
  const view = (await call("GET", `/v1/approvals/${created.body.id}`, undefined, o.auth)).body;
  expect(view.approval_request).toMatchObject({ verifier_did: SERVICE_DID, action: "agent.approval", decisions: ["approve", "deny"] });
  expect((await call("GET", "/v1/approvals", undefined, o.auth)).body.approvals.map((a: any) => a.id)).toContain(created.body.id);
  const decide = (decision: string) => call("POST", `/v1/approvals/${created.body.id}/decision`, {}, { ...o.auth, ...approvalHeader(approval(o.approver, { ...view.approval_request, decision })) });
  const r = await decide("deny");
  expect(r.body).toMatchObject({ state: "denied", approval: { decision: "deny" } });
  expect((await decide("approve")).body.error).toBe("already_decided");
  expect((await asAgent(kp, "GET", `/v1/agent/approvals/${created.body.id}`)).body.state).toBe("denied");
  later(15);
  expect((await asAgent(kp, "GET", "/v1/agent/messages")).body.items).toMatchObject([{ type: "approval.result", approval_id: created.body.id, state: "denied" }]);
});

test("WebSocket and pause: a signed $connect, frames pushed live, pause closes with 4001 and every product hears it, resume needs Face ID", async () => {
  const o = await owner();
  const { kp } = await paired(o);
  const connect = async (id: string, key = kp) => wsEvent(d, { requestContext: { routeKey: "$connect", connectionId: id }, headers: await signRequest({ method: "GET", url: `wss://agents.${HOST}/`, privateKey: key, did: key.did }) });
  expect((await connect("c-stranger", await generateKeyPair())).statusCode).toBe(403);
  expect((await wsEvent(d, { requestContext: { routeKey: "$connect", connectionId: "c-unsigned" }, headers: {} })).statusCode).toBe(401);
  expect((await connect("c1")).statusCode).toBe(200);
  expect((await connect("c2")).statusCode).toBe(200); // one socket per agent: c1 hears 4008 and closes
  expect(frames.get("c1")!.at(-1)).toMatchObject({ type: "error", close_code: 4008 });
  expect(closed).toContain("c1");
  const msg = (await call("POST", `/v1/agents/${kp.did}/messages`, { text: "hello" }, o.auth)).body;
  expect(frames.get("c2")).toMatchObject([{ type: "message", id: msg.id, text: "hello" }]);
  await wsEvent(d, { requestContext: { routeKey: "sync", connectionId: "c2" }, body: '{"action":"sync"}' });
  expect(frames.get("c2")!.at(-1)).toMatchObject({ id: msg.id });
  await wsEvent(d, { requestContext: { routeKey: "ack", connectionId: "c2" }, body: JSON.stringify({ action: "ack", ids: [msg.id] }) });

  calls.length = 0;
  const paused = await call("POST", `/v1/agents/${kp.did}/pause`, { source: "control" }, o.auth); // no approval needed
  expect(paused.body.state).toBe("paused");
  expect(frames.get("c2")!.slice(-2)).toMatchObject([{ type: "command", command: "pause" }, { type: "error", error: "agent_paused", close_code: 4001 }]);
  expect(closed).toContain("c2");
  expect(calls.map((x) => [x.product, x.body.type, x.body.data.seq])).toEqual(PRODUCTS.map((pr) => [pr, "agent.paused", 1]));
  expect((await asAgent(kp, "POST", "/v1/agent/messages", { text: "still here" })).body.error).toBe("agent_paused");
  expect((await connect("c3")).statusCode).toBe(200); // a paused agent may connect to hear the resume
  expect((await call("POST", `/v1/agents/${kp.did}/pause`, { source: "app" }, o.auth)).status).toBe(200); // idempotent
  expect(calls).toHaveLength(4);

  expect((await call("POST", `/v1/agents/${kp.did}/resume`, undefined, o.auth)).status).toBe(428);
  const req = (await call("POST", "/v1/step-up", { action: "agent.resume", params: { agent_did: kp.did } }, o.auth)).body;
  const resumed = await call("POST", `/v1/agents/${kp.did}/resume`, undefined, { ...o.auth, ...approvalHeader(approval(o.approver, req)) });
  expect(resumed.body.state).toBe("active");
  expect(frames.get("c3")!.at(-1)).toMatchObject({ type: "command", command: "resume" });
  expect(calls.slice(4).map((x) => [x.body.type, x.body.data.seq])).toEqual(PRODUCTS.map(() => ["agent.resumed", 2]));
});

test("permissions: narrowing at once, widening is a step-up; unlink tells every product and closes the socket with 4003", async () => {
  const o = await owner();
  const { kp } = await paired(o, ["owner.message", "owner.status"]);
  calls.length = 0;
  expect((await call("PATCH", `/v1/agents/${kp.did}`, { permissions: ["owner.message", "owner.status", "den.post"] }, o.auth)).status).toBe(428);
  const narrowed = await call("PATCH", `/v1/agents/${kp.did}`, { permissions: ["owner.message"], label: "Builder" }, o.auth);
  expect(narrowed.body).toMatchObject({ permissions: ["owner.message"], label: "Builder" });
  expect(calls.map((x) => [x.body.type, x.body.data.seq])).toEqual(PRODUCTS.map(() => ["agent.permissions", 2]));
  const req = (await call("POST", "/v1/step-up", { action: "agent.permissions.widen", params: { agent_did: kp.did, permissions: ["den.post", "owner.message"] } }, o.auth)).body;
  const widened = await call("PATCH", `/v1/agents/${kp.did}`, { permissions: ["owner.message", "den.post"] }, { ...o.auth, ...approvalHeader(approval(o.approver, req)) });
  expect(widened.body.permissions).toEqual(["den.post", "owner.message"]);
  await wsEvent(d, { requestContext: { routeKey: "$connect", connectionId: "u1" }, headers: await signRequest({ method: "GET", url: `wss://agents.${HOST}/`, privateKey: kp, did: kp.did }) });
  calls.length = 0;
  expect((await call("DELETE", `/v1/agents/${kp.did}`, undefined, o.auth)).status).toBe(204);
  expect(frames.get("u1")!.at(-1)).toMatchObject({ error: "unlinked", close_code: 4003 });
  expect(calls.map((x) => x.body.type)).toEqual(PRODUCTS.map(() => "agent.unlinked"));
  expect((await asAgent(kp, "GET", "/v1/agent")).body.error).toBe("not_paired");
  expect((await call("GET", "/v1/agents", undefined, o.auth)).body.agents).toEqual([]);
  await runJobs(d); // nothing is waiting in the outbox
  expect(await d.db.first("SELECT 1 FROM outbox")).toBeNull();
});

test("GET /v1/paused: product-signed, signed back by the service, cursor-based, about that product's agents only", async () => {
  const o = await owner();
  const { kp } = await paired(o);
  const poll = async (since?: string) => {
    const path = `/v1/paused${since === undefined ? "" : `?since=${since}`}`;
    const r = await call("GET", path, undefined, await signRequest({ method: "GET", url: `https://${HOST}${path}`, privateKey: den, did: `${PRODUCTS[0]}#k1` }));
    // The response signature: "@status" and content-digest by the service's Ed25519 key, the contract's three-line base.
    const params = r.headers.get("signature-input")!.slice("sig1=".length);
    const base = `"@status": 200\n"content-digest": ${r.headers.get("content-digest")}\n"@signature-params": ${params}`;
    const sig = Buffer.from(/^sig1=:(.*):$/.exec(r.headers.get("signature")!)![1], "base64");
    expect(nodeVerify(null, Buffer.from(base), createPublicKey({ key: d.keys.did.jwk as any, format: "jwk" }), sig)).toBe(true);
    expect(params).toContain(`keyid="${SERVICE_DID}#${d.keys.did.kid}"`);
    // And as products check it: the SDK's verifyResponse, keys from the authentication methods of our did.json.
    const doc = (await call("GET", "/.well-known/did.json")).body;
    const v = await verifyResponse({ status: 200, headers: Object.fromEntries(r.headers), body: new TextEncoder().encode(r.text), allowDidWeb: [SERVICE_DID], fetchJson: async () => doc });
    expect(v.expires - v.created).toBeLessThanOrEqual(60);
    return r.body;
  };
  const start = await poll();
  expect(start.changes.find((c: any) => c.agent_did === kp.did)).toBeUndefined();
  await call("POST", `/v1/agents/${kp.did}/pause`, { source: "siri" }, o.auth);
  const all = await poll();
  expect(all.changes).toContainEqual({ agent_did: kp.did, owner_did: o.did, state: "paused", at: expect.any(Number), seq: 1 });
  const step = await poll(start.cursor);
  expect(step).toMatchObject({ since: start.cursor, changes: [{ agent_did: kp.did, state: "paused", seq: 1 }] });
  expect((await poll(step.cursor)).changes).toEqual([]);
  expect((await call("GET", "/v1/paused?since=x", undefined, await signRequest({ method: "GET", url: `https://${HOST}/v1/paused?since=x`, privateKey: den, did: `${PRODUCTS[0]}#k1` }))).body.error).toBe("cursor_invalid");
  expect((await call("GET", "/v1/paused", undefined, await signRequest({ method: "GET", url: `https://${HOST}/v1/paused`, privateKey: kp, did: kp.did }))).body.error).toBe("unknown_signer");
});

test("housekeeping: acknowledged inbox items, old pairings and step-up requests go; live ones stay", async () => {
  const o = await owner();
  const { kp } = await paired(o);
  const old = Math.floor(Date.now() / 1000) - 8 * 86_400;
  await d.db.run("INSERT INTO inbox (id, agent_did, frame, created_at, acked_at) VALUES ('itm_old', $1, '{}', $2, $2), ('itm_live', $1, '{}', $2, NULL)", [kp.did, old]);
  await d.db.run("UPDATE pairings SET expires_at = $1, confirmed_at = $1 WHERE account_id = $2", [old, o.accountId]);
  await runJobs(d);
  expect((await d.db.all<{ id: string }>("SELECT id FROM inbox WHERE id IN ('itm_old', 'itm_live')")).map((r) => r.id)).toEqual(["itm_live"]);
  expect(await d.db.first("SELECT 1 FROM pairings WHERE account_id = $1", [o.accountId])).toBeNull();
  expect((await asAgent(kp, "GET", "/v1/agent")).status).toBe(200); // the agent itself stays paired
});

test("gate lead: each pairing is a new link_epoch on agent.paired, and agent.unlinked names the link it ends", async () => {
  const first = await owner(), second = await owner();
  const { kp } = await paired(first);
  calls.length = 0;
  await call("DELETE", `/v1/agents/${kp.did}`, undefined, first.auth);
  expect(calls.map((x) => [x.body.type, x.body.data.link_epoch])).toEqual(PRODUCTS.map(() => ["agent.unlinked", 1]));
  calls.length = 0;
  await paired(second, ["owner.message"], kp);
  expect(calls.filter((x) => x.body.type === "agent.paired").map((x) => x.body.data.link_epoch)).toEqual(PRODUCTS.map(() => 2));
  calls.length = 0;
  await call("DELETE", `/v1/agents/${kp.did}`, undefined, second.auth);
  expect(calls.map((x) => x.body.data.link_epoch)).toEqual(PRODUCTS.map(() => 2)); // a late unlink of link 1 is older than this
});

test("gate R5: an agent renews its product keys at most 6 times a day, then 429 until the next day", async () => {
  const o = await owner();
  const { kp } = await paired(o);
  for (let i = 0; i < 6; i++) expect((await asAgent(kp, "POST", "/v1/agent/credentials/renew")).status).toBe(200);
  await runJobs(d); // the rate_events retention keeps the day's count
  const over = await asAgent(kp, "POST", "/v1/agent/credentials/renew");
  expect(over).toMatchObject({ status: 429, body: { error: "rate_limited", message: "at most 6 a day" } });
  expect(Number(over.headers.get("retry-after"))).toBeGreaterThan(0);
  expect(Number(over.headers.get("retry-after"))).toBeLessThanOrEqual(86_400);
  later(86_400); // the next day
  expect((await asAgent(kp, "POST", "/v1/agent/credentials/renew")).status).toBe(200);
});
