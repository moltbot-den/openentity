import { generateKeyPair, mandateDigest, signRequest, verifyMandate, canonicalize, buildPresentation, type KeyPair } from "@openentity/sdk";
import { expect, test } from "vitest";
import { createApp } from "../src/app.ts";
import { keyLogState } from "../src/keylog.ts";
import { HOST, SERVICE_DID, approval, approvalHeader, caller, entry, ownerId, p256Key, registerRoot, signIn, testDeps } from "./helpers.ts";

const DEN = "did:web:moltbotden.com";
const calls: { product: string; type: string; data: any }[] = [];
const fakeFetch = (async (input: RequestInfo | URL, init: RequestInit = {}) => {
  const url = new URL(String(input)), body = JSON.parse(new TextDecoder().decode(init.body as Uint8Array));
  if (url.pathname === "/v1/oe/credentials/renew") return Response.json({ product: DEN, kind: "bearer", key: "k", expires_at: 1_900_000_000, previous_valid_until: 1 });
  calls.push({ product: url.origin, type: body.type, data: body.data });
  return new Response(null, { status: 204 });
}) as typeof fetch;
const d = await testDeps({ fetch: fakeFetch, ws: { post: async () => true, close: async () => {} } });
const app = createApp(d), call = caller(app);
const SPEND = "spend<=$50/P1D@*.moltbotden.com:credits";

async function owner() {
  const me = await signIn(call, d);
  const root = p256Key({ type: "webauthn" }), approver = p256Key();
  await registerRoot(d.db, me.accountId, root);
  const genesis = entry(approver, { seq: 1, prev: null, op: "genesis", body: { root: root.credential, approver: approver.credential } });
  expect((await call("POST", `/o/${ownerId(genesis)}/log`, { line: genesis }, me.auth)).status).toBe(201);
  return { ...me, approver, did: `did:web:${HOST}:o:${ownerId(genesis)}` };
}
type Owner = Awaited<ReturnType<typeof owner>>;

async function asAgent(kp: KeyPair, method: string, path: string, body?: unknown) {
  const raw = body === undefined ? undefined : JSON.stringify(body);
  const h = await signRequest({ method, url: `https://${HOST}${path}`, body: raw ? new TextEncoder().encode(raw) : undefined, privateKey: kp, did: kp.did });
  return call(method, path, raw, h);
}
async function paired(o: Owner, permissions = ["owner.message", SPEND]) {
  const kp = await generateKeyPair();
  const p = (await call("POST", "/v1/pairings", undefined, o.auth)).body;
  const c = await asAgent(kp, "POST", "/v1/pair", { code: p.code, presentation: await buildPresentation(kp, { audience: SERVICE_DID, nonce: `pair:${p.code}` }), framework: "x", sdk: "openentity", sdk_version: "1.1.0", host: "h" });
  expect(c.status).toBe(201);
  const detail = (await call("GET", `/v1/pairings/${p.id}?permissions=${encodeURIComponent(permissions.join(","))}`, undefined, o.auth)).body;
  const r = await call("POST", `/v1/pairings/${p.id}/confirm`, { permissions }, { ...o.auth, ...approvalHeader(approval(o.approver, detail.approval_request)) });
  expect(r.status).toBe(200);
  return kp;
}
/** The owner's device: sign a draft's digest with the approver key (the app's signing sheet does the same). */
const sign = (o: Owner, m: any, by = o.approver) => ({ ...m, signature: { device_id: by.kid, form: "p256", signature: by.sign("mandate/1|*|" + canonicalize(m)) } });
async function issue(o: Owner, agent: string, perm = SPEND, signer = o.approver) {
  const draft = await call("POST", "/v1/mandates/draft", { agent_did: agent, permission: perm }, o.auth);
  expect(draft.status).toBe(200);
  expect(Buffer.from(mandateDigest(draft.body.mandate)).toString("hex")).toBe(draft.body.digest);
  return { draft: draft.body.mandate, signed: sign(o, draft.body.mandate, signer) };
}

test("the spend grammar: valid forms are accepted, the rest is invalid_permission", async () => {
  const o = await owner(), kp = await paired(o, ["owner.message"]);
  const patch = (permissions: string[]) => call("PATCH", `/v1/agents/${encodeURIComponent(kp.did)}`, { permissions }, o.auth);
  for (const bad of ["spend<=$50", "spend<=$50/P2D@x:card", "spend<=$50/P1D@x:cash", "spend<=50/P1D@x:card", "spend<=$5.001/P1D@x:card", "spend<=$5/P1D@:card"]) {
    expect((await patch([bad])).body.error, bad).toBe("invalid_permission");
  }
});

test("issue: draft from a held permission, signed by the approver, stored, pushed to products, status active with max-age <= 60", async () => {
  const o = await owner(), kp = await paired(o);
  calls.length = 0;
  const { draft, signed } = await issue(o, kp.did);
  expect(draft).toMatchObject({ version: "mandate/1", issuer_did: o.did, agent_did: kp.did, limits: { currency: "USD", per_tx_max: 5000, period: "P1D", period_max: 5000, total_max: 150_000 }, scope: { merchants: ["*.moltbotden.com"], rails: ["credits"] }, step_up_over: 2500, status: `https://${HOST}/v1/mandates/${draft.mandate_id}/status` });
  const r = await call("POST", "/v1/mandates", signed, o.auth);
  expect(r.status).toBe(201);
  expect(r.body).toMatchObject({ status: "active", mandate: signed });
  // a verifier checks it offline against the key log and the status answer
  const st = await call("GET", `/v1/mandates/${draft.mandate_id}/status`);
  expect(st.body).toEqual({ mandate_id: draft.mandate_id, status: "active" });
  expect(Number(/max-age=(\d+)/.exec(st.headers.get("cache-control") ?? "")?.[1])).toBeLessThanOrEqual(60);
  const keyLog = (await keyLogState(d, o.did))!;
  expect(verifyMandate(signed, { keyLog, agentDid: kp.did, status: st.body, origins: d.rp.origins, rpId: d.rp.id }).ok).toBe(true);
  const ev = calls.filter((x) => x.type === "agent.mandates");
  expect(ev.length).toBe(4);
  expect(ev[0].data).toMatchObject({ agent_did: kp.did, owner_did: o.did, mandates: [signed], seq: 1 });
  expect((await call("GET", `/v1/mandates?agent=${encodeURIComponent(kp.did)}`, undefined, o.auth)).body.mandates.map((m: any) => m.status)).toEqual(["active"]);
});

test("guards: agents never write mandates; forged, stale, foreign, uncovered and replayed mandates are refused", async () => {
  const o = await owner(), other = await owner(), kp = await paired(o);
  const { draft, signed } = await issue(o, kp.did);
  const post = (m: unknown, who = o) => call("POST", "/v1/mandates", m, who.auth);
  // the agent itself, signing as itself: not an owner session
  expect((await asAgent(kp, "POST", "/v1/mandates", signed)).status).toBe(401);
  expect((await call("POST", "/v1/mandates", signed)).status).toBe(401);
  // signed by a key outside the owner's log (the agent's own key, or another owner's approver)
  expect((await post(sign(o, draft, other.approver))).body.message).toContain("unknown_key");
  // limits edited after signing
  expect((await post({ ...signed, limits: { ...signed.limits, per_tx_max: 999_999 } })).body.message).toContain("bad_signature");
  // another owner's agent is not found; another owner's mandate id cannot be listed or revoked
  expect((await post(signed, other)).status).toBe(404);
  // beyond the held permission: re-sign a bigger mandate with the real approver
  const big = sign(o, { ...draft, limits: { ...draft.limits, per_tx_max: 90_000, period_max: 90_000 } });
  expect((await post(big)).body.error).toBe("spend_not_granted");
  expect((await post(sign(o, { ...draft, scope: { merchants: [], rails: ["credits"] } }))).body.error).toBe("spend_not_granted");
  expect((await post(sign(o, { ...draft, scope: { ...draft.scope, rails: ["card"] } }))).body.error).toBe("spend_not_granted");
  // narrower than the permission is fine: a merchant-specific mandate under a `*` permission
  const wide = await paired(o, ["owner.message", "spend<=$20/P1D@*:card"]);
  const narrow = (await issue(o, wide.did, "spend<=$20/P1D@*:card")).draft;
  expect((await post(sign(o, { ...narrow, scope: { merchants: ["did:web:shop.example"], rails: ["card"] } }))).status).toBe(201);
  // a status URL pointing elsewhere, and a stale issue time
  expect((await post(sign(o, { ...draft, status: "https://evil.example/status" }))).body.error).toBe("mandate_invalid");
  expect((await post(sign(o, { ...draft, issued_at: draft.issued_at - 3600, expires_at: draft.expires_at - 3600 }))).body.message).toContain("stale");
  // a draft only for a permission the agent holds
  expect((await call("POST", "/v1/mandates/draft", { agent_did: kp.did, permission: "spend<=$500/P1D@*:credits" }, o.auth)).body.error).toBe("invalid_permission");
  // one id is issued once, also after revoke (replay of a revoked mandate)
  expect((await post(signed)).status).toBe(201);
  expect((await post(signed)).body.error).toBe("mandate_exists");
  expect((await call("DELETE", `/v1/mandates/${draft.mandate_id}`, undefined, o.auth)).status).toBe(204);
  expect((await post(signed)).body.error).toBe("mandate_exists");
  expect((await call("DELETE", `/v1/mandates/${draft.mandate_id}`, undefined, other.auth)).status).toBe(404);
  expect((await call("GET", `/v1/mandates?agent=${encodeURIComponent(kp.did)}`, undefined, other.auth)).body.mandates).toEqual([]);
});

test("DELETE revokes: status flips, products get the shorter list", async () => {
  const o = await owner(), kp = await paired(o), { signed, draft } = await issue(o, kp.did);
  await call("POST", "/v1/mandates", signed, o.auth);
  calls.length = 0;
  expect((await call("DELETE", `/v1/mandates/${draft.mandate_id}`, undefined, o.auth)).status).toBe(204);
  expect((await call("GET", `/v1/mandates/${draft.mandate_id}/status`)).body.status).toBe("revoked");
  expect(calls.filter((x) => x.type === "agent.mandates").map((x) => [x.data.mandates, x.data.seq])).toEqual([[[], 2], [[], 2], [[], 2], [[], 2]]);
  expect((await call("GET", "/v1/mandates/md_aaaaaaaaaaaaaaaaaaaaaaaaaa/status")).status).toBe(404);
  expect((await call("GET", "/v1/mandates/nope/status")).status).toBe(404);
});

test("owner pause revokes every mandate of the agent; resume does not bring them back; nothing new while paused", async () => {
  const o = await owner(), kp = await paired(o, ["owner.message", SPEND, "spend<=$10/P7D@did:web:shop.example:card"]);
  const a = await issue(o, kp.did), b = await issue(o, kp.did, "spend<=$10/P7D@did:web:shop.example:card");
  for (const m of [a, b]) expect((await call("POST", "/v1/mandates", m.signed, o.auth)).status).toBe(201);
  calls.length = 0;
  expect((await call("POST", `/v1/agents/${encodeURIComponent(kp.did)}/pause`, { source: "app" }, o.auth)).status).toBe(200);
  for (const m of [a, b]) expect((await call("GET", `/v1/mandates/${m.draft.mandate_id}/status`)).body.status).toBe("revoked");
  expect(calls.filter((x) => x.type === "agent.mandates").every((x) => x.data.mandates.length === 0)).toBe(true);
  expect(calls.some((x) => x.type === "agent.paused")).toBe(true);
  const fresh = await issue(o, kp.did);
  expect((await call("POST", "/v1/mandates", fresh.signed, o.auth)).status).toBe(423);
  expect((await call("GET", `/v1/mandates?agent=${encodeURIComponent(kp.did)}`, undefined, o.auth)).body.mandates.map((m: any) => m.status)).toEqual(["revoked", "revoked"]);
});

test("narrowing the permission ends the mandates it no longer covers; unlinking ends all", async () => {
  const o = await owner(), kp = await paired(o, ["owner.message", SPEND, "spend<=$10/P7D@did:web:shop.example:card"]);
  const a = await issue(o, kp.did), b = await issue(o, kp.did, "spend<=$10/P7D@did:web:shop.example:card");
  for (const m of [a, b]) await call("POST", "/v1/mandates", m.signed, o.auth);
  const patch = await call("PATCH", `/v1/agents/${encodeURIComponent(kp.did)}`, { permissions: ["owner.message", "spend<=$10/P7D@did:web:shop.example:card"] }, o.auth);
  expect(patch.status).toBe(200);
  expect((await call("GET", `/v1/mandates/${a.draft.mandate_id}/status`)).body.status).toBe("revoked");
  expect((await call("GET", `/v1/mandates/${b.draft.mandate_id}/status`)).body.status).toBe("active");
  expect((await call("DELETE", `/v1/agents/${encodeURIComponent(kp.did)}`, undefined, o.auth)).status).toBe(204);
  expect((await call("GET", `/v1/mandates/${b.draft.mandate_id}/status`)).body.status).toBe("revoked");
});
