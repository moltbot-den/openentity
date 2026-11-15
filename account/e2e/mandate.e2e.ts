// C1.4 end to end: an owner with a key log pairs a real agent, grants it a spend permission, signs a mandate with the
// device approver, and a merchant on the other side of a real HTTP socket decides a checkout with the SDK's
// verifyAgentForCheckout, polling the mandate's own status URL. The owner then pauses the agent: the very next status
// answer is revoked and the same checkout is denied. No browser: the signing sheet is the approver key from the fixtures.
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { canonicalize, generateKeyPair, buildPresentation, signRequest, verifyAgentForCheckout } from "@openentity/sdk";
import { afterAll, expect, test } from "vitest";
import { createApp } from "../src/app.ts";
import { keyLogState } from "../src/keylog.ts";
import { HOST, SERVICE_DID, approval, approvalHeader, caller, entry, ownerId, p256Key, registerRoot, signIn, testDeps } from "../test/helpers.ts";

const events: { type: string; data: any }[] = [];
const d = await testDeps({ fetch: (async (_u: unknown, init: RequestInit = {}) => { events.push(JSON.parse(new TextDecoder().decode(init.body as Uint8Array))); return new Response(null, { status: 204 }); }) as typeof fetch, ws: { post: async () => true, close: async () => {} } });
const app = createApp(d), call = caller(app);
const server = createServer(async (req, res) => {
  const r = await app.fetch(new Request(`http://${HOST}${req.url}`, { method: req.method, headers: { ...(req.headers as Record<string, string>), "x-oe-viewer-address": "127.0.0.1" } }));
  res.writeHead(r.status, Object.fromEntries(r.headers));
  res.end(Buffer.from(await r.arrayBuffer()));
});
await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
const live = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
afterAll(() => void server.close());

test("mandate issued by the owner's device, a merchant checks it live, the owner pauses, the merchant is refused", async () => {
  const me = await signIn(call, d), root = p256Key({ type: "webauthn" }), approver = p256Key();
  await registerRoot(d.db, me.accountId, root);
  const genesis = entry(approver, { seq: 1, prev: null, op: "genesis", body: { root: root.credential, approver: approver.credential } });
  expect((await call("POST", `/o/${ownerId(genesis)}/log`, { line: genesis }, me.auth)).status).toBe(201);
  const ownerDid = `did:web:${HOST}:o:${ownerId(genesis)}`;

  // pair an agent with the spend permission (Face ID approval of the pairing)
  const kp = await generateKeyPair(), perm = "spend<=$50/P1D@did:web:shop.example:card";
  const p = (await call("POST", "/v1/pairings", undefined, me.auth)).body;
  const raw = JSON.stringify({ code: p.code, presentation: await buildPresentation(kp, { audience: SERVICE_DID, nonce: `pair:${p.code}` }), framework: "x", sdk: "openentity", sdk_version: "1", host: "h" });
  expect((await call("POST", "/v1/pair", raw, await signRequest({ method: "POST", url: `https://${HOST}/v1/pair`, body: new TextEncoder().encode(raw), privateKey: kp, did: kp.did }))).status).toBe(201);
  const detail = (await call("GET", `/v1/pairings/${p.id}?permissions=${encodeURIComponent(perm)}`, undefined, me.auth)).body;
  expect((await call("POST", `/v1/pairings/${p.id}/confirm`, { permissions: [perm] }, { ...me.auth, ...approvalHeader(approval(approver, detail.approval_request)) })).status).toBe(200);

  // the owner's device signs the draft; the service stores it
  const draft = (await call("POST", "/v1/mandates/draft", { agent_did: kp.did, permission: perm }, me.auth)).body.mandate;
  const mandate = { ...draft, signature: { device_id: approver.kid, form: "p256", signature: approver.sign("mandate/1|*|" + canonicalize(draft)) } };
  expect((await call("POST", "/v1/mandates", mandate, me.auth)).status).toBe(201);
  expect(events.filter((e) => e.type === "agent.mandates").length).toBeGreaterThan(0);

  // the merchant: key log from the owner's DID, status from the mandate's own URL over real HTTP
  const keyLog = (await keyLogState(d, ownerDid))!;
  const cart = { profile: "cart/1", merchant: "did:web:shop.example", agent_did: kp.did, lines: [{ sku: "a", title: "A", qty: 1, unit: 1500 }], total: 1500, currency: "USD", rail: "card", mandate_id: mandate.mandate_id };
  const checkout = async () => {
    const status = await (await fetch(live + new URL(mandate.status).pathname)).json();
    return verifyAgentForCheckout({ agentDid: kp.did, cart, merchantPolicy: { require_mandate: true }, mandate, keyLog, status, origins: d.rp.origins });
  };
  expect(await checkout()).toMatchObject({ decision: "allow", reasons: ["mandate_covers_cart"] });

  expect((await call("POST", `/v1/agents/${encodeURIComponent(kp.did)}/pause`, { source: "app" }, me.auth)).status).toBe(200);
  expect(await checkout()).toMatchObject({ decision: "deny", reasons: ["mandate_revoked"] });
});
