// C5 "done when", the account's half, over real HTTP: an org with two agents and two approvers. One budget set once limits
// both agents; a merchant checks each checkout with the SDK against the org's key log read from the service, the mandate's
// status URL and the org's signed policy (its signature verified here the way a product does); a purchase over the
// step-up line needs 2 of 2 approvals from distinct approver devices; pausing the org stops both agents at the next check.
import { createPublicKey, createHash, verify } from "node:crypto";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { canonicalize, cartDigest, verifyAgentForCheckout, verifyKeyLog } from "@openentity/sdk";
import { afterAll, expect, test } from "vitest";
import { createApp } from "../src/app.ts";
import { HOST, approval, caller, testDeps } from "../test/helpers.ts";
import { orgWorld } from "../test/org-fixtures.ts";

const events: { type: string; data: any }[] = [];
const d = await testDeps({ fetch: (async (_u: unknown, init: RequestInit = {}) => { events.push(JSON.parse(new TextDecoder().decode(init.body as Uint8Array))); return new Response(null, { status: 204 }); }) as typeof fetch, ws: { post: async () => true, close: async () => {} } });
const app = createApp(d), call = caller(app), W = orgWorld(d, call);
const server = createServer(async (req, res) => {
  const r = await app.fetch(new Request(`http://${HOST}${req.url}`, { method: req.method, headers: { ...(req.headers as Record<string, string>), "x-oe-viewer-address": "127.0.0.1" } }));
  res.writeHead(r.status, Object.fromEntries(r.headers));
  res.end(Buffer.from(await r.arrayBuffer()));
});
await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
const live = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
afterAll(() => void server.close());

/** What a product does with GET /o/<id>/policy: check the RFC 9421 response signature with the service's DID key (the same check as GET /v1/paused). */
async function signedPolicy(orgId: string) {
  const r = await fetch(`${live}/o/${orgId}/policy`), body = await r.text();
  const digest = r.headers.get("content-digest")!, input = r.headers.get("signature-input")!.slice("sig1=".length), sig = r.headers.get("signature")!.match(/^sig1=:(.+):$/)![1];
  expect(digest).toBe(`sha-256=:${createHash("sha256").update(body).digest("base64")}:`);
  const base = `"@status": 200\n"content-digest": ${digest}\n"@signature-params": ${input}`;
  const key = createPublicKey({ key: { ...(d.keys.did.jwk as object), kty: "OKP", crv: "Ed25519" } as never, format: "jwk" });
  expect(verify(null, Buffer.from(base), key, Buffer.from(sig, "base64"))).toBe(true);
  return JSON.parse(body) as { org_did: string; state: string; quorum: { m: number; of: string[] }; seq: number };
}

test("an org with two agents and two approvers: one budget, quorum approvals, one pause", async () => {
  const a = await W.person(), b = await W.person(), org = await W.newOrg(a, "Acme");
  await W.join(org, b, "approver");
  const q = await W.stepUp(org, a, a.approver, "org.quorum.set", { org_id: org.id, quorum_m: 2 });
  expect((await call("PATCH", `/v1/orgs/${org.id}`, { quorum_m: 2 }, { ...a.auth, ...q })).status).toBe(200);
  const one = await W.pairAgent(org), two = await W.pairAgent(org);

  // One budget, set once: $20 a purchase, $50 a day, step-up over $10.
  expect((await call("PUT", `/v1/orgs/${org.id}/budgets`, { scope: "org", per_tx_max: 2000, period: "P1D", period_max: 5000, step_up_over: 1000, rails: ["credits"], merchants: ["did:web:shop.example"] }, a.auth)).status).toBe(200);
  const mandates: Record<string, any> = {};
  for (const k of [one, two]) {
    const draft = (await call("POST", `/v1/orgs/${org.id}/mandates/draft`, { agent_did: k.did }, a.auth)).body.mandate;
    const signed = { ...draft, signature: { device_id: a.approver.kid, form: "p256", signature: a.approver.sign("mandate/1|*|" + canonicalize(draft)) } };
    expect((await call("POST", `/v1/orgs/${org.id}/mandates`, signed, a.auth)).status).toBe(201);
    mandates[k.did] = signed;
  }

  const MERCHANT = "did:web:shop.example", cart = (agent: string, total: number, mandate: any) => ({ profile: "cart/1", merchant: MERCHANT, agent_did: agent, lines: [{ sku: "x", title: "X", qty: 1, unit: total }], total, currency: "USD", rail: "credits", mandate_id: mandate.mandate_id });
  /** The merchant: the org's key log over HTTP, the mandate's status over HTTP, the org's signed policy; then the SDK decides. */
  const checkout = async (agent: string, total: number, approvals?: unknown[], requestId = "req_m1") => {
    const m = mandates[agent], logRes = await fetch(`${live}/o/${org.id}/log`), lines = (await logRes.text()).trim().split("\n");
    const seen = logRes.headers.get("x-oe-first-seen-at")!.split(",").map(Number);
    const log = verifyKeyLog(org.did, lines, seen, { serviceKeys: [d.keys.close.jwk as never], origins: d.rp.origins, rpId: d.rp.id });
    if (!log.ok) throw new Error(`org key log: ${log.message}`);
    const status = await (await fetch(`${live}${new URL(m.status).pathname}`)).json(), pol = await signedPolicy(org.id), c = cart(agent, total, m);
    return verifyAgentForCheckout({
      agentDid: agent, cart: c, merchantPolicy: { require_mandate: true, require_owner: true }, mandate: m, keyLog: log.state, status, origins: d.rp.origins,
      quorum: approvals ? { approvals, m: pol.quorum.m, of: pol.quorum.of, verifierDid: MERCHANT, requestId } : undefined,
    });
  };
  const approvalsFor = (agent: string, total: number, keys = [a.approver, b.approver], requestId = "req_m1") =>
    keys.map((k) => approval(k, { verifier_did: MERCHANT, owner_did: org.did, request_id: requestId, payload_digest: cartDigest(cart(agent, total, mandates[agent])) }));

  // The same budget limits both agents.
  for (const k of [one, two]) {
    expect(await checkout(k.did, 800), k.did).toMatchObject({ decision: "allow", reasons: ["mandate_covers_cart"] });
    expect(await checkout(k.did, 2500), k.did).toMatchObject({ decision: "step_up", reasons: ["mandate_over_limit"] });
  }
  // Over the step-up line: one approval is not enough, two distinct approver devices are.
  expect(await checkout(one.did, 1500)).toMatchObject({ decision: "step_up", reasons: ["step_up_over"] });
  expect(await checkout(one.did, 1500, approvalsFor(one.did, 1500, [a.approver]))).toMatchObject({ decision: "step_up", evidence: { approval_error: "quorum_not_met" } });
  expect(await checkout(one.did, 1500, approvalsFor(one.did, 1500, [a.approver, a.approver]))).toMatchObject({ decision: "step_up", evidence: { approval_error: "duplicate_device" } });
  expect(await checkout(one.did, 1500, approvalsFor(one.did, 1400))).toMatchObject({ decision: "step_up", evidence: { approval_error: "wrong_payload" } });
  const full = await checkout(one.did, 1500, approvalsFor(one.did, 1500));
  expect(full).toMatchObject({ decision: "allow", reasons: ["owner_approved_cart", "step_up_over"], evidence: { approval_kids: [a.approver.kid, b.approver.kid] } });
  // The approvals are for that cart and that request: another agent's cart of the same size is not covered by them.
  expect(await checkout(two.did, 1500, approvalsFor(one.did, 1500))).toMatchObject({ decision: "step_up" });

  // Pause the org: both agents are refused at the next check, and the products were told.
  expect((await call("POST", `/v1/orgs/${org.id}/pause`, { source: "web" }, b.auth)).body).toMatchObject({ paused: 2 });
  for (const k of [one, two]) {
    expect(await checkout(k.did, 800), k.did).toMatchObject({ decision: "deny", reasons: ["mandate_revoked"] });
    expect(events.filter((e) => e.type === "agent.paused" && e.data.agent_did === k.did).length, k.did).toBeGreaterThan(0);
  }
  expect((await signedPolicy(org.id)).state).toBe("paused");
});
