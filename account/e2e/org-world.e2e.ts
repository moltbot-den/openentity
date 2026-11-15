// The world for the cross-product organisation e2e (oneentity scripts/e2e-org.sh, docs/commerce/specs/enterprise-orgs.md
// "Done when"). This is the real account service over a real socket: an org of two approvers (quorum 2), one budget set
// once, two paired agents with org-signed mandates, and signed events to the products. Products that run as servers
// (Moltbot Den) receive the events live; the others get the exact signed requests from /_e2e/events.
//
//   OE_TEST_HOST=account.openentity.org OE_WORLD_PORT=8199 OE_WORLD_LIVE=did:web:moltbotden.com=http://127.0.0.1:8115 \
//     pnpm --filter @openentity/account exec vitest run --config vitest.e2e.config.ts e2e/org-world.e2e.ts
//
// Control routes (test only, never in the service): POST /_e2e/build builds the org and answers the world, POST
// /_e2e/approvals signs approval/2.0 for named approvers, POST /_e2e/pause pauses the org, GET /_e2e/events lists what
// the service sent, POST /_e2e/stop ends the run.
import { createServer } from "node:http";
import { canonicalize } from "@openentity/sdk";
import { afterAll, expect, test } from "vitest";
import { createApp } from "../src/app.ts";
import { HOST, approval, caller, testDeps } from "../test/helpers.ts";
import { orgWorld } from "../test/org-fixtures.ts";

const PORT = Number(process.env.OE_WORLD_PORT ?? 8199);
// product DID -> where it listens: live ones get the event over HTTP, the rest are recorded under a stand-in host.
const PRODUCTS: Record<string, string> = {
  "did:web:moltbotden.com": "https://127.0.0.1:8115",
  "did:web:api.agentsecretstore.com": "https://ass.e2e.invalid",
  "did:web:api.clawgrc.com": "https://clawgrc.e2e.invalid",
  "did:web:securemyagent.ai": "https://sma.e2e.invalid",
};
const LIVE = Object.fromEntries((process.env.OE_WORLD_LIVE ?? "").split(",").filter(Boolean).map((x) => { const i = x.indexOf("="); return [x.slice(0, i), x.slice(i + 1)]; }));
for (const [did, url] of Object.entries(LIVE)) PRODUCTS[did] = `https://${new URL(url).host}`;

interface Sent { n: number; product: string; url: string; headers: Record<string, string>; body: string; status: number; at: number }
const sent: Sent[] = [];
const d = await testDeps({
  products: PRODUCTS,
  // Signed for https://<host>; a live product is a local http server, so the scheme is the only thing rewritten.
  fetch: (async (url: string, init: RequestInit = {}) => {
    const u = new URL(url);
    // A product's did.json (how the account verifies its signed calls, e.g. the pause poll): the live product answers it itself.
    const did = Object.entries(LIVE).find(([p]) => url === `https://${p.slice("did:web:".length)}/.well-known/did.json`);
    if (did) return fetch(`${did[1]}/.well-known/did.json`);
    const product = Object.entries(PRODUCTS).find(([, base]) => new URL(base).host === u.host)?.[0];
    if (!product) throw new Error(`no network in the org world: ${url}`);
    const headers = init.headers as Record<string, string>, body = new TextDecoder().decode(init.body as Uint8Array);
    let status = 204, answer: string | undefined;
    if (LIVE[product]) {
      try { const r = await fetch(`${LIVE[product]}${u.pathname}${u.search}`, { method: init.method, headers, body }); status = r.status; answer = status === 204 ? undefined : await r.text(); } catch { status = 0; }
    }
    sent.push({ n: sent.length + 1, product, url, headers, body, status, at: Math.floor(Date.now() / 1000) });
    return new Response(answer ?? null, { status: status || 503, headers: { "content-type": "application/json" } });
  }) as typeof fetch,
  ws: { post: async () => true, close: async () => {} },
});
const app = createApp(d), call = caller(app), W = orgWorld(d, call);

type World = Awaited<ReturnType<typeof build>>;
let world: World | undefined, stopped!: () => void;
const done = new Promise<void>((r) => (stopped = r));

async function build() {
  const a = await W.person(), b = await W.person(), org = await W.newOrg(a, "Acme E2E");
  await W.join(org, b, "approver");
  const quorum = await W.stepUp(org, a, a.approver, "org.quorum.set", { org_id: org.id, quorum_m: 2 });
  expect((await call("PATCH", `/v1/orgs/${org.id}`, { quorum_m: 2 }, { ...a.auth, ...quorum })).status).toBe(200);
  const agents = [await W.pairAgent(org), await W.pairAgent(org)];
  for (const [i, k] of agents.entries()) {
    const r = await call("PATCH", W.agentUrl(org, k), { label: `e2e-agent-${i + 1}`, team: "ops", cost_centre: "CC-4711" }, a.auth);
    expect(r.status, r.text).toBe(200);
  }
  // One budget, set once: $3 a purchase, $25 a day, the approvers over $1, any merchant on credits and USDC (small, so a $5 test top-up reaches every line; a card top-up counts toward the day's cap).
  const budget = { per_tx_max: 300, period: "P1D", period_max: 2500, step_up_over: 100, rails: ["credits", "usdc"], merchants: [] as string[] };
  const bh = await W.stepUp(org, a, a.approver, "org.budget.set", { org_id: org.id, scope: "org", ref: "", ...budget });
  const set = await call("PUT", `/v1/orgs/${org.id}/budgets`, { scope: "org", ...budget }, { ...a.auth, ...bh });
  expect(set.status, set.text).toBe(200);
  const mandates: Record<string, unknown> = {};
  for (const k of agents) {
    const draft = (await call("POST", `/v1/orgs/${org.id}/mandates/draft`, { agent_did: k.did }, a.auth)).body.mandate;
    const signed = { ...draft, signature: { device_id: a.approver.kid, form: "p256", signature: a.approver.sign("mandate/1|*|" + canonicalize(draft)) } };
    const r = await call("POST", `/v1/orgs/${org.id}/mandates`, signed, a.auth);
    expect(r.status, r.text).toBe(201);
    mandates[k.did] = signed;
  }
  return {
    account_url: `http://127.0.0.1:${PORT}`, host: HOST, service_did: `did:web:${HOST}`,
    org: { id: org.id, did: org.did, log: org.log, quorum_m: 2 },
    approvers: { a: { kid: a.approver.kid, did: a.did, log: a.log, auth: a.auth }, b: { kid: b.approver.kid, did: b.did, log: b.log, auth: b.auth } },
    budget, agents: agents.map((k) => ({ did: k.did, private_jwk: k.privateJwk })), mandates,
    keys: { a: a.approver, b: b.approver }, // test-only device keys: used by /_e2e/approvals, never serialised
    kps: Object.fromEntries(agents.map((k) => [k.did, k])), // likewise: /_e2e/agent-keys signs as the agent
  };
}

const json = (res: import("node:http").ServerResponse, code: number, body: unknown) => { res.writeHead(code, { "content-type": "application/json" }); res.end(JSON.stringify(body)); };
const publicWorld = (w: World) => { const { keys: _k, kps: _p, ...rest } = w; return rest; };

const server = createServer(async (req, res) => {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  const raw = Buffer.concat(chunks);
  try {
    if (req.url?.startsWith("/_e2e/")) {
      const route = req.url.split("?")[0], q = new URL(req.url, "http://x").searchParams, input = raw.length ? JSON.parse(raw.toString()) : {};
      if (route === "/_e2e/build") return json(res, 200, publicWorld((world ??= await build())));
      if (route === "/_e2e/events") return json(res, 200, sent.filter((s) => s.n > Number(q.get("since") ?? 0) && (!q.get("product") || s.product === q.get("product"))));
      if (route === "/_e2e/stop") { json(res, 200, { stopping: true }); return stopped(); }
      if (!world) return json(res, 409, { error: "build first" });
      if (route === "/_e2e/approvals") { // input: {verifier_did, request_id, payload_digest, by: ["a","b"], expires_at?}
        const { by, ...a } = input as { by: ("a" | "b")[]; verifier_did: string; request_id: string; payload_digest: string; decision?: string; expires_at?: number };
        return json(res, 200, by.map((who) => approval(world!.keys[who], { ...a, owner_did: world!.org.did })));
      }
      if (route === "/_e2e/agent-keys") { // the agent asks the account for its product keys, as the SDK does: {agent_did} -> {credentials: [{product, key, expires_at}]}
        const r = await W.asAgent(world.kps[input.agent_did], "POST", "/v1/agent/credentials/renew", {});
        return json(res, r.status, r.body);
      }
      if (route === "/_e2e/pause") {
        const r = await call("POST", `/v1/orgs/${world.org.id}/pause`, { source: "web" }, world.approvers.b.auth);
        return json(res, r.status, { ...r.body, at: Math.floor(Date.now() / 1000), events: sent.length });
      }
      return json(res, 404, { error: "no such control route" });
    }
    const r = await app.fetch(new Request(`http://${req.headers.host ?? HOST}${req.url}`, { method: req.method, headers: { ...(req.headers as Record<string, string>), "x-oe-viewer-address": "127.0.0.1" }, body: ["GET", "HEAD"].includes(req.method!) ? undefined : raw }));
    res.writeHead(r.status, Object.fromEntries(r.headers));
    res.end(Buffer.from(await r.arrayBuffer()));
  } catch (e) {
    json(res, 500, { error: String((e as Error).stack ?? e) });
  }
});
await new Promise<void>((r) => server.listen(PORT, "127.0.0.1", r));
afterAll(() => void server.close());

test("the world runs until the e2e stops it", async () => {
  console.log(`org world on http://127.0.0.1:${PORT} (host ${HOST})`);
  await done;
}, 3_600_000);
