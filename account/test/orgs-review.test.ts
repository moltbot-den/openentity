// Adversarial-review regressions for C5 organisations (budget periods, currency, budget step-up, CSV tags, last admin).
import { canonicalize } from "@openentity/sdk";
import { expect, test } from "vitest";
import { createApp } from "../src/app.ts";
import { caller, testDeps, type Key } from "./helpers.ts";
import { orgWorld } from "./org-fixtures.ts";

const d = await testDeps({ fetch: (async () => new Response(null, { status: 204 })) as typeof fetch, ws: { post: async () => true, close: async () => {} } });
const app = createApp(d), call = caller(app);
const { person, newOrg, stepUp, join, pairAgent } = orgWorld(d, call);

test("two admins demoting each other at once leave one admin", async () => {
  const a = await person(), org = await newOrg(a), b = await person();
  await join(org, b, "admin");
  const demote = async (by: typeof a, who: typeof a) => call("PATCH", `/v1/orgs/${org.id}/members/${who.accountId}`, { role: "approver" },
    { ...by.auth, ...(await stepUp(org, by, by.approver, "org.member.set", { org_id: org.id, account_id: who.accountId, role: "approver" })) });
  const [x, y] = await Promise.all([demote(a, b), demote(b, a)]);
  expect([x.status, y.status].filter((n) => n === 200)).toHaveLength(1); // the other is refused
  const members = (await call("GET", `/v1/orgs/${org.id}/members`, undefined, (x.status === 200 ? a : b).auth)).body.members;
  expect(members.filter((m: any) => m.role === "admin")).toHaveLength(1);
});

test("with a quorum of 2 or more one admin cannot raise spending alone: a new or larger budget is a step-up, a lower one is not", async () => {
  const a = await person(), org = await newOrg(a), b = await person();
  await join(org, b, "approver");
  await call("PATCH", `/v1/orgs/${org.id}`, { quorum_m: 2 }, { ...a.auth, ...(await stepUp(org, a, a.approver, "org.quorum.set", { org_id: org.id, quorum_m: 2 })) });
  const budget = { scope: "org", per_tx_max: 2000, period: "P1D", period_max: 5000, step_up_over: 1000, rails: ["credits"], merchants: [] as string[] };
  const put = (body: object, h = {}) => call("PUT", `/v1/orgs/${org.id}/budgets`, body, { ...a.auth, ...h });
  expect((await put(budget)).status).toBe(428);
  const approve = (bud: object, by: Key = a.approver) => stepUp(org, a, by, "org.budget.set", { org_id: org.id, scope: "org", ref: "", ...bud });
  const { scope: _s, ...fields } = budget;
  expect((await put({ ...budget, per_tx_max: 3000 }, await approve(fields))).status).toBe(403); // an approval names the exact budget
  expect((await put(budget, await approve(fields, b.approver))).status).toBe(403); // only the acting admin's own device signs
  const ok = await approve(fields);
  expect((await put(budget, ok)).status).toBe(200);
  expect((await put({ ...budget, per_tx_max: 1500, period_max: 4000 })).status).toBe(200); // lowering needs no approval
  expect((await put({ ...budget, per_tx_max: 2000, period_max: 5000 })).status).toBe(428); // raising again does
});

test("an org mandate must be in USD like the budgets: 100 GBP is not a $100 budget", async () => {
  const a = await person(), org = await newOrg(a), agent = await pairAgent(org);
  await call("PUT", `/v1/orgs/${org.id}/budgets`, { scope: "org", per_tx_max: 10000, period: "P1D", period_max: 10000, rails: ["credits"] }, a.auth);
  const dr = (await call("POST", `/v1/orgs/${org.id}/mandates/draft`, { agent_did: agent.did }, a.auth)).body.mandate;
  const gbp = { ...dr, limits: { ...dr.limits, currency: "GBP" } };
  const sign = (m: any) => ({ ...m, signature: { device_id: a.approver.kid, form: "p256", signature: a.approver.sign("mandate/1|*|" + canonicalize(m)) } });
  expect((await call("POST", `/v1/orgs/${org.id}/mandates`, sign(gbp), a.auth)).body.error).toBe("over_budget");
  expect((await call("POST", `/v1/orgs/${org.id}/mandates`, sign(dr), a.auth)).status).toBe(201);
});

test("a longer-period agent budget cannot hide a burst inside a shorter org window", async () => {
  const a = await person(), org = await newOrg(a), agent = await pairAgent(org);
  const base = { per_tx_max: 10000, rails: ["credits"] };
  await call("PUT", `/v1/orgs/${org.id}/budgets`, { scope: "org", period: "P1D", period_max: 10000, ...base }, a.auth);
  const r = await call("PUT", `/v1/orgs/${org.id}/budgets`, { scope: "agent", ref: agent.did, period: "P1M", period_max: 300000, ...base }, a.auth);
  expect([r.status, r.body.error]).toEqual([400, "exceeds_parent"]);
});

test("the CSV shows tags only for agents of this org, never another owner's current tags", async () => {
  const a = await person(), org = await newOrg(a);
  const agent = await pairAgent(org);
  await call("PUT", `/v1/orgs/${org.id}/budgets`, { scope: "org", per_tx_max: 1000, period: "P1D", period_max: 3000, rails: ["credits"] }, a.auth);
  const dr = (await call("POST", `/v1/orgs/${org.id}/mandates/draft`, { agent_did: agent.did }, a.auth)).body.mandate;
  await call("POST", `/v1/orgs/${org.id}/mandates`, { ...dr, signature: { device_id: a.approver.kid, form: "p256", signature: a.approver.sign("mandate/1|*|" + canonicalize(dr)) } }, a.auth);
  // The agent leaves for another owner, who tags it.
  await d.db.run("UPDATE agents SET org_id = NULL, team = 'secret-project', cost_centre = 'CC-SECRET' WHERE did = $1", [agent.did]);
  const csv = (await call("GET", `/v1/orgs/${org.id}/export.csv`, undefined, a.auth)).text;
  expect(csv).toContain(agent.did);
  expect(csv).not.toContain("secret-project");
  expect(csv).not.toContain("CC-SECRET");
});
