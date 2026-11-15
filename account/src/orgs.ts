// Organisations (enterprise orgs spec, C5): an owner principal with its own key log, members with roles, budgets issued as
// org-signed mandate/1, quorum approvals, a pause that stops every org agent, and an org view of the same agents.
//
// Trust model, in one place:
//  - The org key log is the authority. Its approvers are member devices; every product verifies an org's approvals and
//    mandates against that log with the SDK, never against this service's tables.
//  - Roles (admin > approver > viewer) and the quorum list are this service's access control. A device counts toward a
//    quorum only if a member with role approver or admin registered it (PUT /device) and it is still in the log: one
//    device per member, so m devices are m members. GET /o/<id>/policy publishes that list, signed by this service.
//  - Admin and approver changes, a lower or higher quorum, resuming the org and widening an org agent are step-ups: an
//    approval/2.0 owned by the org, signed by the acting admin's own registered device.
import { createHash } from "node:crypto";
import type { Context, Hono } from "hono";
import { type Mandate, mandateDigest } from "@openentity/sdk";
import { type AgentRow, agentView, approvalView, pause, resume, setPermissions, signedJson, unlink, type ApprovalRow } from "./agents.ts";
import type { Deps } from "./app.ts";
import { bump, newId, now } from "./db.ts";
import { deliver } from "./ws.ts";
import { bearer, fail, json, str } from "./http.ts";
import { append, base32, genesisGate, keyLogState } from "./keylog.ts";
import { issueMandate, push, revokeFor, statusUrl, view as mandateView, type Row as MandateRow } from "./mandates.ts";
import { type OrgRow, type Role, ROLES, bumpOrg, memberDevice, orgAgent, orgOf, quorumDevices, quorumOf } from "./orgbase.ts";
import { type Budget, draftMandate, ofMandate, parseBudget, within } from "./orgbudget.ts";
import { checkApproval, permissionList, requireApproval } from "./stepup.ts";
import { track } from "./events.ts";

const MAX_ORGS = 20, MAX_MEMBERS = 200, ORG_ID = /^[a-z2-7]{52}$/, TAG = /^[^\u0000-\u001f\u007f]{1,64}$/u, ACCOUNT_ID = /^[A-Za-z0-9_-]{1,64}$/;
const sha = (s: string) => createHash("sha256").update(s, "utf8").digest();
const strong = (r?: string) => r === "admin" || r === "approver";

interface BudgetRow { id: string; org_id: string; scope: "org" | "team" | "agent"; ref: string; body: string; updated_at: number }
const budgetView = (r: BudgetRow) => ({ budget_id: r.id, scope: r.scope, ref: r.ref, ...JSON.parse(r.body), updated_at: Number(r.updated_at) });

/** A CSV cell that no spreadsheet runs as a formula, with quotes doubled. */
const cell = (v: unknown) => {
  let s = v === null || v === undefined ? "" : String(v);
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return /[",\n\r]/.test(s) ? `"${s.replaceAll('"', '""')}"` : s;
};

export function routes(app: Hono, d: Deps) {
  const me = async (c: Context, min: Role) => {
    const o = await bearer(c, d), id = c.req.param("id") ?? "";
    if (!ORG_ID.test(id)) fail(404, "not_found", "no such organisation");
    return { o, ...(await orgOf(d, o.accountId, id, min)) };
  };
  const orgView = async (org: OrgRow, role: Role) => ({ id: org.id, did: org.owner_did, name: org.name, state: org.state, role, quorum: await quorumOf(d, org), seq: org.seq, created_at: org.created_at });
  const tag = (v: unknown, name: string): string | null => v === null ? null : typeof v === "string" && TAG.test(v) ? v : fail(400, "bad_request", `${name} is 1 to 64 characters without control characters, or null`);

  /** The step-up for an org action: the approval is the org's, signed by the acting admin's own registered device. */
  const stepUp = async (c: Context, org: OrgRow, accountId: string, action: "org.member.set" | "org.quorum.set" | "org.resume" | "agent.permissions.widen" | "agent.resume", params: Record<string, unknown>) => {
    const { kid } = await requireApproval(c, d, { accountId, ownerDid: org.owner_did, action, params });
    await memberDevice(d, org, accountId, kid);
  };

  // ---------------------------------------------------------------- the org
  app.post("/v1/orgs", async (c) => {
    const o = await genesisGate(c, d), b = await json(c);
    const name = str(b.name, "name", 80), line = str(b.line, "line", 65_536);
    if (!o.ownerDid) fail(403, "key_log_required", "creating an organisation needs your own key log first; finish \"Turn on Face ID approvals\"");
    if (Number((await d.db.first<{ n: number }>("SELECT count(*) AS n FROM org_members WHERE account_id = $1", [o.accountId]))!.n) >= MAX_ORGS) fail(409, "too_many_orgs", `at most ${MAX_ORGS} organisations per account`);
    try { if (JSON.parse(line)?.op !== "genesis") throw 0; } catch { fail(400, "bad_request", "line is the org key log's genesis entry"); }
    const id = base32(sha(line));
    await append(d, id, line, { account: o.accountId, org: { name } });
    await track(d, "org_created", {}, { owner: o.ownerDid });
    const { org, role } = await orgOf(d, o.accountId, id, "viewer");
    return c.json(await orgView(org, role), 201);
  });

  app.get("/v1/orgs", async (c) => {
    const o = await bearer(c, d);
    const rows = await d.db.all<OrgRow & { role: Role }>("SELECT g.*, m.role FROM orgs g JOIN org_members m ON m.org_id = g.id WHERE m.account_id = $1 ORDER BY g.created_at", [o.accountId]);
    return c.json({ orgs: await Promise.all(rows.map((r) => orgView({ ...r, quorum_m: Number(r.quorum_m), seq: Number(r.seq), created_at: Number(r.created_at) }, r.role))) });
  });

  app.get("/v1/orgs/:id", async (c) => {
    const { org, role } = await me(c, "viewer");
    return c.json(await orgView(org, role));
  });

  app.patch("/v1/orgs/:id", async (c) => {
    const { o, org, role } = await me(c, "admin"), b = await json(c);
    if (b.name === undefined && b.quorum_m === undefined) fail(400, "bad_request", "send name or quorum_m");
    if (b.name !== undefined) await d.db.run("UPDATE orgs SET name = $2 WHERE id = $1", [org.id, str(b.name, "name", 80)]);
    if (b.quorum_m !== undefined && b.quorum_m !== org.quorum_m) {
      if (!Number.isInteger(b.quorum_m) || b.quorum_m < 1 || b.quorum_m > 16) fail(400, "bad_request", "quorum_m is 1 to 16");
      await stepUp(c, org, o.accountId, "org.quorum.set", { org_id: org.id, quorum_m: b.quorum_m });
      await d.db.run("UPDATE orgs SET quorum_m = $2, seq = seq + 1 WHERE id = $1", [org.id, b.quorum_m]);
    }
    return c.json(await orgView((await orgOf(d, o.accountId, org.id, "viewer")).org, role));
  });

  // ---------------------------------------------------------------- the policy products read
  // Public and signed (RFC 9421, like GET /v1/paused): the quorum a product enforces for an org-owned approval, and whether the org is paused.
  app.get("/o/:id/policy", async (c) => {
    const id = c.req.param("id") ?? "";
    const org = ORG_ID.test(id) ? await d.db.first<OrgRow>("SELECT * FROM orgs WHERE id = $1", [id]) : null;
    if (!org) fail(404, "not_found", "no such organisation");
    const q = await quorumOf(d, org!);
    c.header("cache-control", "public, max-age=30");
    return signedJson(c, d, { org_did: org!.owner_did, state: org!.state, quorum: { m: q.m, of: q.of }, seq: Number(org!.seq), generated_at: now() });
  });

  // ---------------------------------------------------------------- members and devices
  app.get("/v1/orgs/:id/members", async (c) => {
    const { org } = await me(c, "viewer");
    const rows = await d.db.all<{ account_id: string; email: string | null; role: Role; kid: string | null }>(
      "SELECT m.account_id, a.email, m.role, v.kid FROM org_members m JOIN accounts a ON a.id = m.account_id LEFT JOIN org_devices v ON v.org_id = m.org_id AND v.account_id = m.account_id WHERE m.org_id = $1 ORDER BY m.added_at, m.account_id", [org.id]);
    return c.json({ members: rows.map((r) => ({ account_id: r.account_id, email: r.email, role: r.role, device: r.kid })) });
  });

  /** Sets a member's role (or removes them with "none"). Admin and approver changes are step-ups; a device still in the log blocks demotion. */
  const setRole = async (c: Context, org: OrgRow, acting: string, target: string, role: Role | "none") => {
    const cur = await d.db.first<{ role: Role }>("SELECT role FROM org_members WHERE org_id = $1 AND account_id = $2", [org.id, target]);
    if (!cur && role === "none") fail(404, "not_found", "no such member");
    if (cur?.role === role) return;
    if (!cur && Number((await d.db.first<{ n: number }>("SELECT count(*) AS n FROM org_members WHERE org_id = $1", [org.id]))!.n) >= MAX_MEMBERS) fail(409, "too_many_members", `at most ${MAX_MEMBERS} members`);
    if (strong(role) || strong(cur?.role)) await stepUp(c, org, acting, "org.member.set", { org_id: org.id, account_id: target, role });
    if (cur?.role === "admin" && role !== "admin" && Number((await d.db.first<{ n: number }>("SELECT count(*) AS n FROM org_members WHERE org_id = $1 AND role = 'admin'", [org.id]))!.n) <= 1) fail(409, "last_admin", "an organisation keeps at least one admin");
    if (!strong(role)) {
      // A viewer or a removed member must not keep an approver key in the org log: an approver there can add keys and sign.
      const dev = await d.db.first<{ kid: string }>("SELECT kid FROM org_devices WHERE org_id = $1 AND account_id = $2", [org.id, target]);
      if (dev) {
        const log = await keyLogState(d, org.owner_did);
        if (log && !log.closed && log.approvers.some((a) => a.kid === dev.kid)) fail(409, "device_in_log", `revoke key ${dev.kid} from the org key log first (a revoke entry signed by another approver), then change this member`);
        await d.db.run("DELETE FROM org_devices WHERE org_id = $1 AND account_id = $2", [org.id, target]);
      }
    }
    if (role === "none") {
      await d.db.run("DELETE FROM org_members WHERE org_id = $1 AND account_id = $2", [org.id, target]);
      await d.db.run("UPDATE agents SET account_id = $3 WHERE org_id = $1 AND account_id = $2", [org.id, target, acting]); // the pairer's seat passes to the admin who removed them
    } else {
      await d.db.run("INSERT INTO org_members (org_id, account_id, role, added_at) VALUES ($1, $2, $3, $4) ON CONFLICT (org_id, account_id) DO UPDATE SET role = $3", [org.id, target, role, now()]);
    }
    await bumpOrg(d, org.id);
  };

  app.post("/v1/orgs/:id/members", async (c) => {
    const { o, org } = await me(c, "admin"), b = await json(c);
    const role = ROLES.includes(b.role) ? b.role as Role : fail(400, "bad_request", "role is admin, approver or viewer");
    const email = str(b.email, "email", 254).trim().toLowerCase();
    if ((await bump(d.db, `orgadd:${o.accountId}`, String(Math.floor(now() / 3600)))) > 30) fail(429, "rate_limited", "at most 30 members added an hour", { retry_after: 3600 });
    const target = await d.db.first<{ id: string }>("SELECT id FROM accounts WHERE email = $1 AND deleted_at IS NULL", [email]);
    if (!target) fail(404, "no_account", "that person has no OpenEntity account yet: ask them to sign in once, then add them");
    if (await d.db.first("SELECT 1 FROM org_members WHERE org_id = $1 AND account_id = $2", [org.id, target!.id])) fail(409, "already_member", "already a member; change their role instead");
    await setRole(c, org, o.accountId, target!.id, role);
    return c.json({ account_id: target!.id, email, role }, 201);
  });

  app.patch("/v1/orgs/:id/members/:account_id", async (c) => {
    const { o, org } = await me(c, "admin"), b = await json(c), target = c.req.param("account_id") ?? "";
    if (!ACCOUNT_ID.test(target)) fail(404, "not_found", "no such member");
    if (!ROLES.includes(b.role)) fail(400, "bad_request", "role is admin, approver or viewer");
    if (!(await d.db.first("SELECT 1 FROM org_members WHERE org_id = $1 AND account_id = $2", [org.id, target]))) fail(404, "not_found", "no such member");
    await setRole(c, org, o.accountId, target, b.role);
    return c.json({ account_id: target, role: b.role });
  });

  app.delete("/v1/orgs/:id/members/:account_id", async (c) => {
    const { o, org } = await me(c, "admin"), target = c.req.param("account_id") ?? "";
    if (!ACCOUNT_ID.test(target)) fail(404, "not_found", "no such member");
    await setRole(c, org, o.accountId, target, "none");
    return c.body(null, 204);
  });

  // Registers the caller's device for the org: a current approver of both the org's key log and the caller's own.
  app.put("/v1/orgs/:id/device", async (c) => {
    const { o, org } = await me(c, "approver"), b = await json(c), kid = str(b.kid, "kid", 128);
    const own = o.ownerDid ? await keyLogState(d, o.ownerDid) : null, log = await keyLogState(d, org.owner_did);
    if (!own?.approvers.some((a) => a.kid === kid) || !log || log.closed || !log.approvers.some((a) => a.kid === kid)) {
      fail(403, "device_not_approver", "the device must be a current approver in your own key log and in the org's (add it to the org log first, with an add_approver entry signed by a current org approver)");
    }
    await d.db.tx(async (tx) => {
      await tx.run("DELETE FROM org_devices WHERE org_id = $1 AND account_id = $2", [org.id, o.accountId]);
      const ins = await tx.run("INSERT INTO org_devices (org_id, account_id, kid, added_at) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING", [org.id, o.accountId, kid, now()]);
      if (!ins.changes) fail(409, "device_taken", "another member registered this key");
    });
    await bumpOrg(d, org.id);
    return c.json({ kid });
  });

  app.delete("/v1/orgs/:id/device", async (c) => {
    const { o, org } = await me(c, "approver");
    await d.db.run("DELETE FROM org_devices WHERE org_id = $1 AND account_id = $2", [org.id, o.accountId]);
    await bumpOrg(d, org.id);
    return c.body(null, 204);
  });

  // ---------------------------------------------------------------- agents
  const orgAgents = async (org: OrgRow) => d.db.all<AgentRow>("SELECT * FROM agents WHERE org_id = $1 AND state <> 'unlinked' ORDER BY paired_at, did", [org.id]);
  const agentParam = (c: Context) => decodeURIComponent(c.req.param("agent_did") ?? "");

  app.get("/v1/orgs/:id/agents", async (c) => {
    const { org } = await me(c, "viewer");
    return c.json({ agents: await Promise.all((await orgAgents(org)).map((a) => agentView(d, a))) });
  });

  app.patch("/v1/orgs/:id/agents/:agent_did", async (c) => {
    const { o, org } = await me(c, "admin"), b = await json(c);
    const a = await orgAgent(d, org, agentParam(c));
    if (b.label === undefined && b.permissions === undefined && b.team === undefined && b.cost_centre === undefined) fail(400, "bad_request", "send label, team, cost_centre or permissions");
    if (b.label !== undefined && (typeof b.label !== "string" || b.label.length > 80)) fail(400, "bad_request", "label is at most 80 characters");
    const team = b.team === undefined ? undefined : tag(b.team, "team"), cost = b.cost_centre === undefined ? undefined : tag(b.cost_centre, "cost_centre");
    if (b.permissions !== undefined) {
      const next = permissionList(b.permissions), held: string[] = JSON.parse(a.permissions);
      if (next.some((p) => !held.includes(p))) await stepUp(c, org, o.accountId, "agent.permissions.widen", { agent_did: a.did, permissions: next });
      if (JSON.stringify(next) !== JSON.stringify(held)) await setPermissions(d, a, next);
    }
    if (b.label !== undefined) await d.db.run("UPDATE agents SET label = $2 WHERE did = $1", [a.did, b.label]);
    if (team !== undefined) await d.db.run("UPDATE agents SET team = $2 WHERE did = $1", [a.did, team]);
    if (cost !== undefined) await d.db.run("UPDATE agents SET cost_centre = $2 WHERE did = $1", [a.did, cost]);
    const after = await orgAgent(d, org, a.did);
    if (team !== undefined || cost !== undefined) {
      await reconcile(org, after); // a new team can mean a narrower budget
      await push(d, a.did, org.owner_did); // and the products learn the new tags with the mandates
    }
    return c.json(await agentView(d, after));
  });

  app.delete("/v1/orgs/:id/agents/:agent_did", async (c) => {
    const { org } = await me(c, "admin");
    await unlink(d, await orgAgent(d, org, agentParam(c)), "the organisation unlinked this agent");
    return c.body(null, 204);
  });

  const source = (b: Record<string, any>) => ["app", "control", "siri", "tile", "widget", "web"].includes(b.source) ? b.source as string : fail(400, "bad_request", "source is app, control, siri, tile, widget or web");

  app.post("/v1/orgs/:id/agents/:agent_did/pause", async (c) => {
    const { org } = await me(c, "approver"), src = source(await json(c));
    const a = await orgAgent(d, org, agentParam(c));
    await pause(d, a, src);
    return c.json(await agentView(d, await orgAgent(d, org, a.did)));
  });

  app.post("/v1/orgs/:id/agents/:agent_did/resume", async (c) => {
    const { o, org } = await me(c, "admin");
    const a = await orgAgent(d, org, agentParam(c));
    if (org.state === "paused") fail(423, "org_paused", "the organisation is paused; resume the organisation first");
    if (a.state !== "paused") fail(409, "not_paused", "this agent is not paused");
    await stepUp(c, org, o.accountId, "agent.resume", { agent_did: a.did });
    await resume(d, a);
    return c.json(await agentView(d, await orgAgent(d, org, a.did)));
  });

  // The kill switch: every org agent pauses at once. The pause events go to the products now and the signed feed (GET /v1/paused) carries them within 30 seconds.
  app.post("/v1/orgs/:id/pause", async (c) => {
    const { org } = await me(c, "approver"), src = source(await json(c));
    if (org.state === "active") await d.db.run("UPDATE orgs SET state = 'paused', seq = seq + 1 WHERE id = $1 AND state = 'active'", [org.id]);
    const active = (await orgAgents(org)).filter((a) => a.state === "active");
    const done = await Promise.all(active.map((a) => pause(d, a, src)));
    await track(d, "org_paused", { source: src }, { owner: org.owner_did });
    return c.json({ state: "paused", paused: done.filter(Boolean).length });
  });

  app.post("/v1/orgs/:id/resume", async (c) => {
    const { o, org } = await me(c, "admin");
    await stepUp(c, org, o.accountId, "org.resume", { org_id: org.id });
    await d.db.run("UPDATE orgs SET state = 'active', seq = seq + 1 WHERE id = $1", [org.id]);
    let n = 0;
    for (const a of (await orgAgents(org)).filter((x) => x.state === "paused")) { await resume(d, a).then(() => n++).catch(() => null); }
    return c.json({ state: "active", resumed: n });
  });

  // ---------------------------------------------------------------- budgets
  const budgetsFor = async (org: OrgRow, a: Pick<AgentRow, "did" | "team">): Promise<{ scope: string; b: Budget }[]> =>
    (await d.db.all<BudgetRow>("SELECT * FROM org_budgets WHERE org_id = $1 AND ((scope = 'org') OR (scope = 'team' AND ref = $2) OR (scope = 'agent' AND ref = $3))", [org.id, a.team, a.did]))
      .map((r) => ({ scope: r.scope, b: JSON.parse(r.body) as Budget }));
  /** The most specific budget: the agent's own, else its team's, else the org's. */
  const effective = (list: { scope: string; b: Budget }[]) => (["agent", "team", "org"] as const).map((s) => list.find((x) => x.scope === s)).find(Boolean)?.b ?? null;
  /** Ends the agent's mandates that no longer fit every budget that applies to it (all of them when none applies). */
  const reconcile = async (org: OrgRow, a: AgentRow) => {
    const list = await budgetsFor(org, a);
    await revokeFor(d, a, "budget_changed", (m: Mandate) => list.length > 0 && list.every((x) => within(ofMandate(m), x.b)));
  };

  app.get("/v1/orgs/:id/budgets", async (c) => {
    const { org } = await me(c, "viewer");
    return c.json({ budgets: (await d.db.all<BudgetRow>("SELECT * FROM org_budgets WHERE org_id = $1 ORDER BY scope, ref", [org.id])).map(budgetView) });
  });

  app.put("/v1/orgs/:id/budgets", async (c) => {
    const { org } = await me(c, "admin"), b = await json(c);
    const scope = ["org", "team", "agent"].includes(b.scope) ? b.scope as "org" | "team" | "agent" : fail(400, "bad_request", "scope is org, team or agent");
    const budget = parseBudget(b);
    if (typeof budget === "string") fail(400, "bad_request", budget);
    const ref = scope === "org" ? "" : scope === "team" ? tag(b.ref, "ref") ?? fail(400, "bad_request", "ref is the team tag") : (await orgAgent(d, org, String(b.ref ?? ""))).did;
    const all = (await d.db.all<BudgetRow>("SELECT * FROM org_budgets WHERE org_id = $1", [org.id])).filter((r) => !(r.scope === scope && r.ref === ref));
    const agents = await orgAgents(org);
    const teamOf = (did: string) => agents.find((a) => a.did === did)?.team ?? null;
    // Narrower budgets stay inside wider ones, both ways: this one inside its parents, and its children inside this one.
    const parents = all.filter((r) => scope !== "org" && (r.scope === "org" || (scope === "agent" && r.scope === "team" && r.ref === teamOf(ref))));
    const bad = parents.find((r) => !within(budget as Budget, JSON.parse(r.body)));
    if (bad) fail(400, "exceeds_parent", `the ${bad.scope} budget${bad.ref ? ` ${bad.ref}` : ""} is narrower; lower this one or raise that one first`);
    const children = all.filter((r) => scope === "org" ? true : scope === "team" ? r.scope === "agent" && teamOf(r.ref) === ref : false);
    const over = children.filter((r) => !within(JSON.parse(r.body), budget as Budget));
    if (over.length) fail(409, "children_exceed", `these narrower budgets would exceed this one: ${over.map((r) => `${r.scope} ${r.ref || "org"}`).join(", ")}`);
    const t = now();
    await d.db.run("INSERT INTO org_budgets (id, org_id, scope, ref, body, updated_at) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (org_id, scope, ref) DO UPDATE SET body = $5, updated_at = $6",
      [newId("bud"), org.id, scope, ref, JSON.stringify(budget), t]);
    const hit = scope === "org" ? agents : scope === "team" ? agents.filter((a) => a.team === ref) : agents.filter((a) => a.did === ref);
    for (const a of hit) await reconcile(org, a); // lowering a budget ends the mandates it no longer fits
    return c.json(budgetView((await d.db.first<BudgetRow>("SELECT * FROM org_budgets WHERE org_id = $1 AND scope = $2 AND ref = $3", [org.id, scope, ref]))!));
  });

  app.delete("/v1/orgs/:id/budgets/:budget_id", async (c) => {
    const { org } = await me(c, "admin");
    const r = await d.db.first<BudgetRow>("DELETE FROM org_budgets WHERE id = $1 AND org_id = $2 RETURNING *", [c.req.param("budget_id"), org.id]) ?? fail(404, "not_found", "no such budget");
    const hit = (await orgAgents(org)).filter((a) => r.scope === "org" || (r.scope === "team" ? a.team === r.ref : a.did === r.ref));
    for (const a of hit) await reconcile(org, a);
    return c.body(null, 204);
  });

  // ---------------------------------------------------------------- mandates: budgets reach products as org-signed mandate/1
  app.post("/v1/orgs/:id/mandates/draft", async (c) => {
    const { org } = await me(c, "admin"), b = await json(c);
    const a = await orgAgent(d, org, String(b.agent_did ?? ""));
    const bud = effective(await budgetsFor(org, a)) ?? fail(409, "no_budget", "no budget applies to this agent: set an org, team or agent budget first");
    const days = b.expires_in_days === undefined ? 30 : Number(b.expires_in_days);
    if (!Number.isInteger(days) || days < 1 || days > 90) fail(400, "bad_request", "expires_in_days is 1 to 90");
    const id = `md_${base32(sha(`${newId("x")}`)).slice(0, 26)}`;
    const mandate = draftMandate(bud!, { id, issuer: org.owner_did, agent: a.did, t: now(), days, status: statusUrl(d, id) });
    return c.json({ mandate, digest: Buffer.from(mandateDigest(mandate)).toString("hex") });
  });

  app.post("/v1/orgs/:id/mandates", async (c) => {
    const { o, org } = await me(c, "admin"), m = await json(c) as unknown as Mandate;
    const a = await orgAgent(d, org, String(m.agent_did));
    if (org.state === "paused") fail(423, "org_paused", "the organisation is paused");
    const out = await issueMandate(d, {
      accountId: o.accountId, ownerDid: org.owner_did, agent: a, mandate: m, ceiling: "none",
      check: async (md) => {
        // Signed by a device a member registered for the org, and inside every budget that applies to the agent.
        if (!(await quorumDevices(d, org)).some((v) => v.kid === md.signature?.device_id)) fail(403, "device_not_registered", "sign with a device an admin or approver registered for this organisation");
        const list = await budgetsFor(org, a);
        if (!list.length) fail(403, "over_budget", "no budget applies to this agent");
        const bad = list.find((x) => !within(ofMandate(md), x.b));
        if (bad) fail(403, "over_budget", `the mandate exceeds the ${bad.scope} budget`);
      },
    });
    return c.json(out, 201);
  });

  app.get("/v1/orgs/:id/mandates", async (c) => {
    const { org } = await me(c, "viewer"), agent = c.req.query("agent");
    const rows = await d.db.all<MandateRow>("SELECT * FROM mandates WHERE owner_did = $1 AND ($2::text IS NULL OR agent_did = $2) ORDER BY issued_at DESC, id LIMIT 200", [org.owner_did, agent ?? null]);
    return c.json({ mandates: rows.map(mandateView) });
  });

  app.delete("/v1/orgs/:id/mandates/:mandate_id", async (c) => {
    const { org } = await me(c, "admin");
    const r = await d.db.first<MandateRow>("SELECT * FROM mandates WHERE id = $1 AND owner_did = $2", [c.req.param("mandate_id"), org.owner_did]) ?? fail(404, "not_found", "no such mandate");
    if (r.revoked_at === null) {
      await d.db.run("UPDATE mandates SET revoked_at = $2, revoke_reason = 'owner' WHERE id = $1 AND revoked_at IS NULL", [r.id, now()]);
      await push(d, r.agent_did, r.owner_did);
    }
    return c.body(null, 204);
  });

  // ---------------------------------------------------------------- quorum approvals of the agents' requests
  interface Vote { kid: string; decision: string; approval: string; at: number }
  const votesOf = (id: string) => d.db.all<Vote>("SELECT kid, decision, approval, at FROM approval_votes WHERE approval_id = $1 ORDER BY at, kid", [id]);
  const withVotes = async (r: ApprovalRow) => ({ ...approvalView(d, r, true), votes: (await votesOf(r.id)).map((v) => ({ device: v.kid, decision: v.decision, at: Number(v.at) })) });

  app.get("/v1/orgs/:id/approvals", async (c) => {
    const { org } = await me(c, "viewer"), decided = c.req.query("state") === "decided";
    const rows = await d.db.all<ApprovalRow>(decided
      ? "SELECT * FROM agent_approvals WHERE owner_did = $1 AND quorum IS NOT NULL AND (state <> 'pending' OR expires_at <= $2) ORDER BY created_at DESC LIMIT 100"
      : "SELECT * FROM agent_approvals WHERE owner_did = $1 AND quorum IS NOT NULL AND state = 'pending' AND expires_at > $2 ORDER BY created_at DESC LIMIT 100", [org.owner_did, now()]);
    return c.json({ approvals: await Promise.all(rows.map(withVotes)) });
  });

  // One device's decision. The approval is verified like any approval/2.0 (X-OE-Approval, the org as owner); it counts if the
  // device is one the quorum named when the agent asked, is the caller's own, and is still in the log. m approves approve it;
  // more denies than the quorum can overcome deny it.
  app.post("/v1/orgs/:id/approvals/:approval_id/decision", async (c) => {
    const { o, org } = await me(c, "approver");
    const r = await d.db.first<ApprovalRow>("SELECT * FROM agent_approvals WHERE id = $1 AND owner_did = $2 AND quorum IS NOT NULL", [c.req.param("approval_id"), org.owner_did]) ?? fail(404, "not_found", "no such approval");
    if (r.state !== "pending") fail(409, "already_decided", "this approval was already decided");
    if (Number(r.expires_at) <= now()) fail(410, "expired", "this approval request expired");
    const q = JSON.parse(r.quorum!) as { m: number; of: string[] };
    const { kid, decision, approval } = await checkApproval(c, d, { ownerDid: org.owner_did, requestId: r.request_id, payloadDigest: r.payload_digest });
    if (!q.of.includes(kid)) fail(403, "not_in_quorum", "this device was not in the quorum when the agent asked");
    await memberDevice(d, org, o.accountId, kid);
    const ins = await d.db.run("INSERT INTO approval_votes (approval_id, kid, decision, approval, at) VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING", [r.id, kid, decision, JSON.stringify(approval), now()]);
    if (!ins.changes) fail(409, "already_voted", "this device already answered");
    const live = new Set((await quorumDevices(d, org)).map((v) => v.kid));
    const counted = (await votesOf(r.id)).filter((v) => q.of.includes(v.kid) && live.has(v.kid));
    const yes = counted.filter((v) => v.decision === "approve"), no = counted.filter((v) => v.decision === "deny");
    const done = yes.length >= q.m ? { state: "approved", from: yes } : no.length > q.of.length - q.m ? { state: "denied", from: no } : null;
    let row = r;
    if (done) {
      const bundle = done.from.map((v) => JSON.parse(v.approval)), t = now();
      const won = await d.db.run("UPDATE agent_approvals SET state = $2, approval = $3, approvals = $4, decided_at = $5 WHERE id = $1 AND state = 'pending'", [r.id, done.state, JSON.stringify(bundle[0]), JSON.stringify(bundle), t]);
      if (won.changes) {
        await deliver(d, r.agent_did, { type: "approval.result", approval_id: r.id, state: done.state, approval: bundle[0], approvals: bundle });
        await track(d, "approval_decided", { decision: done.state, product: "openentity", kind: "org", risk: JSON.parse(r.payload).risk, seconds_to_decide: t - Number(r.created_at), number_match: false, form: String(bundle[0].form) }, { owner: org.owner_did, agent: r.agent_did });
      }
      row = (await d.db.first<ApprovalRow>("SELECT * FROM agent_approvals WHERE id = $1", [r.id]))!;
    }
    return c.json(await withVotes(row));
  });

  // ---------------------------------------------------------------- export: what each cost centre was allowed and decided
  // ponytail: allowances and approvals only. Actual spend lives in the products' receipts (ClawGRC groups it by the cost centre these rows carry).
  app.get("/v1/orgs/:id/export.csv", async (c) => {
    const { org } = await me(c, "viewer");
    const from = Number(c.req.query("from") ?? 0), to = Number(c.req.query("to") ?? now() + 1);
    if (!Number.isSafeInteger(from) || !Number.isSafeInteger(to) || from < 0 || to < from) fail(400, "bad_request", "from and to are unix seconds, from at most to");
    const tags = new Map((await orgAgents(org)).map((a) => [a.did, a]));
    const tagOf = async (did: string) => tags.get(did) ?? await d.db.first<AgentRow>("SELECT * FROM agents WHERE did = $1", [did]);
    const lines: unknown[][] = [["kind", "id", "at", "agent_did", "team", "cost_centre", "state", "period", "period_max_cents", "per_tx_max_cents", "approvals", "detail"]];
    for (const m of await d.db.all<MandateRow>("SELECT * FROM mandates WHERE owner_did = $1 AND issued_at >= $2 AND issued_at < $3 ORDER BY issued_at, id", [org.owner_did, from, to])) {
      const v = mandateView(m), a = await tagOf(m.agent_did), md = v.mandate as Mandate;
      lines.push(["mandate", m.id, m.issued_at, m.agent_did, a?.team, a?.cost_centre, v.status, md.limits.period, md.limits.period_max, md.limits.per_tx_max, "", md.scope.rails.join(" ")]);
    }
    for (const r of await d.db.all<ApprovalRow>("SELECT * FROM agent_approvals WHERE owner_did = $1 AND quorum IS NOT NULL AND created_at >= $2 AND created_at < $3 ORDER BY created_at, id", [org.owner_did, from, to])) {
      const a = await tagOf(r.agent_did), q = JSON.parse(r.quorum!), got = r.approvals ? JSON.parse(r.approvals).length : 0;
      lines.push(["approval", r.id, r.created_at, r.agent_did, a?.team, a?.cost_centre, r.state, "", "", "", `${got} of ${q.m}`, JSON.parse(r.payload).title]);
    }
    return c.body(`${lines.map((l) => l.map(cell).join(",")).join("\r\n")}\r\n`, 200, { "content-type": "text/csv; charset=utf-8", "content-disposition": `attachment; filename="${org.id.slice(0, 12)}-${from}.csv"` });
  });
}

/** deletion.ts: an account in an organisation is not deleted until it has left (or the org's last admin is someone else). */
export async function membershipsOf(d: Deps, accountId: string): Promise<number> {
  return Number((await d.db.first<{ n: number }>("SELECT count(*) AS n FROM org_members WHERE account_id = $1", [accountId]))!.n);
}
