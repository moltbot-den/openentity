// Mandates (commerce profile section 2 and 7): the owner's signed, bounded spend permission for one agent. The owner's
// device signs a mandate/1 (an approver key in the key log, never the agent); this service checks it with the SDK,
// stores it, answers the public status URL merchants poll, and tells the agent's products with agent.mandates.
// A spend permission (`spend<=$N/<period>@<merchant>:<rail>`, stepup.ts) is the ceiling: the agent must hold it, and
// widening permissions already needs approval/2.0, so a mandate never exceeds what the owner approved.
import { randomBytes } from "node:crypto";
import type { Context, Hono } from "hono";
import { type Mandate, mandateDigest, verifyMandate } from "@openentity/sdk";
import { type AgentRow, ownersAgent } from "./agents.ts";
import type { Deps } from "./app.ts";
import { now } from "./db.ts";
import { bearer, fail, json } from "./http.ts";
import { productSigned } from "./rfc9421.ts";
import { base32, keyLogState } from "./keylog.ts";
import { sendEvent } from "./outbound.ts";

const DAY = 86_400, FRESH = 600, MAX_ACTIVE = 20, DEFAULT_DAYS = 30;
export const SPEND = /^spend<=\$([0-9]+)(?:\.([0-9]{1,2}))?\/(P1D|P7D|P1M)@(\S+):(card|x402|mpp|credits|usdc)$/;
const ID = /^md_[a-z2-7]{26}$/;
const PERIOD_DAYS: Record<string, number> = { P1D: 1, P7D: 7, P1M: 30 };

interface Spend { cents: number; period: string; pattern: string; rail: string }
/** The parsed spend permissions in a permission list; amounts are integer cents (no floats). */
export function spendPermissions(perms: string[]): Spend[] {
  return perms.flatMap((p) => {
    const m = SPEND.exec(p);
    return m ? [{ cents: Number(m[1]) * 100 + Number((m[2] ?? "").padEnd(2, "0")), period: m[3], pattern: m[4], rail: m[5] }] : [];
  });
}

/** Whether the held permissions cover every merchant x rail of this mandate: same period, the same pattern (or `*`), cap at or above period_max. */
export function covered(perms: string[], m: Pick<Mandate, "limits" | "scope">): boolean {
  if (m.limits.currency !== "USD") return false;
  const held = spendPermissions(perms), merchants = m.scope.merchants.length ? m.scope.merchants : ["*"];
  return merchants.every((p) => m.scope.rails.every((r) => held.some((h) => (h.pattern === p || h.pattern === "*") && h.rail === r && h.period === m.limits.period && h.cents >= m.limits.period_max && h.cents >= m.limits.per_tx_max)));
}

export const statusUrl = (d: Deps, id: string) => `https://${d.host}/v1/mandates/${id}/status`;
const seqOf = async (d: Deps, agent: string) => Number((await d.db.first<{ seq: number }>(
  "INSERT INTO mandate_seqs (agent_did, seq) VALUES ($1, 1) ON CONFLICT (agent_did) DO UPDATE SET seq = mandate_seqs.seq + 1 RETURNING seq", [agent]))!.seq);

/** agent.mandates to every product of the agent: the full list of its active mandates (replace, newest `seq` wins). */
export async function push(d: Deps, agentDid: string, ownerDid: string) {
  // seq first, list after: of two concurrent pushes the higher seq read the list last, so it is never the stale one.
  const seq = await seqOf(d, agentDid);
  const rows = await d.db.all<{ body: string }>("SELECT body FROM mandates WHERE agent_did = $1 AND revoked_at IS NULL AND expires_at > $2 ORDER BY id", [agentDid, now()]);
  const tags = await d.db.first<{ team: string | null; cost_centre: string | null }>("SELECT team, cost_centre FROM agents WHERE did = $1", [agentDid]);
  // Organisation agents carry their team and cost centre to the products, which put them on receipts and evidence.
  const data = { agent_did: agentDid, owner_did: ownerDid, mandates: rows.map((r) => JSON.parse(r.body)), seq, ...(tags?.team || tags?.cost_centre ? { team: tags.team, cost_centre: tags.cost_centre } : {}) };
  const products = await d.db.all<{ product: string }>("SELECT product FROM agent_products WHERE agent_did = $1", [agentDid]);
  await Promise.all(products.map((p) => sendEvent(d, p.product, "agent.mandates", data)));
}

/**
 * Revokes the agent's active mandates (all, or those its permissions no longer cover) and pushes the new list. Revoked
 * is final: a mandate never comes back, the owner signs a new one. Called by pause, unlink and permission changes.
 */
export async function revokeFor(d: Deps, a: Pick<AgentRow, "did" | "owner_did">, reason: string, keep?: (m: Mandate) => boolean): Promise<number> {
  const rows = await d.db.all<{ id: string; body: string }>("SELECT id, body FROM mandates WHERE agent_did = $1 AND revoked_at IS NULL", [a.did]);
  const ids = rows.filter((r) => !keep?.(JSON.parse(r.body))).map((r) => r.id);
  if (!ids.length) return 0;
  await d.db.run("UPDATE mandates SET revoked_at = $2, revoke_reason = $3 WHERE id = ANY($1::text[]) AND revoked_at IS NULL", [ids, now(), reason]);
  await push(d, a.did, a.owner_did);
  return ids.length;
}

export interface Row { id: string; account_id: string; owner_did: string; agent_did: string; body: string; issued_at: number; expires_at: number; revoked_at: number | null; revoke_reason: string | null }
export const view = (r: Row) => ({ mandate: JSON.parse(r.body), status: r.revoked_at !== null ? "revoked" : Number(r.expires_at) <= now() ? "expired" : "active", revoked_at: r.revoked_at === null ? null : Number(r.revoked_at), revoke_reason: r.revoke_reason });

export interface IssueOptions {
  accountId: string; ownerDid: string; agent: AgentRow; mandate: Mandate;
  /** "permissions": the agent must hold a spend permission covering the mandate (a person's agent). "none": the caller already bounded it (an org's budgets). */
  ceiling: "permissions" | "none";
  /** Extra refusal, thrown by the caller (org: budgets, quorum device). */
  check?: (m: Mandate) => void | Promise<void>;
}

/** Verifies a signed mandate against the issuer's key log, stores it and pushes agent.mandates. Returns the stored view. */
export async function issueMandate(d: Deps, o: IssueOptions) {
  const { agent: a, mandate: m, ownerDid } = o;
  const keyLog = await keyLogState(d, ownerDid) ?? fail(403, "key_log_required", "this account has no key log");
  if (a.state === "paused") fail(423, "agent_paused", "the owner paused this agent");
  const r = verifyMandate(m, { keyLog: keyLog!, agentDid: a.did, status: { status: "active" }, origins: d.rp.origins, rpId: d.rp.id });
  if (!r.ok) fail(r.error === "malformed" || r.error === "bad_version" ? 400 : 403, "mandate_invalid", `${r.error}: ${r.message}`);
  const t = now();
  if (t - m.issued_at > FRESH) fail(403, "mandate_invalid", "stale: issued_at is more than 10 minutes old; ask for a new draft");
  if (m.status !== statusUrl(d, m.mandate_id)) fail(400, "mandate_invalid", `status must be ${statusUrl(d, m.mandate_id)}`);
  if (o.ceiling === "permissions" && !covered(JSON.parse(a.permissions), m)) fail(403, "spend_not_granted", "the agent does not hold a spend permission that covers this mandate; widen its permissions first");
  await o.check?.(m);
  if ((await d.db.first<{ n: number }>("SELECT count(*)::int AS n FROM mandates WHERE agent_did = $1 AND revoked_at IS NULL AND expires_at > $2", [a.did, t]))!.n >= MAX_ACTIVE) fail(409, "too_many_mandates", `at most ${MAX_ACTIVE} active mandates per agent`);
  const ins = await d.db.run("INSERT INTO mandates (id, account_id, owner_did, agent_did, body, issued_at, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT DO NOTHING",
    [m.mandate_id, o.accountId, ownerDid, a.did, JSON.stringify(m), m.issued_at, m.expires_at]);
  if (!ins.changes) fail(409, "mandate_exists", "this mandate id was already issued");
  // Re-read after the insert: pause, unlink and narrowing change the agent first and revokeFor after, so a mandate that
  // slipped in between those two steps is seen here and ended (an insert before the change is caught by revokeFor).
  const now2 = await d.db.first<AgentRow & { org_state: string | null }>("SELECT a.*, g.state AS org_state FROM agents a LEFT JOIN orgs g ON g.id = a.org_id WHERE a.did = $1", [a.did]);
  if (now2?.state !== "active" || now2.org_state === "paused" || (o.ceiling === "permissions" && !covered(JSON.parse(now2.permissions), m))) {
    await d.db.run("UPDATE mandates SET revoked_at = $2, revoke_reason = 'agent_changed' WHERE id = $1 AND revoked_at IS NULL", [m.mandate_id, now()]);
    fail(423, "agent_changed", "the agent was paused, unlinked or narrowed while this mandate was issued; sign a new one");
  }
  await push(d, a.did, ownerDid);
  return view((await d.db.first<Row>("SELECT * FROM mandates WHERE id = $1", [m.mandate_id]))!);
}

export function routes(app: Hono, d: Deps) {
  // A person's own mandates: the ones issued under their DID (an org's are the org's, whoever signed them in).
  const owned = async (c: Context, o: { accountId: string; ownerDid: string | null }) => await d.db.first<Row>("SELECT * FROM mandates WHERE id = $1 AND account_id = $2 AND owner_did = $3", [c.req.param("id"), o.accountId, o.ownerDid ?? ""]) ?? fail(404, "not_found", "no such mandate");

  // The unsigned mandate/1 for a spend permission the agent holds, ready for the owner's device to sign (mandateDigest).
  app.post("/v1/mandates/draft", async (c) => {
    const o = await bearer(c, d), b = await json(c);
    const ownerDid = o.ownerDid ?? fail(403, "key_log_required", "mandates need a key log; finish \"Turn on Face ID approvals\" first");
    const a = await ownersAgent(d, o.accountId, String(b.agent_did ?? ""));
    const perm = String(b.permission ?? ""), p = SPEND.test(perm) && (JSON.parse(a.permissions) as string[]).includes(perm) ? spendPermissions([perm])[0] : fail(400, "invalid_permission", "permission must be a spend permission this agent holds");
    const days = b.expires_in_days === undefined ? DEFAULT_DAYS : Number(b.expires_in_days);
    if (!Number.isInteger(days) || days < 1 || days > 90) fail(400, "bad_request", "expires_in_days is 1 to 90");
    const t = now(), id = `md_${base32(randomBytes(17)).slice(0, 26)}`;
    const mandate = {
      version: "mandate/1", mandate_id: id, issuer_did: ownerDid, agent_did: a.did, issued_at: t, expires_at: t + days * DAY,
      limits: { currency: "USD", per_tx_max: p.cents, period: p.period, period_max: p.cents, total_max: p.cents * Math.ceil(days / PERIOD_DAYS[p.period]) },
      scope: { merchants: p.pattern === "*" ? [] : [p.pattern], rails: [p.rail] },
      step_up_over: Math.floor(p.cents / 2), status: statusUrl(d, id),
    };
    return c.json({ mandate, digest: Buffer.from(mandateDigest(mandate)).toString("hex") });
  });

  app.post("/v1/mandates", async (c) => {
    const o = await bearer(c, d), m = await json(c) as unknown as Mandate;
    const ownerDid = o.ownerDid ?? fail(403, "key_log_required", "mandates need a key log; finish \"Turn on Face ID approvals\" first");
    const a = await ownersAgent(d, o.accountId, String(m.agent_did));
    return c.json(await issueMandate(d, { accountId: o.accountId, ownerDid, agent: a, mandate: m, ceiling: "permissions" }), 201);
  });

  app.get("/v1/mandates", async (c) => {
    const o = await bearer(c, d), agent = c.req.query("agent");
    const rows = await d.db.all<Row>("SELECT * FROM mandates WHERE account_id = $1 AND owner_did = $3 AND ($2::text IS NULL OR agent_did = $2) ORDER BY issued_at DESC, id LIMIT 200", [o.accountId, agent ?? null, o.ownerDid ?? ""]);
    return c.json({ mandates: rows.map(view) });
  });

  app.delete("/v1/mandates/:id", async (c) => {
    const o = await bearer(c, d), r = await owned(c, o);
    if (r.revoked_at === null) {
      await d.db.run("UPDATE mandates SET revoked_at = $2, revoke_reason = 'owner' WHERE id = $1 AND revoked_at IS NULL", [r.id, now()]);
      await push(d, r.agent_did, r.owner_did);
    }
    return c.body(null, 204);
  });

  // Public: merchants and products poll this (profile section 2.2). Spend is what the enforcing products reported (PUT .../spend).
  const status = async (id: string) => {
    const r = ID.test(id) ? await d.db.first<Row & { state: string }>("SELECT m.*, a.state FROM mandates m JOIN agents a ON a.did = m.agent_did WHERE m.id = $1", [id]) : null;
    if (!r) fail(404, "not_found", "no such mandate");
    const limits = (JSON.parse(r!.body) as Mandate).limits;
    // A period figure counts only while its report is inside the current period (rolling window of the period's length); older reports read as 0.
    const since = now() - PERIOD_DAYS[limits.period] * 86400;
    const s = (await d.db.first<{ p: string; t: string }>("SELECT COALESCE(SUM(CASE WHEN reported_at > $2 THEN period_spent ELSE 0 END), 0) AS p, COALESCE(SUM(total_spent), 0) AS t FROM mandate_spend WHERE mandate_id = $1", [id, since]))!;
    const period_spent = Number(s.p), total_spent = Number(s.t);
    const state = r!.revoked_at !== null || r!.state !== "active" ? "revoked" : total_spent >= limits.total_max ? "exhausted" : "active";
    return { r: r!, body: { mandate_id: id, status: state, period_spent, total_spent } };
  };
  app.get("/v1/mandates/:id/status", async (c) => {
    c.header("cache-control", "public, max-age=30");
    return c.json((await status(c.req.param("id"))).body);
  });

  // The product that enforces a mandate reports the agent's spend under it. total_spent only grows (a lower report cannot reopen
  // a spent mandate); period_spent is the latest figure for the current period. A product reports for agents it is linked to.
  app.put("/v1/mandates/:id/spend", async (c) => {
    const { did: product } = await productSigned(c, d);
    const b = await json(c), id = c.req.param("id");
    for (const k of ["period_spent", "total_spent"]) if (!Number.isSafeInteger(b[k]) || b[k] < 0) fail(400, "bad_request", `${k} must be an unsigned integer in minor units`);
    const { r } = await status(id);
    if (!(await d.db.first("SELECT 1 FROM agent_products WHERE agent_did = $1 AND product = $2", [r.agent_did, product]))) fail(403, "not_linked", "this product is not linked to the mandate's agent");
    await d.db.run(
      "INSERT INTO mandate_spend (mandate_id, product, period_spent, total_spent, reported_at) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (mandate_id, product) DO UPDATE SET period_spent = EXCLUDED.period_spent, total_spent = GREATEST(mandate_spend.total_spent, EXCLUDED.total_spent), reported_at = EXCLUDED.reported_at",
      [id, product, b.period_spent, b.total_spent, now()]);
    return c.json((await status(id)).body);
  });
}
