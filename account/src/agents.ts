// Agents (core lane, PLAN 8.2, 8.3): the agent API (RFC 9421 by the agent's did:key, no CAPTCHA, login or payment),
// the owner's agent routes, approvals agents write, and pause, which products enforce: a signed event to each
// product now, and the signed GET /v1/paused feed they poll every 30 seconds.
import { createHash } from "node:crypto";
import type { Context, Hono } from "hono";
import { OpenEntityError, payloadDigest } from "@openentity/sdk";
import type { Deps } from "./app.ts";
import { bump, newId, now } from "./db.ts";
import { bearer, fail, json } from "./http.ts";
import { notifyOwner } from "./notify.ts";
import { callProduct, reaches, sendEvent } from "./outbound.ts";
import { agentSigned, productSigned } from "./rfc9421.ts";
import { checkApproval, permissionList, requireApproval } from "./stepup.ts";
import { ack, closeSocket, deliver, unacked } from "./ws.ts";

const MAX_TEXT = 4096, MESSAGES_PER_HOUR = 60, APPROVALS_PER_HOUR = 30, STATUS_PER_HOUR = 600, POLL_GAP = 15;
const PAUSE_LOCK = 7_231_001; // pg advisory lock: pause_changes rows commit in id order

export interface AgentRow {
  did: string; account_id: string; owner_did: string; label: string | null; framework: string | null; host: string | null;
  permissions: string; perm_seq: number; state: "active" | "paused" | "unlinked"; pause_seq: number; status: string | null;
  connection_id: string | null; paired_at: number; last_seen_at: number | null;
}

/** The Agent object (openapi.yaml) the owner sees. */
export async function agentView(d: Deps, a: AgentRow) {
  const products = await d.db.all<{ product: string }>("SELECT product FROM agent_products WHERE agent_did = $1 ORDER BY product", [a.did]);
  return {
    did: a.did, label: a.label, framework: a.framework, host: a.host, state: a.state === "paused" ? "paused" : "active",
    status: a.status ? JSON.parse(a.status) : null, permissions: JSON.parse(a.permissions) as string[], products: products.map((p) => p.product),
    paired_at: Number(a.paired_at), last_seen_at: a.last_seen_at === null ? null : Number(a.last_seen_at),
  };
}

const agentDidParam = (c: Context) => {
  const did = decodeURIComponent(c.req.param("agent_did") ?? "");
  return /^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]+$/.test(did) ? did : fail(404, "not_found", "no such agent");
};

/** One of the owner's linked agents, or 404. */
export async function ownersAgent(d: Deps, accountId: string, did: string): Promise<AgentRow> {
  return (await d.db.first<AgentRow>("SELECT * FROM agents WHERE did = $1 AND account_id = $2 AND state <> 'unlinked'", [did, accountId])) ?? fail(404, "not_found", "no such agent");
}

/** The paired agent behind a signed request: 401 for a bad signature, 403 not_paired otherwise. */
async function pairedAgent(c: Context, d: Deps): Promise<AgentRow> {
  const { did } = await agentSigned(c, d);
  const a = await d.db.first<AgentRow>("SELECT * FROM agents WHERE did = $1 AND state <> 'unlinked'", [did]) ?? fail(403, "not_paired", "this agent is not paired; pair it from the OpenEntity app");
  await d.db.run("UPDATE agents SET last_seen_at = $2 WHERE did = $1", [did, now()]);
  return a;
}
const allowed = (a: AgentRow, perm: string) => (JSON.parse(a.permissions) as string[]).includes(perm) || fail(403, "permission_denied", `the owner has not granted ${perm}`);
const notPaused = (a: AgentRow) => a.state !== "paused" || fail(423, "agent_paused", "the owner paused this agent");
async function limit(d: Deps, key: string, max: number, code = "rate_limited") {
  const hour = Math.floor(now() / 3600);
  const n = await bump(d.db, key, String(hour));
  if (n > max) fail(429, code, `at most ${max} an hour`, { retry_after: (hour + 1) * 3600 - now() });
  return n;
}
const utf8Text = (v: unknown, name: string) => {
  if (typeof v !== "string" || !v) fail(400, "bad_request", `${name} is required`);
  if (Buffer.byteLength(v as string) > MAX_TEXT) fail(413, "too_large", `${name} is over ${MAX_TEXT} bytes`);
  return v as string;
};

// ---------------------------------------------------------------- pause (PLAN 8.3)

/** Records one pause-state change in commit order; returns the new seq, or null when the agent was not in `from`. */
async function changePause(d: Deps, a: AgentRow, from: "active" | "paused", to: "paused" | "active", t: number): Promise<number | null> {
  return d.db.tx(async (tx) => {
    await tx.run("SELECT pg_advisory_xact_lock($1)", [PAUSE_LOCK]);
    const row = await tx.first<{ pause_seq: number }>("UPDATE agents SET state = $3, pause_seq = pause_seq + 1 WHERE did = $1 AND state = $2 RETURNING pause_seq", [a.did, from, to]);
    if (!row) return null;
    await tx.run("INSERT INTO pause_changes (agent_did, owner_did, state, seq, at) VALUES ($1, $2, $3, $4, $5)", [a.did, a.owner_did, to === "paused" ? "paused" : "active", row.pause_seq, t]);
    return Number(row.pause_seq);
  });
}

const productsOf = async (d: Deps, did: string) => (await d.db.all<{ product: string }>("SELECT product FROM agent_products WHERE agent_did = $1", [did])).map((p) => p.product);

/** Pause needs no biometrics: record it, close the socket with 4001, queue a pause command, tell every product now. Idempotent. */
export async function pause(d: Deps, a: AgentRow, source: string): Promise<boolean> {
  const t = now(), seq = await changePause(d, a, "active", "paused", t);
  if (seq === null) return false;
  await deliver(d, a.did, { type: "command", command: "pause", args: { source } });
  await closeSocket(d, a.did, a.connection_id, 4001, "agent_paused", "the owner paused this agent; reconnect to receive the resume command");
  const data = { agent_did: a.did, owner_did: a.owner_did, paused_at: t, seq };
  await Promise.all((await productsOf(d, a.did)).map((p) => sendEvent(d, p, "agent.paused", data)));
  return true;
}

async function resume(d: Deps, a: AgentRow): Promise<void> {
  const t = now(), seq = await changePause(d, a, "paused", "active", t) ?? fail(409, "not_paused", "this agent is not paused");
  await deliver(d, a.did, { type: "command", command: "resume", args: {} });
  const data = { agent_did: a.did, owner_did: a.owner_did, resumed_at: t, seq };
  await Promise.all((await productsOf(d, a.did)).map((p) => sendEvent(d, p, "agent.resumed", data)));
}

/** RFC 9421 response signature over "@status" and content-digest by the service key (GET /v1/paused). */
async function signedJson(c: Context, d: Deps, payload: unknown) {
  const body = JSON.stringify(payload), created = now();
  const digest = `sha-256=:${createHash("sha256").update(body).digest("base64")}:`;
  const params = `("@status" "content-digest");created=${created};expires=${created + 60};keyid="did:web:${d.host}#${d.keys.did.kid}";alg="ed25519"`;
  const base = new TextEncoder().encode(`"@status": 200\n"content-digest": ${digest}\n"@signature-params": ${params}`);
  const sig = Buffer.from(await d.keys.did.sign(base)).toString("base64");
  return c.body(body, 200, { "content-type": "application/json", "content-digest": digest, "signature-input": `sig1=${params}`, signature: `sig1=:${sig}:` });
}

// ---------------------------------------------------------------- approvals agents write

interface ApprovalRow { id: string; agent_did: string; account_id: string; owner_did: string; request_id: string; payload: string; payload_digest: string; state: string; approval: string | null; created_at: number; expires_at: number; decided_at: number | null }

/** AgentApproval (openapi.yaml); the owner view adds agent_did and, while pending, the approval request. */
function approvalView(d: Deps, r: ApprovalRow, owner: boolean) {
  const p = JSON.parse(r.payload), t = now();
  const state = r.state === "pending" && Number(r.expires_at) <= t ? "expired" : r.state;
  return {
    id: r.id, request_id: r.request_id, state, title: p.title, summary: p.summary, ...(p.details ? { details: p.details } : {}), risk: p.risk,
    created_at: Number(r.created_at), expires_at: Number(r.expires_at), decided_at: r.decided_at === null ? null : Number(r.decided_at),
    ...(r.approval ? { approval: JSON.parse(r.approval) } : {}),
    ...(owner ? { agent_did: r.agent_did } : {}),
    ...(owner && state === "pending" ? { approval_request: {
      verifier_did: `did:web:${d.host}`, owner_did: r.owner_did, request_id: r.request_id, action: "agent.approval", payload: p,
      payload_digest: r.payload_digest, expires_at: Number(r.expires_at), decisions: ["approve", "deny"],
    } } : {}),
  };
}

export function routes(app: Hono, d: Deps) {
  // ---------------------------------------------------------------- agent API
  app.get("/v1/agent", async (c) => {
    const a = await pairedAgent(c, d);
    return c.json({ did: a.did, owner_did: a.owner_did, state: a.state, permissions: JSON.parse(a.permissions), products: await productsOf(d, a.did) });
  });

  app.get("/v1/agent/messages", async (c) => {
    const a = await pairedAgent(c, d), t = now();
    // Never held open; at most once every 15 seconds.
    const ok = await d.db.first("UPDATE agents SET inbox_polled_at = $2 WHERE did = $1 AND (inbox_polled_at IS NULL OR inbox_polled_at <= $3) RETURNING did", [a.did, t, t - POLL_GAP]);
    if (!ok) fail(429, "rate_limited", "poll at most every 15 seconds, or hold the WebSocket", { retry_after: POLL_GAP });
    return c.json(await unacked(d, a.did));
  });

  app.post("/v1/agent/messages", async (c) => {
    const a = await pairedAgent(c, d);
    notPaused(a);
    allowed(a, "owner.message");
    const b = await json(c);
    const text = utf8Text(b.text, "text");
    if (Array.isArray(b.attachments) && b.attachments.length) fail(400, "upload_unknown", "attachments are not available yet");
    await limit(d, `msg:${a.did}`, MESSAGES_PER_HOUR);
    const id = newId("msg");
    await d.db.run("INSERT INTO messages (id, agent_did, sender, text, created_at) VALUES ($1, $2, 'agent', $3, $4)", [id, a.did, text, now()]);
    await notifyOwner(d, a.account_id, { type: "message", id, agent: a.did });
    return c.json({ id }, 201);
  });

  app.post("/v1/agent/messages/ack", async (c) => {
    const a = await pairedAgent(c, d);
    await ack(d, a.did, (await json(c)).ids);
    return c.body(null, 204);
  });

  app.post("/v1/agent/status", async (c) => {
    const a = await pairedAgent(c, d);
    allowed(a, "owner.status");
    const b = await json(c);
    if (!["running", "idle", "blocked", "error", "done"].includes(b.state)) fail(400, "bad_request", "state must be running, idle, blocked, error or done");
    if (typeof b.summary !== "string" || b.summary.length > 200) fail(400, "bad_request", "summary is at most 200 characters");
    if (b.progress !== undefined && (typeof b.progress !== "number" || !(b.progress >= 0 && b.progress <= 1))) fail(400, "bad_request", "progress is a number from 0 to 1");
    await limit(d, `status:${a.did}`, STATUS_PER_HOUR);
    const status = { state: b.state, summary: b.summary, progress: b.progress ?? null, at: now() };
    await d.db.run("UPDATE agents SET status = $2 WHERE did = $1", [a.did, JSON.stringify(status)]);
    await notifyOwner(d, a.account_id, { type: "agent.status", id: a.did, agent: a.did });
    return c.body(null, 204);
  });

  app.post("/v1/agent/approvals", async (c) => {
    const a = await pairedAgent(c, d);
    notPaused(a);
    allowed(a, "owner.approval");
    const b = await json(c);
    const str = (v: unknown, max: number, name: string) => (typeof v === "string" && v.length >= 1 && v.length <= max ? v : fail(400, "bad_request", `${name} is 1 to ${max} characters`));
    const payload = {
      action: "agent.approval", agent_did: a.did, title: str(b.title, 120, "title"), summary: str(b.summary, 2000, "summary"),
      risk: ["low", "medium", "high"].includes(b.risk) ? b.risk : fail(400, "bad_request", "risk is low, medium or high"),
      ...(b.details === undefined ? {} : { details: b.details && typeof b.details === "object" && !Array.isArray(b.details) ? b.details : fail(400, "bad_request", "details is an object") }),
    };
    const ttl = Number.isInteger(b.expires_in) && b.expires_in >= 60 && b.expires_in <= 600 ? b.expires_in : fail(400, "bad_request", "expires_in is 60 to 600 seconds");
    let digest = "";
    try { digest = payloadDigest(payload); } catch (e) { if (e instanceof OpenEntityError) fail(400, "bad_request", `details: ${e.message}`); throw e; }
    const n = await bump(d.db, `appr:${a.did}`, String(Math.floor(now() / 3600)));
    if (n > APPROVALS_PER_HOUR) {
      // Muted for the rest of the hour; the owner hears about it once.
      if (n === APPROVALS_PER_HOUR + 1) await notifyOwner(d, a.account_id, { type: "agent.muted", id: a.did, agent: a.did });
      fail(429, "muted", `more than ${APPROVALS_PER_HOUR} approval requests this hour; this agent is muted until the hour ends`, { retry_after: (Math.floor(now() / 3600) + 1) * 3600 - now() });
    }
    const t = now(), row: ApprovalRow = {
      id: newId("apr"), agent_did: a.did, account_id: a.account_id, owner_did: a.owner_did, request_id: newId("aar"), payload: JSON.stringify(payload),
      payload_digest: digest, state: "pending", approval: null, created_at: t, expires_at: t + ttl, decided_at: null,
    };
    await d.db.run("INSERT INTO agent_approvals (id, agent_did, account_id, owner_did, request_id, payload, payload_digest, state, created_at, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending', $8, $9)",
      [row.id, row.agent_did, row.account_id, row.owner_did, row.request_id, row.payload, row.payload_digest, row.created_at, row.expires_at]);
    await notifyOwner(d, a.account_id, { type: "approval.requested", id: row.id, agent: a.did });
    return c.json(approvalView(d, row, false), 201);
  });

  app.get("/v1/agent/approvals/:id", async (c) => {
    const a = await pairedAgent(c, d);
    const r = await d.db.first<ApprovalRow>("SELECT * FROM agent_approvals WHERE id = $1 AND agent_did = $2", [c.req.param("id"), a.did]) ?? fail(404, "not_found", "no such approval");
    return c.json(approvalView(d, r, false));
  });

  app.post("/v1/agent/credentials/renew", async (c) => {
    const a = await pairedAgent(c, d);
    notPaused(a);
    const b = (await c.req.text()) ? await json(c) : {};
    const held = await productsOf(d, a.did);
    const want: string[] = Array.isArray(b.products) ? b.products : held;
    if (want.some((p) => !held.includes(p))) fail(400, "bad_request", "products must be ones this agent holds keys for");
    return c.json({ credentials: await productKeys(d, a, want, newId("rn")) });
  });

  // ---------------------------------------------------------------- owner: agents
  app.get("/v1/agents", async (c) => {
    const o = await bearer(c, d);
    const rows = await d.db.all<AgentRow>("SELECT * FROM agents WHERE account_id = $1 AND state <> 'unlinked' ORDER BY paired_at", [o.accountId]);
    return c.json({ agents: await Promise.all(rows.map((r) => agentView(d, r))) });
  });

  app.post("/v1/agents/pause-all", async (c) => {
    const o = await bearer(c, d);
    const source = pauseSource(await json(c));
    const rows = await d.db.all<AgentRow>("SELECT * FROM agents WHERE account_id = $1 AND state = 'active'", [o.accountId]);
    const done = await Promise.all(rows.map((r) => pause(d, r, source)));
    return c.json({ paused: done.filter(Boolean).length });
  });

  app.get("/v1/agents/:agent_did", async (c) => {
    const o = await bearer(c, d);
    return c.json(await agentView(d, await ownersAgent(d, o.accountId, agentDidParam(c))));
  });

  app.patch("/v1/agents/:agent_did", async (c) => {
    const o = await bearer(c, d);
    const a = await ownersAgent(d, o.accountId, agentDidParam(c));
    const b = await json(c);
    if (b.label === undefined && b.permissions === undefined) fail(400, "bad_request", "send label or permissions");
    if (b.label !== undefined && (typeof b.label !== "string" || b.label.length > 80)) fail(400, "bad_request", "label is at most 80 characters");
    if (b.permissions !== undefined) {
      const next = permissionList(b.permissions), held: string[] = JSON.parse(a.permissions);
      // Narrowing takes effect at once; widening is a step-up.
      if (next.some((p) => !held.includes(p))) await requireApproval(c, d, { accountId: o.accountId, ownerDid: o.ownerDid, action: "agent.permissions.widen", params: { agent_did: a.did, permissions: next } });
      if (JSON.stringify(next) !== JSON.stringify(held)) await setPermissions(d, a, next);
    }
    if (b.label !== undefined) await d.db.run("UPDATE agents SET label = $2 WHERE did = $1", [a.did, b.label]);
    return c.json(await agentView(d, await ownersAgent(d, o.accountId, a.did)));
  });

  app.delete("/v1/agents/:agent_did", async (c) => {
    const o = await bearer(c, d);
    const a = await ownersAgent(d, o.accountId, agentDidParam(c));
    await d.db.run("UPDATE agents SET state = 'unlinked', unlinked_at = $2 WHERE did = $1", [a.did, now()]);
    await closeSocket(d, a.did, a.connection_id, 4003, "unlinked", "the owner unlinked this agent");
    const data = { agent_did: a.did, owner_did: a.owner_did };
    await Promise.all((await productsOf(d, a.did)).map((p) => sendEvent(d, p, "agent.unlinked", data)));
    return c.body(null, 204);
  });

  app.post("/v1/agents/:agent_did/pause", async (c) => {
    const o = await bearer(c, d);
    const a = await ownersAgent(d, o.accountId, agentDidParam(c));
    await pause(d, a, pauseSource(await json(c)));
    return c.json(await agentView(d, await ownersAgent(d, o.accountId, a.did)));
  });

  app.post("/v1/agents/:agent_did/resume", async (c) => {
    const o = await bearer(c, d);
    const a = await ownersAgent(d, o.accountId, agentDidParam(c));
    if (a.state !== "paused") fail(409, "not_paused", "this agent is not paused");
    await requireApproval(c, d, { accountId: o.accountId, ownerDid: o.ownerDid, action: "agent.resume", params: { agent_did: a.did } });
    await resume(d, a);
    return c.json(await agentView(d, await ownersAgent(d, o.accountId, a.did)));
  });

  app.post("/v1/agents/:agent_did/commands", async (c) => {
    const o = await bearer(c, d);
    const a = await ownersAgent(d, o.accountId, agentDidParam(c));
    const b = await json(c);
    if (b.command !== "checkup" && b.command !== "fix") fail(400, "bad_request", "command is checkup or fix");
    if (b.args !== undefined && (!b.args || typeof b.args !== "object" || Array.isArray(b.args))) fail(400, "bad_request", "args is an object");
    const f = await deliver(d, a.did, { type: "command", command: b.command, args: b.args ?? {} });
    return c.json({ id: f.id }, 202);
  });

  app.get("/v1/agents/:agent_did/messages", async (c) => {
    const o = await bearer(c, d);
    const a = await ownersAgent(d, o.accountId, agentDidParam(c));
    const limitN = Math.min(Math.max(Number(c.req.query("limit") ?? 50) || 50, 1), 100);
    const before = c.req.query("before");
    const at = before ? await d.db.first<{ seq: number }>("SELECT seq FROM messages WHERE id = $1 AND agent_did = $2", [before, a.did]) : null;
    if (before && !at) fail(404, "not_found", "no such message");
    const rows = at
      ? await d.db.all<any>("SELECT * FROM messages WHERE agent_did = $1 AND seq < $2 ORDER BY seq DESC LIMIT $3", [a.did, at.seq, limitN])
      : await d.db.all<any>("SELECT * FROM messages WHERE agent_did = $1 ORDER BY seq DESC LIMIT $2", [a.did, limitN]);
    return c.json({ messages: rows.map((m) => ({ id: m.id, from: m.sender, text: m.text, attachments: [], created_at: Number(m.created_at), ...(m.sender === "owner" ? { acked_at: m.acked_at === null ? null : Number(m.acked_at) } : {}) })) });
  });

  app.post("/v1/agents/:agent_did/messages", async (c) => {
    const o = await bearer(c, d);
    const a = await ownersAgent(d, o.accountId, agentDidParam(c));
    const text = utf8Text((await json(c)).text, "text");
    const id = newId("msg"), t = now();
    await d.db.run("INSERT INTO messages (id, agent_did, sender, text, created_at) VALUES ($1, $2, 'owner', $3, $4)", [id, a.did, text, t]);
    await deliver(d, a.did, { type: "message", text, attachments: [] }, id);
    return c.json({ id, from: "owner", text, attachments: [], created_at: t, acked_at: null }, 201);
  });

  // ---------------------------------------------------------------- owner: approvals agents wrote
  app.get("/v1/approvals", async (c) => {
    const o = await bearer(c, d);
    const decided = c.req.query("state") === "decided";
    const rows = await d.db.all<ApprovalRow>(decided
      ? "SELECT * FROM agent_approvals WHERE account_id = $1 AND (state <> 'pending' OR expires_at <= $2) ORDER BY created_at DESC LIMIT 100"
      : "SELECT * FROM agent_approvals WHERE account_id = $1 AND state = 'pending' AND expires_at > $2 ORDER BY created_at DESC LIMIT 100", [o.accountId, now()]);
    return c.json({ approvals: rows.map((r) => approvalView(d, r, true)) });
  });

  app.get("/v1/approvals/:id", async (c) => {
    const o = await bearer(c, d);
    const r = await d.db.first<ApprovalRow>("SELECT * FROM agent_approvals WHERE id = $1 AND account_id = $2", [c.req.param("id"), o.accountId]) ?? fail(404, "not_found", "no such approval");
    return c.json(approvalView(d, r, true));
  });

  app.post("/v1/approvals/:id/decision", async (c) => {
    const o = await bearer(c, d);
    const r = await d.db.first<ApprovalRow>("SELECT * FROM agent_approvals WHERE id = $1 AND account_id = $2", [c.req.param("id"), o.accountId]) ?? fail(404, "not_found", "no such approval");
    if (r.state !== "pending") fail(409, "already_decided", "this approval was already decided");
    if (Number(r.expires_at) <= now()) fail(410, "expired", "this approval request expired");
    const { decision, approval } = await checkApproval(c, d, { ownerDid: r.owner_did, requestId: r.request_id, payloadDigest: r.payload_digest });
    const state = decision === "approve" ? "approved" : "denied", t = now();
    const won = await d.db.run("UPDATE agent_approvals SET state = $2, approval = $3, decided_at = $4 WHERE id = $1 AND state = 'pending'", [r.id, state, JSON.stringify(approval), t]);
    if (!won.changes) fail(409, "already_decided", "this approval was already decided");
    await deliver(d, r.agent_did, { type: "approval.result", approval_id: r.id, state, approval });
    return c.json(approvalView(d, { ...r, state, approval: JSON.stringify(approval), decided_at: t }, true));
  });

  // ---------------------------------------------------------------- products: the pause feed
  app.get("/v1/paused", async (c) => {
    const { did: product } = await productSigned(c, d);
    const since = c.req.query("since");
    if (since !== undefined && !/^\d{1,18}$/.test(since)) fail(400, "cursor_invalid", "since is the cursor of an earlier answer");
    const top = Number((await d.db.first<{ id: number | null }>("SELECT max(id) AS id FROM pause_changes"))?.id ?? 0);
    let changes, cursor = String(top);
    if (since === undefined) {
      const rows = await d.db.all<any>(
        "SELECT a.did, a.owner_did, a.pause_seq, (SELECT max(at) FROM pause_changes pc WHERE pc.agent_did = a.did) AS at FROM agents a JOIN agent_products ap ON ap.agent_did = a.did AND ap.product = $1 WHERE a.state = 'paused' ORDER BY a.did",
        [product]);
      changes = rows.map((r) => ({ agent_did: r.did, owner_did: r.owner_did, state: "paused", at: Number(r.at), seq: Number(r.pause_seq) }));
    } else {
      const rows = await d.db.all<any>(
        "SELECT pc.* FROM pause_changes pc JOIN agent_products ap ON ap.agent_did = pc.agent_did AND ap.product = $1 WHERE pc.id > $2 AND pc.id <= $3 ORDER BY pc.id LIMIT 500",
        [product, Number(since), top]);
      if (rows.length === 500) cursor = String(rows.at(-1).id);
      changes = rows.map((r) => ({ agent_did: r.agent_did, owner_did: r.owner_did, state: r.state, at: Number(r.at), seq: Number(r.seq) }));
    }
    return signedJson(c, d, { since: since ?? null, cursor, generated_at: now(), changes });
  });
}

const pauseSource = (b: Record<string, any>) =>
  ["app", "control", "siri", "tile", "widget", "web"].includes(b.source) ? (b.source as string) : fail(400, "bad_request", "source is app, control, siri, tile, widget or web");

/** Replaces the agent's permissions: agent.permissions to every product, a permissions frame to the agent. */
export async function setPermissions(d: Deps, a: AgentRow, next: string[]) {
  const row = await d.db.first<{ perm_seq: number }>("UPDATE agents SET permissions = $2, perm_seq = perm_seq + 1 WHERE did = $1 RETURNING perm_seq", [a.did, JSON.stringify(next)]);
  const data = { agent_did: a.did, owner_did: a.owner_did, permissions: next, seq: Number(row!.perm_seq) };
  await Promise.all((await productsOf(d, a.did)).map((p) => sendEvent(d, p, "agent.permissions", data)));
  await deliver(d, a.did, { type: "permissions", permissions: next });
}

/**
 * Asks each product for a fresh 30-day bearer key for the agent (POST /v1/oe/credentials/renew, PLAN 8.4) and passes
 * them through; nothing is stored. A product that cannot issue one now is left out of the list.
 */
export async function productKeys(d: Deps, a: Pick<AgentRow, "did" | "owner_did" | "permissions">, products: string[], requestId: string) {
  const answers = await Promise.all(products.filter((p) => reaches(d, p)).map(async (product) => {
    const r = await callProduct(d, product, "/v1/oe/credentials/renew", { request_id: requestId, agent_did: a.did, owner_did: a.owner_did, kind: "bearer", permissions: JSON.parse(a.permissions) });
    const k = r.body;
    if (r.status !== 200 || typeof k?.key !== "string" || !Number.isSafeInteger(k.expires_at)) {
      console.warn(`${product} issued no key for ${a.did}: ${r.status} ${JSON.stringify(k)?.slice(0, 120)}`);
      return null;
    }
    return { product, kind: "bearer", key: k.key, expires_at: k.expires_at };
  }));
  return answers.filter((x) => x !== null);
}
