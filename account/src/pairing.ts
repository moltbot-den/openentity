// Pairing (core lane, PLAN 8.1): the owner shows a single-use code, the agent claims it with an RFC 9421 signature and
// a Presentation over the code, both sides show the same match string (pair-sas/1), and the owner confirms with an
// approval/2.0 over the link. Then every product hears agent.paired, and the agent's first read of the confirmed
// pairing carries its product keys, fetched from the products then and never stored here.
import { createHash, randomInt } from "node:crypto";
import type { Hono } from "hono";
import { normalizeEid, pairSas, payloadDigest, trust, verifyPresentation } from "@openentity/sdk";
import { type AgentRow, agentView, productKeys } from "./agents.ts";
import type { Deps } from "./app.ts";
import { bump, newId, now } from "./db.ts";
import { bearer, fail, ipOf, json } from "./http.ts";
import { track } from "./events.ts";
import { sendEvent } from "./outbound.ts";
import { agentSigned } from "./rfc9421.ts";
import { checkApproval, permissionList } from "./stepup.ts";
import { PRODUCT_DIDS } from "./wellknown.ts";

export const CODE_TTL = 600, CONFIRM_TTL = 600, CODES_PER_DAY = 10, AGENT_LIMIT = 50, POLL_GAP = 2;
const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"; // base32 without I, L, O and U
const CODE = /^OE-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$/;

interface PairingRow {
  id: string; account_id: string; code: string; state: string; created_at: number; expires_at: number;
  agent_did: string | null; agent: string | null; request_id: string | null; claimed_at: number | null; confirmed_at: number | null; credentials_at: number | null;
}

const newCode = () => {
  const c = Array.from({ length: 8 }, () => CROCKFORD[randomInt(32)]).join("");
  return `OE-${c.slice(0, 4)}-${c.slice(4)}`;
};

/** pair-sas/1: the four items both sides show (test-vectors/pair-sas-1). */
export function sas(code: string, agentDid: string) {
  const h = createHash("sha256").update(`oe-pair-sas/1|${code.trim().toUpperCase()}|${agentDid}`).digest();
  return { version: "pair-sas/1", indexes: [...h.subarray(0, 4)], names: pairSas(code, agentDid) };
}

/**
 * The newest live Secure My Agent posture attestation about the agent, read from the registry and verified locally by
 * the SDK's trust() (ADR 0002). Null when there is none, or the registry or a key does not answer within 2 seconds.
 * checked_at is when this service read it.
 */
async function safetyOf(d: Deps, did: string): Promise<{ verdict: string; checked_at: number } | null> {
  const fetchJson = async (url: string) => {
    const r = await (d.fetch ?? fetch)(url, { signal: AbortSignal.timeout(2000), headers: { accept: "application/json" } });
    if (!r.ok) throw new Error(`${url} answered ${r.status}`);
    return r.json();
  };
  const report = await Promise.race([trust(did, { fetchJson }), new Promise<null>((ok) => setTimeout(() => ok(null), 2500).unref())]).catch(() => null);
  const band = report?.ok ? report.securityPosture?.score_band : undefined;
  return typeof band === "string" && band ? { verdict: band.slice(0, 32), checked_at: now() } : null;
}

/** Waiting and claimed pairings past their time read as expired. */
const stateOf = (p: PairingRow) => (["waiting", "claimed"].includes(p.state) && Number(p.expires_at) <= now() ? "expired" : p.state);

/** What the owner signs to confirm: the pairing's agent and match string. */
/** What the owner signs to confirm: the agent, the match string and the permissions it gets (sorted, unique; gate lead). */
const confirmPayload = (p: PairingRow, permissions: string[]) => {
  const agent = JSON.parse(p.agent!);
  return { action: "pairing.confirm", pairing_id: p.id, agent_did: p.agent_did, framework: agent.framework, host: agent.host, match: sas(p.code, p.agent_did!).names, permissions };
};

function detail(d: Deps, p: PairingRow, ownerDid: string, permissions: string[]) {
  const state = stateOf(p), agent = p.agent ? JSON.parse(p.agent) : null;
  const payload = state === "claimed" ? confirmPayload(p, permissions) : null;
  return {
    id: p.id, code: p.code, url: `https://openentity.org/pair#${p.code}`, expires_at: Number(p.expires_at), state,
    agent: agent && p.agent_did ? { did: p.agent_did, framework: agent.framework, host: agent.host, sdk: agent.sdk, sdk_version: agent.sdk_version, safety: agent.safety ?? null } : null,
    sas: p.agent_did ? sas(p.code, p.agent_did) : null,
    approval_request: payload ? {
      verifier_did: `did:web:${d.host}`, owner_did: ownerDid, request_id: p.request_id, action: "pairing.confirm", payload,
      payload_digest: payloadDigest(payload), expires_at: Math.min(now() + 600, Number(p.expires_at)), decisions: ["approve"],
    } : null,
  };
}

const short = (v: unknown, max: number, name: string, optional = false): string | null => {
  if (optional && (v === undefined || v === null)) return null;
  if (typeof v !== "string" || !v || v.length > max) fail(400, "bad_request", `${name} is required, at most ${max} characters`);
  return v as string;
};

export function routes(app: Hono, d: Deps) {
  const serviceDid = `did:web:${d.host}`;
  const own = async (accountId: string, id: string) =>
    (await d.db.first<PairingRow>("SELECT * FROM pairings WHERE id = $1 AND account_id = $2", [id, accountId])) ?? fail(404, "not_found", "no such pairing");
  const linked = async (accountId: string) => Number((await d.db.first<{ n: number }>("SELECT count(*) AS n FROM agents WHERE account_id = $1 AND state <> 'unlinked'", [accountId]))!.n);

  // ---------------------------------------------------------------- owner side
  app.post("/v1/pairings", async (c) => {
    const o = await bearer(c, d);
    if (!o.ownerDid) fail(403, "key_log_required", "pairing needs a key log, since confirming signs approval/2.0");
    const t = now();
    const today = await d.db.all<{ created_at: number }>("SELECT created_at FROM pairings WHERE account_id = $1 AND created_at > $2 ORDER BY created_at", [o.accountId, t - 86_400]);
    if (today.length >= CODES_PER_DAY) fail(429, "rate_limited", `at most ${CODES_PER_DAY} pairing codes a day`, { retry_after: Number(today[0].created_at) + 86_400 - t });
    if ((await linked(o.accountId)) >= AGENT_LIMIT) fail(409, "agent_limit", `at most ${AGENT_LIMIT} paired agents; unlink one first`);
    for (let attempt = 0; ; attempt++) {
      const p = { id: newId("pr"), code: newCode(), expires_at: t + CODE_TTL };
      const ins = await d.db.run("INSERT INTO pairings (id, account_id, code, state, created_at, expires_at) VALUES ($1, $2, $3, 'waiting', $4, $5) ON CONFLICT (code) DO NOTHING",
        [p.id, o.accountId, p.code, t, p.expires_at]);
      if (ins.changes) {
        await track(d, "pair_code_created", {}, { owner: o.ownerDid });
        return c.json({ ...p, url: `https://openentity.org/pair#${p.code}`, state: "waiting" }, 201);
      }
      if (attempt > 3) throw new Error("no free pairing code");
    }
  });

  app.get("/v1/pairings/:id", async (c) => {
    const o = await bearer(c, d);
    // ?permissions=a,b: the approval request covers the permissions the owner picked; confirm sends the same list.
    const q = c.req.query("permissions");
    return c.json(detail(d, await own(o.accountId, c.req.param("id")), o.ownerDid ?? "", permissionList(q ? q.split(",") : [])));
  });

  app.delete("/v1/pairings/:id", async (c) => {
    const o = await bearer(c, d);
    const p = await own(o.accountId, c.req.param("id"));
    await d.db.run("UPDATE pairings SET state = 'cancelled' WHERE id = $1 AND state IN ('waiting', 'claimed')", [p.id]);
    return c.body(null, 204);
  });

  app.post("/v1/pairings/:id/confirm", async (c) => {
    const o = await bearer(c, d);
    const p = await own(o.accountId, c.req.param("id"));
    const state = stateOf(p);
    if (state === "expired") fail(410, "code_expired", "this pairing expired; show a new code");
    if (state !== "claimed") fail(409, "not_claimed", "no agent has claimed this code");
    const b = await json(c);
    const permissions = permissionList(b.permissions ?? fail(400, "bad_request", "permissions are required"));
    const label = b.label === undefined ? null : short(b.label, 80, "label");
    const previous = await d.db.first<AgentRow>("SELECT * FROM agents WHERE did = $1", [p.agent_did]);
    if (previous && previous.state !== "unlinked" && previous.account_id !== o.accountId) fail(409, "agent_linked", "this agent is paired with another owner");
    if (!(previous && previous.state !== "unlinked") && (await linked(o.accountId)) >= AGENT_LIMIT) fail(409, "agent_limit", `at most ${AGENT_LIMIT} paired agents; unlink one first`);
    await checkApproval(c, d, { ownerDid: o.ownerDid!, requestId: p.request_id!, payloadDigest: payloadDigest(confirmPayload(p, permissions)), decisions: ["approve"] });
    const agent = JSON.parse(p.agent!), t = now();
    const link = await d.db.tx(async (tx) => {
      const won = await tx.run("UPDATE pairings SET state = 'confirmed', confirmed_at = $2 WHERE id = $1 AND state = 'claimed'", [p.id, t]);
      if (!won.changes) fail(409, "approval_reused", "this pairing was already confirmed");
      // A paused agent that pairs again with the same owner stays paused; an unlinked one starts active.
      const row = await tx.first<{ perm_seq: number; link_epoch: number }>(
        `INSERT INTO agents (did, account_id, owner_did, label, framework, host, permissions, perm_seq, state, paired_at, link_epoch)
         VALUES ($1, $2, $3, $4, $5, $6, $7, 1, 'active', $8, 1)
         ON CONFLICT (did) DO UPDATE SET account_id = $2, owner_did = $3, label = COALESCE($4, agents.label), framework = $5, host = $6, permissions = $7,
           perm_seq = agents.perm_seq + 1, state = CASE WHEN agents.state = 'paused' AND agents.account_id = $2 THEN 'paused' ELSE 'active' END,
           paired_at = $8, unlinked_at = NULL, link_epoch = agents.link_epoch + 1
         RETURNING perm_seq, link_epoch`,
        [p.agent_did, o.accountId, o.ownerDid, label, agent.framework, agent.host, JSON.stringify(permissions), t]);
      for (const product of PRODUCT_DIDS) await tx.run("INSERT INTO agent_products (agent_did, product) VALUES ($1, $2) ON CONFLICT DO NOTHING", [p.agent_did, product]);
      return { seq: Number(row!.perm_seq), linkEpoch: Number(row!.link_epoch) };
    });
    const data = { agent_did: p.agent_did, owner_did: o.ownerDid, permissions, framework: agent.framework, seq: link.seq, link_epoch: link.linkEpoch };
    await Promise.all(PRODUCT_DIDS.map((product) => sendEvent(d, product, "agent.paired", data)));
    await track(d, "pair_confirmed", { framework: agent.framework, permissions_count: permissions.length, seconds_from_code: t - Number(p.created_at) }, { owner: o.ownerDid, agent: p.agent_did! });
    return c.json(await agentView(d, (await d.db.first<AgentRow>("SELECT * FROM agents WHERE did = $1", [p.agent_did]))!));
  });

  // ---------------------------------------------------------------- agent side (no CAPTCHA, login or payment)
  app.post("/v1/pair", async (c) => {
    const { did } = await agentSigned(c, d);
    if ((await bump(d.db, `pair:${createHash("sha256").update(ipOf(c)).digest("hex").slice(0, 32)}`, String(Math.floor(now() / 60)))) > 30) {
      fail(429, "rate_limited", "too many pairing attempts from this address", { retry_after: 60 });
    }
    const b = await json(c);
    const code = typeof b.code === "string" ? b.code.trim().toUpperCase() : "";
    if (!CODE.test(code)) fail(400, "bad_request", "code looks like OE-XXXX-XXXX");
    const agent = { framework: short(b.framework, 64, "framework"), sdk: short(b.sdk, 64, "sdk"), sdk_version: short(b.sdk_version, 32, "sdk_version"), host: short(b.host, 255, "host", true) };
    // The Presentation's nonce is "pair:" + the code (OEIS-1 nonces have 16 characters at least), in any case.
    const sent = typeof b.presentation?.nonce === "string" ? b.presentation.nonce : "";
    const pres = await verifyPresentation(b.presentation, { audience: serviceDid, nonce: sent.toUpperCase() === `PAIR:${code}` ? sent : `pair:${code}` });
    if (!pres.ok) fail(400, "presentation_invalid", pres.errors.join("; ").slice(0, 300));
    if (normalizeEid(pres.eid!) !== did) fail(400, "presentation_invalid", "the presentation's eid is not the signer");
    const p = await d.db.first<PairingRow>("SELECT * FROM pairings WHERE code = $1", [code]) ?? fail(404, "code_unknown", "no such pairing code");
    const state = stateOf(p);
    if (state === "expired" || state === "cancelled") fail(410, "code_expired", "this code expired; ask the owner for a new one");
    if (state !== "waiting") fail(409, "code_used", "this code was already used");
    const linkedTo = await d.db.first<{ account_id: string }>("SELECT account_id FROM agents WHERE did = $1 AND state <> 'unlinked'", [did]);
    if (linkedTo && linkedTo.account_id !== p.account_id) fail(409, "agent_linked", "this agent is paired with another owner, who must unlink it first");
    const t = now();
    const won = await d.db.run(
      "UPDATE pairings SET state = 'claimed', agent_did = $2, agent = $3, request_id = $4, claimed_at = $5, expires_at = $6 WHERE id = $1 AND state = 'waiting' AND expires_at > $5",
      [p.id, did, JSON.stringify({ ...agent, safety: await safetyOf(d, did) }), newId("pc"), t, t + CONFIRM_TTL]);
    if (!won.changes) fail(409, "code_used", "this code was already used");
    const owner = await d.db.first<{ owner_did: string | null }>("SELECT owner_did FROM accounts WHERE id = $1", [p.account_id]);
    await track(d, "pair_requested", { framework: agent.framework!, sdk: agent.sdk!, sdk_version: agent.sdk_version! }, { owner: owner?.owner_did, agent: did });
    return c.json({ pairing_id: p.id, sas: sas(code, did), expires_at: t + CONFIRM_TTL, poll_interval: POLL_GAP }, 201);
  });

  app.get("/v1/pair/:pairing_id", async (c) => {
    const { did } = await agentSigned(c, d);
    const p = await d.db.first<PairingRow>("SELECT * FROM pairings WHERE id = $1 AND agent_did = $2", [c.req.param("pairing_id"), did]) ?? fail(404, "not_found", "no such pairing");
    const t = now();
    if (!(await d.db.first("UPDATE pairings SET polled_at = $2 WHERE id = $1 AND (polled_at IS NULL OR polled_at <= $3) RETURNING id", [p.id, t, t - POLL_GAP]))) {
      fail(429, "rate_limited", "poll at most every 2 seconds", { retry_after: POLL_GAP });
    }
    const state = stateOf(p);
    if (state !== "confirmed") return c.json({ state: state === "cancelled" ? "rejected" : state, owner_did: null, permissions: [] });
    const a = (await d.db.first<AgentRow>("SELECT * FROM agents WHERE did = $1", [did]))!;
    const out: Record<string, unknown> = { state, owner_did: a.owner_did, permissions: JSON.parse(a.permissions) };
    // The keys go out once, on the first confirmed read: fetched from the products now and never stored here.
    if (await d.db.first("UPDATE pairings SET credentials_at = $2 WHERE id = $1 AND credentials_at IS NULL RETURNING id", [p.id, t])) {
      out.credentials = await productKeys(d, a, PRODUCT_DIDS, `pair:${p.id}`);
    }
    return c.json(out);
  });
}
