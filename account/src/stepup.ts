// Step-up (PLAN 2.4, ADR 0008): POST /v1/step-up issues an approval/2.0 request whose verifier is this service; the
// action's own call then carries the signed Approval2 in X-OE-Approval. Verification is verifyApproval from
// @openentity/sdk against the owner's key log; each request is used once.
import type { Context, Hono } from "hono";
import { canonicalize, payloadDigest, verifyApproval } from "@openentity/sdk";
import type { Deps } from "./app.ts";
import { newId, now } from "./db.ts";
import { bearer, fail, json } from "./http.ts";
import { keyLogState } from "./keylog.ts";

export const ACTIONS = ["agent.resume", "agent.permissions.widen", "method.add", "method.remove", "email.change", "account.delete", "deletion.cancel", "product.link"] as const;
export type Action = (typeof ACTIONS)[number];
export const REQUEST_TTL = 600;

const PERMISSION = /^(owner\.message|owner\.status|owner\.approval|vault\.request:\S+|evidence\.file|den\.post|market\.sell|contract\.accept<=\$[0-9]+(\.[0-9]{1,2})?)$/;
const AGENT_DID = /^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]+$/;
const ID = /^[A-Za-z0-9_-]{1,64}$/;

/** Sorted, de-duplicated permission strings; 400 invalid_permission for one outside the grammar (openapi.yaml Permission). */
export function permissionList(v: unknown): string[] {
  if (!Array.isArray(v) || v.length > 64) fail(400, "bad_request", "permissions must be an array of at most 64 strings");
  for (const p of v as unknown[]) if (typeof p !== "string" || p.length > 256 || !PERMISSION.test(p)) fail(400, "invalid_permission", `not a permission: ${String(p).slice(0, 80)}`);
  return [...new Set(v as string[])].sort();
}

/** The params of each action in one normal form, so the request and the action's own call compare byte for byte. */
export function normalParams(action: string, p: any): Record<string, unknown> {
  const need = (ok: boolean, what: string) => ok || fail(400, "bad_request", `${action} needs ${what}`);
  p = p && typeof p === "object" && !Array.isArray(p) ? p : {};
  switch (action) {
    case "agent.resume": need(AGENT_DID.test(p.agent_did ?? ""), "params.agent_did"); return { agent_did: p.agent_did };
    case "agent.permissions.widen": need(AGENT_DID.test(p.agent_did ?? ""), "params.agent_did"); return { agent_did: p.agent_did, permissions: permissionList(p.permissions) };
    case "method.add": need(["apple", "google", "passkey", "email"].includes(p.type), "params.type"); return { type: p.type };
    case "method.remove": need(ID.test(p.method_id ?? ""), "params.method_id"); return { method_id: p.method_id };
    case "email.change": need(typeof p.email === "string" && p.email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(p.email), "params.email"); return { email: p.email.trim().toLowerCase() };
    case "product.link": need(typeof p.product === "string" && p.product.length <= 128, "params.product"); return { product: p.product };
    case "account.delete": case "deletion.cancel": return {};
    default: return fail(400, "unknown_action", `unknown action ${action}`);
  }
}

/** The Approval2 in X-OE-Approval: 428 when missing, 403 approval_invalid when it is not an object. */
function approvalHeader(c: Context): Record<string, unknown> {
  const h = c.req.header("x-oe-approval");
  if (!h) fail(428, "approval_required", "this action needs an approval/2.0 signature in X-OE-Approval");
  try {
    if (h!.length > 8192 || !/^[A-Za-z0-9_-]+$/.test(h!)) throw 0;
    const v = JSON.parse(Buffer.from(h!, "base64url").toString("utf8"));
    if (!v || typeof v !== "object" || Array.isArray(v)) throw 0;
    return v;
  } catch { return fail(403, "approval_invalid", "X-OE-Approval must be base64url JSON of an Approval2"); }
}

/**
 * Checks the Approval2 in X-OE-Approval against the owner's key log for a request this service issued (verifier = the
 * service DID). Throws 428 approval_required, 403 approval_invalid or approval_expired. The caller makes the request
 * single use (409 approval_reused). Returns the signing key's kid.
 */
export async function checkApproval(c: Context, d: Deps, o: { ownerDid: string; requestId: string; payloadDigest: string; decisions?: string[]; allowRoot?: boolean }): Promise<{ kid: string; decision: string; approval: Record<string, unknown> }> {
  const a = approvalHeader(c);
  const keyLog = await keyLogState(d, o.ownerDid) ?? fail(403, "key_log_required", "this account has no key log");
  const counterRow = typeof a.device_id === "string"
    ? await d.db.first<{ counter: number }>("SELECT counter FROM approver_counters WHERE owner_did = $1 AND kid = $2", [o.ownerDid, a.device_id])
    : null;
  const r = verifyApproval(a, {
    keyLog, verifierDid: `did:web:${d.host}`, ownerDid: o.ownerDid, requestId: o.requestId, payloadDigest: o.payloadDigest,
    decisions: o.decisions, origins: d.rp.origins, rpId: d.rp.id, counter: Number(counterRow?.counter ?? 0), allowRoot: o.allowRoot,
  });
  if (!r.ok) fail(403, r.error === "expired" ? "approval_expired" : "approval_invalid", `${r.error}: ${r.message}`);
  if (r.ok && a.form === "webauthn") {
    await d.db.run("INSERT INTO approver_counters (owner_did, kid, counter) VALUES ($1, $2, $3) ON CONFLICT (owner_did, kid) DO UPDATE SET counter = GREATEST(approver_counters.counter, EXCLUDED.counter)",
      [o.ownerDid, r.kid, r.counter]);
  }
  return { kid: r.ok ? r.kid : "", decision: String(a.decision), approval: a };
}

/**
 * The step-up gate for one action: X-OE-Approval must sign a request from POST /v1/step-up for this account, this
 * action and these params, decision approve. Throws 428, 403 (approval_invalid, approval_expired, key_log_required)
 * or 409 approval_reused, as the contract says. Each request works once.
 */
export async function requireApproval(c: Context, d: Deps, o: { accountId: string; ownerDid: string | null; action: Action; params: Record<string, unknown>; allowRoot?: boolean }): Promise<{ kid: string }> {
  if (!o.ownerDid) fail(403, "key_log_required", "this action needs a key log; finish \"Turn on Face ID approvals\" first");
  const a = approvalHeader(c);
  const row = await d.db.first<{ action: string; params: string; payload_digest: string; expires_at: number; used_at: number | null }>(
    "SELECT action, params, payload_digest, expires_at, used_at FROM step_ups WHERE request_id = $1 AND account_id = $2", [String(a.request_id ?? ""), o.accountId]);
  if (!row) fail(403, "approval_invalid", "wrong_request: no such step-up request for this account; call POST /v1/step-up");
  if (row!.action !== o.action || row!.params !== canonicalize(normalParams(o.action, o.params))) fail(403, "approval_invalid", "wrong_request: the approval is for another action");
  if (row!.used_at !== null) fail(409, "approval_reused", "this approval was already used");
  if (Number(row!.expires_at) <= now()) fail(403, "approval_expired", "expired: the step-up request expired; ask again");
  const { kid } = await checkApproval(c, d, { ownerDid: o.ownerDid!, requestId: String(a.request_id), payloadDigest: row!.payload_digest, decisions: ["approve"], allowRoot: o.allowRoot });
  const used = await d.db.run("UPDATE step_ups SET used_at = $2 WHERE request_id = $1 AND used_at IS NULL", [a.request_id, now()]);
  if (!used.changes) fail(409, "approval_reused", "this approval was already used");
  return { kid };
}

export function routes(app: Hono, d: Deps) {
  app.post("/v1/step-up", async (c) => {
    const owner = await bearer(c, d);
    const b = await json(c);
    if (!ACTIONS.includes(b.action)) fail(400, "unknown_action", `action must be one of: ${ACTIONS.join(", ")}`);
    if (!owner.ownerDid) fail(403, "key_log_required", "step-up needs a key log; finish \"Turn on Face ID approvals\" first");
    const params = normalParams(b.action, b.params);
    if (b.action === "method.remove" && !(await d.db.first("SELECT 1 FROM methods WHERE id = $1 AND account_id = $2", [params.method_id, owner.accountId]))) fail(404, "not_found", "no such method");
    const payload = { action: b.action, ...params };
    const t = now(), request = { request_id: newId("su"), payload_digest: payloadDigest(payload), expires_at: t + REQUEST_TTL };
    await d.db.run("INSERT INTO step_ups (request_id, account_id, owner_did, action, params, payload_digest, created_at, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
      [request.request_id, owner.accountId, owner.ownerDid, b.action, canonicalize(params), request.payload_digest, t, request.expires_at]);
    return c.json({ verifier_did: `did:web:${d.host}`, owner_did: owner.ownerDid, action: b.action, payload, decisions: ["approve"], ...request });
  });
}
