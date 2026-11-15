// Agent Commerce Check (docs/commerce spec "agent-commerce-check"): one call before a merchant accepts an agent purchase.
// The decision is verifyAgentForCheckout from the SDK. This file gathers what the SDK must not take from the request
// (registry facts, the owner's key log, the mandate status), refuses replays, and writes the hash-chained evidence record.
import {
  canonicalize, cartDigest, normalizeEid, parseJson, sha256Hex, verifyAgentForCheckout, verifyKeyLog, verifyMandate, verifyRequest,
  type AgentFacts, type AgentPolicy, type KeyLogState, type MandateStatus,
} from "./sdk.ts";
import { type Env, nowIso } from "./env.ts";
import { getJson, getText } from "./aliases.ts";

export const VERIFIER = "commerce-check/1";
export const EVIDENCE_DAYS = 400;
export const ACCOUNT_HOST = "account.openentity.org";
export const ACCOUNT_DID = `did:web:${ACCOUNT_HOST}`;
const OWNER_DID = /^did:web:account\.openentity\.org:o:[A-Za-z0-9_-]{8,128}$/;
const STATUS_URL = /^https:\/\/account\.openentity\.org\/v1\/mandates\/(md_[a-z2-7]{26})\/status$/;
const ZERO = "0".repeat(64);
const BAND_CLAIM = "custom:securemyagent:security_posture", OWNED_CLAIM = "custom:openentity:operated_by";
const OWNER_LEVELS = ["basic", "id", "kyb"];

/** A bad request body: the route answers 400 with `code`. */
export class CheckInputError extends Error {
  constructor(public code: string, message: string) { super(message); }
}
const bad = (code: string, m: string): never => { throw new CheckInputError(code, m); };

/** The owner's key log as the account service serves it, plus the service's P-256 close keys. */
export interface OwnerLog { lines: string[]; serviceKeys: { kty: "EC"; crv: "P-256"; x: string; y: string }[]; origins?: string[] }
export type OwnerSource = (ownerDid: string) => Promise<OwnerLog | null>;
export interface CommerceEnv extends Env { commerceOwner?: OwnerSource; commerceStatus?: (url: string) => Promise<unknown> }

/** Production: only the OpenEntity Account serves owner key logs (an owner DID elsewhere is unknown, never fetched). */
export const accountOwnerSource: OwnerSource = async (did) => {
  if (!OWNER_DID.test(did)) return null;
  const text = await getText(`https://${ACCOUNT_HOST}/o/${did.split(":").pop()}/log`, "application/jsonl");
  if (!text) return null;
  const doc = await getJson(`https://${ACCOUNT_HOST}/.well-known/did.json`);
  const serviceKeys = (doc?.assertionMethod ?? []).flatMap((id: unknown) => {
    const vm = (doc.verificationMethod ?? []).find((v: any) => v.id === id);
    return vm?.publicKeyJwk?.kty === "EC" && vm.publicKeyJwk.crv === "P-256" ? [vm.publicKeyJwk] : [];
  });
  // The Android app's passkey origins: android:apk-key-hash:<base64url SHA-256 of the signing certificate>, from the fingerprints the account publishes.
  const links = await getJson(`https://${ACCOUNT_HOST}/.well-known/assetlinks.json`);
  const origins = [`https://${ACCOUNT_HOST}`, ...(Array.isArray(links) ? links : []).flatMap((l: any) => (l?.target?.sha256_cert_fingerprints ?? []) as string[]).filter((f) => /^[0-9A-F:]{95}$/i.test(f)).map((f) => `android:apk-key-hash:${btoa(String.fromCharCode(...f.split(":").map((h) => parseInt(h, 16)))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")}`)];
  const lines = text.split("\n").filter(Boolean);
  return lines.length && lines.length <= 500 ? { lines, serviceKeys, origins } : null;
};

/** Verifies the owner's key log with first_seen_at taken from this registry's own memory (every key log delay runs from it). Null when the log is unknown or invalid; "fork" when an entry changed. */
type Owner = { keyLog: Pick<KeyLogState, "did" | "root" | "approvers" | "closed">; origins?: string[] };
async function ownerKeyLog(env: CommerceEnv, did: string, now: number): Promise<Owner | null | "fork"> {
  const log = await (env.commerceOwner ?? accountOwnerSource)(did);
  if (!log) return null;
  const seen = await env.db.all<{ seq: number; line_sha: string; first_seen: number }>("SELECT seq, line_sha, first_seen FROM commerce_keylog WHERE owner = $1 ORDER BY seq", [did]);
  if (seen.length > log.lines.length) return "fork";
  const first: number[] = [];
  for (let i = 0; i < log.lines.length; i++) {
    const sha = await sha256Hex(log.lines[i]);
    if (seen[i]) {
      if (seen[i].line_sha !== sha) return "fork";
      first.push(Number(seen[i].first_seen));
    } else {
      await env.db.run("INSERT INTO commerce_keylog (owner, seq, line_sha, first_seen) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING", [did, i + 1, sha, now]);
      first.push(now);
    }
  }
  const r = verifyKeyLog(did, log.lines, first, { now, serviceKeys: log.serviceKeys, origins: log.origins });
  return r.ok ? { keyLog: r.state, origins: log.origins } : null;
}

/** What verifyMandate needs besides the mandate: the issuer's key log and the status answer (only from the account service). */
export async function mandateContext(env: CommerceEnv, m: Record<string, any>, nowS: number) {
  const keyLog = typeof m.issuer_did === "string" ? await ownerKeyLog(env, m.issuer_did, nowS) : null;
  let status: MandateStatus | undefined;
  const sm = typeof m.status === "string" ? STATUS_URL.exec(m.status) : null;
  if (sm) {
    const s: any = await (env.commerceStatus ?? ((u: string) => getJson(u)))(m.status);
    if (isObj(s) && s.mandate_id === sm[1] && (s.status === "active" || s.status === "revoked" || s.status === "exhausted")) status = s as MandateStatus;
  }
  return { keyLog, status };
}

/** POST /v1/commerce/mandate: is this mandate/1 valid now, for this agent? (No cart, no evidence: the MCP tool openentity_mandate_verify.) */
export async function mandateCheck(env: CommerceEnv, mandate: unknown, agentDid: string | undefined) {
  if (!isObj(mandate)) return bad("bad_request", "mandate must be an object");
  const { keyLog, status } = await mandateContext(env, mandate, Math.floor(Date.now() / 1000));
  if (keyLog === "fork") return { ok: false, error: "owner_key_log_fork" };
  if (!keyLog) return { ok: false, error: "no_key_log" };
  const r = verifyMandate(mandate, { keyLog: keyLog.keyLog, origins: keyLog.origins, agentDid, status });
  return r.ok ? { ok: true, mandate_id: r.mandate_id, owner_did: mandate.issuer_did, limits: r.limits, scope: r.scope, step_up_over: r.step_up_over, period_spent: r.period_spent, total_spent: r.total_spent } : { ok: false, error: r.error, message: r.message };
}

const claimOf = (row: { json: string }) => JSON.parse(row.json).claim ?? {};
const BANDS = ["poor", "fair", "good", "strong"];

/** What the registry says about the agent: never taken from the request. */
async function agentFacts(env: Env, did: string, now: string): Promise<{ facts: AgentFacts; used: string[]; withdrawn: boolean; violation: boolean; ownerLevel?: string }> {
  const db = env.db, eid = normalizeEid(did), used: string[] = [];
  const e = await db.first<{ level: number | null; withdrawn_at: string | null }>("SELECT level, withdrawn_at FROM entities WHERE eid = $1", [eid]);
  const facts: AgentFacts = {};
  if (e?.level !== null && e?.level !== undefined) facts.level = Number(e.level);
  const live = "revoked_at IS NULL AND expires > $2";
  const owned = await db.first<{ sha256: string; json: string }>(`SELECT sha256, json FROM attestations WHERE subject = $1 AND claim_type = $3 AND issuer = $4 AND ${live} ORDER BY created DESC LIMIT 1`, [eid, now, OWNED_CLAIM, ACCOUNT_DID]);
  let ownerLevel: string | undefined;
  if (owned) {
    facts.owner_did = String(claimOf(owned).owner ?? "");
    used.push(owned.sha256);
    const v = await db.first<{ sha256: string; json: string }>(`SELECT sha256, json FROM attestations WHERE subject = $1 AND claim_type = 'custom:openentity:owner_verified' AND issuer = $3 AND ${live} ORDER BY created DESC LIMIT 1`, [facts.owner_did, now, ACCOUNT_DID]);
    if (v) { ownerLevel = String(claimOf(v).level ?? ""); used.push(v.sha256); }
  }
  // Only accredited observers count (the same rule as levels), so a self-issued "strong" posture is worth nothing.
  const band = await db.first<{ sha256: string; issuer: string; json: string }>(`SELECT a.sha256, a.issuer, a.json FROM attestations a JOIN observers o ON o.did = a.issuer WHERE a.subject = $1 AND a.claim_type = $3 AND a.revoked_at IS NULL AND a.expires > $2 ORDER BY a.created DESC LIMIT 1`, [eid, now, BAND_CLAIM]);
  if (band) { facts.security_band = String(claimOf(band).score_band ?? ""); facts.security_issuer = band.issuer; used.push(band.sha256); }
  const viol = await db.first<{ sha256: string }>(`SELECT a.sha256 FROM attestations a JOIN observers o ON o.did = a.issuer WHERE a.subject = $1 AND a.claim_type = 'custom:clawgrc:violation' AND a.revoked_at IS NULL AND a.expires > $2 LIMIT 1`, [eid, now]);
  if (viol) used.push(viol.sha256);
  return { facts, used, withdrawn: !!e?.withdrawn_at, violation: !!viol, ownerLevel };
}

/** The merchant's published `agent_policy` (Entity Document extension `openentity:merchant`), overlaid by the inline policy. */
async function mergedPolicy(env: Env, inline: Record<string, unknown>): Promise<AgentPolicy & Record<string, unknown>> {
  const { merchant, ...rest } = inline;
  if (typeof merchant !== "string") return rest;
  const row = await env.db.first<{ json: string }>("SELECT json FROM documents WHERE eid = $1 ORDER BY seq DESC LIMIT 1", [normalizeEid(merchant)]);
  const published = row ? JSON.parse(row.json).extensions?.["openentity:merchant"]?.agent_policy : undefined;
  if (published === undefined) bad("unknown_merchant", "policy.merchant has no published openentity:merchant agent_policy");
  return { ...published, ...rest };
}

const isObj = (v: unknown): v is Record<string, any> => typeof v === "object" && v !== null && !Array.isArray(v);
const b64uJson = (s: string): unknown => {
  if (!/^[A-Za-z0-9_-]+$/.test(s) || s.length > 16384) bad("bad_mandate", "OE-Mandate must be base64url JSON of at most 16 KB");
  try { return parseJson(new TextDecoder().decode(Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0)))); } catch { return bad("bad_mandate", "OE-Mandate is not valid JSON"); }
};

export interface CheckBody {
  request: { method: string; url: string; headers: Record<string, string>; body?: string; body_b64?: string };
  cart: unknown;
  policy?: Record<string, unknown>;
  mandate?: unknown;
  approval?: { approval: unknown; verifier_did: string; request_id: string };
}
export function parseCheckBody(o: unknown): CheckBody {
  if (!isObj(o) || !isObj(o.request) || !isObj(o.request.headers) || typeof o.request.method !== "string" || typeof o.request.url !== "string") return bad("bad_request", "body must be {request: {method, url, headers}, cart, policy}");
  if (!Object.values(o.request.headers).every((v) => typeof v === "string")) bad("bad_request", "request.headers values must be strings");
  if (o.policy !== undefined && !isObj(o.policy)) bad("bad_request", "policy must be an object");
  const b64 = (o.request as { body_b64?: unknown }).body_b64;
  if (b64 !== undefined && !(typeof b64 === "string" && /^[A-Za-z0-9+/]*={0,2}$/.test(b64) && b64.length % 4 === 0)) bad("bad_request", "request.body_b64 must be base64");
  if ((o.request as { body?: unknown }).body !== undefined && typeof (o.request as { body?: unknown }).body !== "string") bad("bad_request", "request.body must be a string");
  if (o.approval !== undefined && !(isObj(o.approval) && typeof o.approval.verifier_did === "string" && typeof o.approval.request_id === "string")) bad("bad_request", "approval must be {approval, verifier_did, request_id}");
  return o as unknown as CheckBody;
}

const CHECK_OF: [RegExp, string][] = [
  [/^(request_|agent_mismatch$)/, "signature"], [/^(level_too_low|agent_withdrawn)$/, "registry"], [/^(owner_|no_key_log$|mandate_owner_mismatch$)/, "owner"],
  [/^(security_|issuer_not_accepted$|clawgrc_)/, "security"], [/^(mandate|no_mandate$|step_up_over$|approval_|owner_approved_cart$)/, "mandate"],
];
const ORDER = ["signature", "registry", "owner", "security", "mandate", "policy"];
/** The six checks of the spec in order: `fail` where a reason names it, `skipped` after a deny stopped the run, else `pass`. */
function checksOf(decision: string, reasons: string[]) {
  const failed = new Set(decision === "allow" ? [] : reasons.map((r) => CHECK_OF.find(([re]) => re.test(r))?.[1] ?? "policy"));
  if (decision === "step_up") failed.add("mandate");
  const stop = decision === "deny" ? Math.min(...[...failed].map((c) => ORDER.indexOf(c))) : ORDER.length;
  return ORDER.map((check, i) => ({ check, result: failed.has(check) ? (decision === "step_up" ? "step_up" : "fail") : i > stop ? "skipped" : "pass" }));
}

export interface CheckResult {
  decision: "allow" | "step_up" | "deny"; reasons: string[]; agent_did?: string; owner_did?: string; mandate_id?: string;
  cart_digest?: string; cart?: unknown; evidence_id: string;
}

/** Runs the check and stores the evidence. `ip` is the salted client hash, never stored. */
export async function commerceCheck(env: CommerceEnv, b: CheckBody): Promise<CheckResult> {
  const nowS = Math.floor(Date.now() / 1000), now = nowIso(), db = env.db;
  const lower = Object.fromEntries(Object.entries(b.request.headers).map(([k, v]) => [k.toLowerCase(), v]));
  const mandateRaw = b.mandate ?? (lower["oe-mandate"] ? b64uJson(lower["oe-mandate"]) : undefined);
  const policy = await mergedPolicy(env, b.policy ?? {});
  const body = b.request.body_b64 !== undefined ? Uint8Array.from(atob(b.request.body_b64), (c) => c.charCodeAt(0)) : b.request.body !== undefined ? new TextEncoder().encode(b.request.body) : undefined;

  let reasons: string[] = [], decision: CheckResult["decision"] = "deny", evidence: Record<string, unknown> = {}, owner: string | undefined, agentDid: string | undefined;
  let used: string[] = [], mandateId: string | undefined, sigNonce: string | undefined;
  try {
    // 1. signature. did:web keys are fetched through the SSRF-guarded fetch; the nonce is single-use for everyone.
    const keyid = /keyid="([^"]+)"/.exec(lower["signature-input"] ?? "")?.[1];
    const v = await verifyRequest({ method: b.request.method, url: b.request.url, headers: lower, body, allowDidWeb: keyid?.startsWith("did:web:") ? [keyid.split("#")[0]] : undefined, fetchJson: (u) => getJson(u) });
    agentDid = v.did;
    sigNonce = v.nonce;
  } catch { /* verifyAgentForCheckout reports request_unverified below */ }

  if (agentDid && sigNonce) {
    const first = await db.run("INSERT INTO commerce_used (key, n, created_at) VALUES ($1, 0, $2) ON CONFLICT DO NOTHING", [`nonce:${await sha256Hex(`${agentDid}|${sigNonce}`)}`, now]);
    if (!first.changes) { reasons = ["request_replayed"]; agentDid = undefined; }
  }
  if (!agentDid && !reasons.length) reasons = ["request_unverified"];

  if (agentDid) {
    const f = await agentFacts(env, agentDid, now);
    used = f.used;
    let approvalCounter = 0;
    const m = isObj(mandateRaw) ? mandateRaw : undefined;
    if (mandateRaw !== undefined && !m) reasons = ["mandate_malformed"];
    const ctx = m ? await mandateContext(env, m, nowS) : { keyLog: null, status: undefined };
    let keyLog = ctx.keyLog;
    const status = ctx.status;
    const a = b.approval;
    if (a && !keyLog && f.facts.owner_did) keyLog = await ownerKeyLog(env, f.facts.owner_did, nowS);
    if (a && isObj(a.approval) && typeof a.approval.device_id === "string") approvalCounter = Number((await db.first<{ n: number }>("SELECT n FROM commerce_used WHERE key = $1", [`kid:${a.approval.device_id}`]))?.n ?? 0);
    if (!reasons.length) {
      if (f.withdrawn) reasons = ["agent_withdrawn"];
      else if (keyLog === "fork") reasons = ["owner_key_log_fork"];
      // The registry knows the agent's owner: a mandate from another owner's key log is not that owner's permission.
      else if (m && f.facts.owner_did && m.issuer_did !== f.facts.owner_did) reasons = ["mandate_owner_mismatch"];
      else if (policy.min_security_band !== undefined && f.violation) reasons = ["clawgrc_violation"];
      else if (typeof policy.min_owner_level === "string" && (!f.facts.owner_did || OWNER_LEVELS.indexOf(f.ownerLevel ?? "") < OWNER_LEVELS.indexOf(policy.min_owner_level))) reasons = ["owner_not_verified"];
    }
    if (!reasons.length) {
      const r = await verifyAgentForCheckout({
        agentDid, cart: b.cart, merchantPolicy: policy, agent: f.facts, mandate: mandateRaw, keyLog: keyLog && keyLog !== "fork" ? keyLog.keyLog : undefined, origins: keyLog && keyLog !== "fork" ? keyLog.origins : undefined, status, now: nowS,
        approval: a && { approval: a.approval, verifierDid: a.verifier_did, requestId: a.request_id, counter: approvalCounter },
      });
      ({ decision, reasons, evidence } = r);
      owner = (m?.issuer_did as string | undefined) ?? f.facts.owner_did;
      mandateId = evidence.mandate_id as string | undefined;
      if (decision === "allow" && evidence.approval_request_id !== undefined) {
        const key = `approval:${await sha256Hex(`${a!.verifier_did}|${a!.request_id}`)}`;
        const fresh = await db.run("INSERT INTO commerce_used (key, n, created_at) VALUES ($1, 0, $2) ON CONFLICT DO NOTHING", [key, now]);
        if (!fresh.changes) { decision = "deny"; reasons = ["approval_replayed"]; }
        else {
          const kid = `kid:${evidence.approval_kid}`;
          await db.run("INSERT INTO commerce_used (key, n, created_at) VALUES ($1, $2, $3) ON CONFLICT (key) DO UPDATE SET n = excluded.n WHERE commerce_used.n < excluded.n", [kid, evidence.approval_counter, now]);
        }
      }
    } else decision = "deny";
  } else decision = "deny";

  const cartOk = isObj(b.cart);
  const result: CheckResult = { decision, reasons, evidence_id: "", ...(agentDid ? { agent_did: agentDid } : {}), ...(owner ? { owner_did: owner } : {}), ...(mandateId ? { mandate_id: mandateId } : {}) };
  if (decision === "step_up" && cartOk) { try { result.cart_digest = cartDigest(b.cart); result.cart = b.cart; } catch { /* bad cart is a deny */ } }
  result.evidence_id = await writeEvidence(env, {
    inputs_digest: await sha256Hex(canonicalize({ request: { method: b.request.method, url: b.request.url, headers: lower, body_sha256: body ? await sha256Hex(body) : null }, cart: b.cart ?? null, policy, mandate: mandateRaw ?? null, approval: b.approval ?? null })),
    checks: checksOf(decision, reasons), attestation_ids: used, mandate_hash: mandateRaw && isObj(mandateRaw) && evidence.mandate_hash ? evidence.mandate_hash : null,
    decision, reasons, agent_did: agentDid ?? null, owner_did: owner ?? null, verifier_version: VERIFIER,
  }, now);
  return result;
}

const B32 = "abcdefghijklmnopqrstuvwxyz234567";
const newId = () => "ev_" + Array.from(crypto.getRandomValues(new Uint8Array(26)), (x) => B32[x % 32]).join("");

/** Appends one record to the hash chain: hash = sha256(JCS(record)), `prev_hash` = the previous record's hash. A concurrent writer takes the same seq and loses on the key; retry. */
async function writeEvidence(env: Env, body: Record<string, unknown>, now: string): Promise<string> {
  const id = newId();
  for (let n = 0; ; n++) {
    const head = await env.db.first<{ seq: number; hash: string }>("SELECT seq, hash FROM commerce_evidence ORDER BY seq DESC LIMIT 1");
    const record = { evidence_id: id, seq: Number(head?.seq ?? 0) + 1, created_at: now, ...body, prev_hash: head?.hash ?? ZERO };
    const hash = await sha256Hex(canonicalize(record));
    try {
      await env.db.run("INSERT INTO commerce_evidence (seq, evidence_id, created_at, json, hash) VALUES ($1, $2, $3, $4, $5)", [record.seq, id, now, JSON.stringify({ ...record, hash }), hash]);
      return id;
    } catch (e) {
      if (n >= 8 || !/duplicate key value/.test(String(e))) throw e;
    }
  }
}

export async function readEvidence(env: Env, id: string) {
  const r = await env.db.first<{ json: string }>("SELECT json FROM commerce_evidence WHERE evidence_id = $1", [id]);
  return r ? JSON.parse(r.json) : null;
}
export async function evidenceHead(env: Env) {
  const r = await env.db.first<{ seq: number; hash: string; created_at: string }>("SELECT seq, hash, created_at FROM commerce_evidence ORDER BY seq DESC LIMIT 1");
  return r ? { seq: Number(r.seq), hash: r.hash, at: r.created_at } : { seq: 0, hash: ZERO, at: null };
}
/** True when the record's `hash` is the SHA-256 of its JCS form without `hash`. */
export async function evidenceIntact(r: Record<string, unknown>): Promise<boolean> {
  const { hash, ...rest } = r;
  return typeof hash === "string" && (await sha256Hex(canonicalize(rest))) === hash;
}

/** Retention: 400 days (the longest card dispute window plus margin), then deleted; single-use keys outlive no signature or approval. */
export async function sweepCommerce(env: Env) {
  const ago = (days: number) => new Date(Date.now() - days * 86400_000).toISOString().replace(/\.\d+Z$/, "Z");
  await env.db.run("DELETE FROM commerce_evidence WHERE created_at < $1", [ago(EVIDENCE_DAYS)]);
  await env.db.run("DELETE FROM commerce_used WHERE key NOT LIKE 'kid:%' AND created_at < $1", [ago(2)]);
}
