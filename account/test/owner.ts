// Web lane test fixtures on top of helpers.ts: an app whose outside calls (products, Apple, mail) are recorded, owners
// with a key log stored the way the service stores it, and approval/2.0 signatures from software keys. No key is real.
import { createHash, randomUUID } from "node:crypto";
import { createApp, type Deps } from "../src/app.ts";
import { newId } from "../src/db.ts";
import { base32 } from "../src/keylog.ts";
import { accessToken, openSession } from "../src/sessions.ts";
import type { WebConfig } from "../src/web/config.ts";
import { HOST, ORIGIN, SERVICE_DID, caller, entry, lineHash, p256Key, testDeps, type Key } from "./helpers.ts";

export { HOST, ORIGIN, SERVICE_DID as SERVICE, type Key };
const now = () => Math.floor(Date.now() / 1000);

/** Outside calls the app made: product calls (with their signed headers), Apple and others, mail, email codes. */
export interface Outside { calls: { url: string; body: any; headers: Record<string, string> }[]; mail: { to: string; subject: string; text: string }[]; codes: string[] }

export async function webApp(o: { web?: Partial<WebConfig>; answer?: (url: string, init?: RequestInit) => Response | undefined; deps?: Partial<Deps> } = {}) {
  const out: Outside = { calls: [], mail: [], codes: [] };
  const d = await testDeps({
    web: { sendMail: async (to, subject, text) => { out.mail.push({ to, subject, text }); }, ...o.web },
    fetch: (async (url: string, init?: RequestInit) => {
      const raw = init?.body instanceof Uint8Array ? new TextDecoder().decode(init.body) : String(init?.body ?? "");
      let body: any = raw;
      try { body = JSON.parse(raw); } catch { /* a form or nothing */ }
      out.calls.push({ url: String(url), body, headers: Object.fromEntries(Object.entries(init?.headers ?? {})) as Record<string, string> });
      return o.answer?.(String(url), init) ?? new Response(null, { status: 204 });
    }) as typeof fetch,
    ...o.deps,
  });
  out.codes = d.codes;
  const app = createApp(d);
  return { d, app, out, call: caller(app) };
}

export const call = (app: ReturnType<typeof createApp>, method: string, path: string, body?: unknown, headers: Record<string, string> = {}) => caller(app)(method, path, body, headers);

export interface Owner { accountId: string; ownerDid: string; root: Key; approver: Key | null; token: string; sid: string; install: string }

/** A signed-in account. With a key log (default) its genesis holds the root passkey and a p256 approver (or the root only). */
export async function owner(d: Deps, o: { keyLog?: boolean; rootOnly?: boolean; email?: string; authAgo?: number } = {}): Promise<Owner> {
  const accountId = newId("acct"), t = now(), install = randomUUID();
  await d.db.run("INSERT INTO accounts (id, email, app_account_token, created_at) VALUES ($1, $2, $3, $4)", [accountId, o.email ?? `${accountId}@example.com`, randomUUID(), t]);
  const root = p256Key({ type: "webauthn" }), approver = o.rootOnly ? null : p256Key();
  let ownerDid = "";
  if (o.keyLog !== false) {
    const line = entry(approver ?? root, { seq: 1, prev: null, op: "genesis", ts: t, body: { root: root.credential, approver: approver?.credential ?? null } });
    const id = base32(createHash("sha256").update(line).digest());
    ownerDid = `did:web:${d.rp.id}:o:${id}`;
    await d.db.run("INSERT INTO keylog_entries (owner_id, seq, line, hash, op, first_seen_at, effective_at) VALUES ($1, 1, $2, $3, 'genesis', $4, $4)", [id, line, lineHash(line), t]);
    await d.db.run("UPDATE accounts SET owner_did = $2 WHERE id = $1", [accountId, ownerDid]);
  }
  const authTime = t - (o.authAgo ?? 0);
  const s = await openSession(d.db, { accountId, platform: "ios", amr: "passkey", installId: install }, authTime);
  const at = await accessToken(d, accountId, SERVICE_DID, s.sessionId, "ios", authTime, "passkey");
  return { accountId, ownerDid, root, approver, token: at.access_token, sid: s.sessionId, install };
}

export const bearer = (o: Owner) => ({ authorization: `Bearer ${o.token}` });

/** An Approval2 for an ApprovalRequest, signed by a key log key in its own form (p256, or webauthn for a passkey). */
export function approve(k: Key, req: { verifier_did: string; owner_did: string; request_id: string; payload_digest: string; expires_at: number }, decision = "approve") {
  const pre = ["approval/2.0", req.verifier_did, req.owner_did, req.request_id, req.payload_digest, decision, String(req.expires_at)].join("|");
  const base = { version: "approval/2.0", verifier_did: req.verifier_did, owner_did: req.owner_did, request_id: req.request_id, payload_digest: req.payload_digest, decision, expires_at: req.expires_at, device_id: k.kid };
  return k.credential.type === "webauthn"
    ? { ...base, form: "webauthn", ...k.assert(createHash("sha256").update(pre).digest()) }
    : { ...base, form: "p256", signature: k.sign(pre) };
}
export const approvalHeader = (a: object) => ({ "x-oe-approval": Buffer.from(JSON.stringify(a)).toString("base64url") });

/** POST /v1/step-up, then the bearer and Approval2 headers for the action's call, signed by `signer` (the approver by default). */
export async function stepUp(app: ReturnType<typeof createApp>, o: Owner, action: string, params: Record<string, unknown> = {}, signer: Key | null = o.approver ?? o.root) {
  const r = await call(app, "POST", "/v1/step-up", { action, params }, bearer(o));
  if (r.status !== 200) throw new Error(`step-up ${action}: ${r.status} ${r.text}`);
  return { ...bearer(o), ...approvalHeader(approve(signer!, r.body)) };
}
