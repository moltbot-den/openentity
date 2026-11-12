// Owner key logs (PLAN 3, ADR 0007, test-vectors/keylog-1). The service stores each entry as its exact JCS line and
// serves those bytes; every check runs through verifyKeyLog from @openentity/sdk, so the service accepts exactly
// what every product's verifier accepts. The database alone never justifies a key: a stored log is re-verified on read.
import { createHash, createPublicKey, randomInt } from "node:crypto";
import type { Context, Hono } from "hono";
import { compactVerify, importJWK } from "jose";
import { type Credential, type KeyLogState, canonicalize, verifyKeyLog } from "@openentity/sdk";
import type { Deps } from "./app.ts";
import { receipt, receiptClaims, verifyAndroidKey, verifyAppAttest } from "./attest.ts";
import { integrity, revokedSerials } from "./binding.ts";
import { bump, newId, now } from "./db.ts";
import { bearer, fail, json, str } from "./http.ts";
import { nonceHash } from "./idtoken.ts";
import { track } from "./events.ts";
import { notifyOwner } from "./notify.ts";
import { BUNDLE_ID } from "./wellknown.ts";

const DAY = 86_400, ENROLL_TTL = 600, PENDING_MAX = 3, ATTESTATIONS_PER_HOUR = 20;
const ID = /^[a-z2-7]{52}$/;
const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n; // P-256 group order

/** RFC 4648 base32, lowercase, no padding: the owner id is base32(SHA-256(genesis line)). */
export function base32(b: Uint8Array): string {
  const A = "abcdefghijklmnopqrstuvwxyz234567";
  let out = "", bits = 0, value = 0;
  for (const x of b) {
    value = (value << 8) | x;
    bits += 8;
    while (bits >= 5) out += A[(value >> (bits -= 5)) & 31];
    value &= (1 << bits) - 1;
  }
  return bits ? out + A[(value << (5 - bits)) & 31] : out;
}
const sha256 = (s: string) => createHash("sha256").update(s, "utf8").digest();
const sha256Hex = (s: string) => createHash("sha256").update(s, "utf8").digest("hex");

export const ownerDidOf = (d: Deps, id: string) => `did:web:${d.rp.id}:o:${id}`;
const idOf = (d: Deps, ownerDid: string) => {
  const prefix = `did:web:${d.rp.id}:o:`;
  return ownerDid.startsWith(prefix) && ID.test(ownerDid.slice(prefix.length)) ? ownerDid.slice(prefix.length) : null;
};

interface Row { seq: number; line: string; hash: string; first_seen_at: number }
const rows = async (d: Deps, id: string) =>
  (await d.db.all<Row>("SELECT seq, line, hash, first_seen_at FROM keylog_entries WHERE owner_id = $1 ORDER BY seq", [id]))
    .map((r) => ({ ...r, seq: Number(r.seq), first_seen_at: Number(r.first_seen_at) }));

const verifyOpts = (d: Deps, t: number) => ({ now: t, rpId: d.rp.id, origins: d.rp.origins, serviceKeys: [d.keys.close.jwk as Credential["jwk"]] });

/** The owner's verified key log as of now, or null when the owner has none. A stored log that fails verification throws. */
export async function keyLogState(d: Deps, ownerDid: string): Promise<KeyLogState | null> {
  const id = idOf(d, ownerDid);
  if (!id) return null;
  const log = await rows(d, id);
  if (!log.length) return null;
  const r = verifyKeyLog(ownerDid, log.map((e) => e.line), log.map((e) => e.first_seen_at), verifyOpts(d, now()));
  if (!r.ok) throw new Error(`stored key log ${ownerDid} fails verification at seq ${r.seq}: ${r.error} ${r.message}`);
  return r.state;
}

/** Low S (s <= n/2), as key log entries require: a signer whose s is high sends n - s (test-vectors/keylog-1). */
export function lowS(sig: Uint8Array): Uint8Array {
  const s = BigInt(`0x${Buffer.from(sig.subarray(32)).toString("hex")}`);
  if (s <= N >> 1n) return sig;
  const out = new Uint8Array(sig);
  out.set(Buffer.from((N - s).toString(16).padStart(64, "0"), "hex"), 32);
  return out;
}

/** Appends the service's `close` entry (account deletion), signed with the P-256 close key. No entry is accepted after it. */
export async function closeKeyLog(d: Deps, ownerDid: string): Promise<void> {
  const id = idOf(d, ownerDid) ?? fail(404, "not_found", "no such owner");
  const log = await rows(d, id);
  if (!log.length) fail(404, "not_found", "no such key log");
  const last = log[log.length - 1];
  const unsigned = { v: 1, seq: last.seq + 1, prev: last.hash, op: "close", ts: now(), body: {} };
  // The close signer hashes what it is given with SHA-256: ECDSA over SHA-256(JCS of the entry without auth), the entry digest.
  const sig = lowS(await d.keys.close.sign(new TextEncoder().encode(canonicalize(unsigned))));
  const line = canonicalize({ ...unsigned, auth: { kid: d.keys.close.kid, form: "p256", signature: Buffer.from(sig).toString("base64url") } });
  await append(d, id, line, { service: true });
}

interface Appended { seq: number; hash: string; first_seen_at: number; effective_at: number }

/**
 * Verifies `line` as the next entry of log `id` and stores it with this service's first_seen_at. Genesis needs `account`
 * (the signed-in owner). Returns the stored entry; an identical line already in the log returns what was stored.
 */
async function append(d: Deps, id: string, line: string, o: { account?: string; service?: boolean }): Promise<Appended> {
  let entry: any;
  try { entry = JSON.parse(line); } catch { fail(422, "invalid_entry", "malformed: not JSON"); }
  if (!entry || typeof entry !== "object" || !Number.isSafeInteger(entry.seq)) fail(422, "invalid_entry", "malformed: an entry has a seq");
  if (entry.op === "close" && !o.service) fail(403, "forbidden", "close is written only by the account service");
  const did = ownerDidOf(d, id);
  const log = await rows(d, id);
  if (entry.op === "genesis") {
    if (!o.account) fail(401, "unauthorized", "genesis needs the owner's bearer token");
    if (base32(sha256(line)) !== id) fail(400, "bad_request", "the id must be the lowercase base32 of SHA-256(line)");
  } else if (!log.length) {
    fail(404, "not_found", "no such key log");
  }
  const same = log.find((e) => e.seq === entry.seq);
  if (same?.line === line) {
    const stored = await d.db.first<{ effective_at: number }>("SELECT effective_at FROM keylog_entries WHERE owner_id = $1 AND seq = $2", [id, same.seq]);
    return { seq: same.seq, hash: same.hash, first_seen_at: same.first_seen_at, effective_at: Number(stored!.effective_at) };
  }
  if (log.length && (await d.db.first("SELECT 1 FROM keylog_entries WHERE owner_id = $1 AND op = 'close'", [id]))) fail(410, "log_closed", "this key log is closed");
  if (entry.seq !== log.length + 1) fail(409, "seq_conflict", `the next seq is ${log.length + 1}; read the log and sign again`);
  if (entry.op === "genesis") await rootIsTheAccountsPasskey(d, o.account!, entry.body?.root);
  for (const c of credentialsIn(entry)) await receiptHolds(d, c);

  const t = Math.max(now(), log.at(-1)?.first_seen_at ?? 0);
  const r = verifyKeyLog(did, [...log.map((e) => e.line), line], [...log.map((e) => e.first_seen_at), t], verifyOpts(d, t));
  if (!r.ok) {
    if (r.seq <= log.length) throw new Error(`stored key log ${did} fails verification at seq ${r.seq}: ${r.error} ${r.message}`);
    if (r.error === "closed") fail(410, "log_closed", "this key log is closed");
    fail(422, "invalid_entry", `${r.error}: ${r.message}`);
  }
  const state = r.ok ? r.state : null!;
  const delayed = (entry.op === "recover" || entry.op === "replace_root") && state.pending.some((p) => p.seq === entry.seq);
  const out: Appended = { seq: entry.seq, hash: sha256Hex(line), first_seen_at: t, effective_at: delayed ? t + DAY : t };
  const accountId = await d.db.tx(async (tx) => {
    if (entry.op === "genesis") {
      const set = await tx.run("UPDATE accounts SET owner_did = $2 WHERE id = $1 AND owner_did IS NULL AND deleted_at IS NULL", [o.account, did]);
      if (!set.changes) fail(403, "log_exists", "this account already has a key log");
    }
    const ins = await tx.run(
      "INSERT INTO keylog_entries (owner_id, seq, line, hash, op, first_seen_at, effective_at) VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT DO NOTHING",
      [id, out.seq, line, out.hash, entry.op, out.first_seen_at, out.effective_at]);
    if (!ins.changes) fail(409, "seq_conflict", "another entry took this seq; read the log and sign again");
    return (await tx.first<{ id: string }>("SELECT id FROM accounts WHERE owner_did = $1", [did]))?.id ?? null;
  });
  if (accountId && (entry.op === "revoke" || entry.op === "recover" || entry.op === "replace_root")) {
    const what = { revoke: "An approver was removed from", recover: "A recovery was started on", replace_root: "A new root passkey was added to" }[entry.op as "revoke"];
    const when = delayed ? ` It takes effect on ${new Date(out.effective_at * 1000).toUTCString()} unless an approver cancels it in the app.` : "";
    await notifyOwner(d, accountId, {
      type: `keylog.${entry.op}`, id: String(out.seq),
      email: { subject: "A change to your OpenEntity approvers", text: `${what} your OpenEntity account.${when}\n\nIf this was not you, open the OpenEntity app now.` },
    });
  }
  if (accountId) await settleEnrollments(d, accountId, id, entry, out, delayed);
  const added = entry.op === "add_approver" ? entry.body.approver : null;
  const event = {
    genesis: ["owner_key_log_created", { approver_kind: entry.body?.approver ? entry.body.approver.type : "root_only" }],
    add_approver: added && ["approver_added", { platform: added.platform ?? "web", storage: added.type === "webauthn" ? "passkey" : added.key_storage ?? "tee", strong_integrity: !!added.integrity?.strong }],
    recover: ["recovery_started", {}], replace_root: ["root_replace_started", {}],
  }[entry.op as string] as [string, Record<string, string | boolean>] | undefined;
  if (event) await track(d, event[0], event[1], { owner: did });
  return out;
}

/** An appended entry completes the enrollment of the credential it carries, or cancels the one its target carried. */
async function settleEnrollments(d: Deps, accountId: string, id: string, entry: any, out: Appended, delayed: boolean) {
  const settled: string[] = [];
  if (entry.op === "cancel") {
    const target = await d.db.first<{ seq: number }>("SELECT seq FROM keylog_entries WHERE owner_id = $1 AND hash = $2", [id, entry.body.target]);
    if (target) for (const r of await d.db.all<{ id: string }>("UPDATE enrollments SET state = 'cancelled' WHERE account_id = $1 AND seq = $2 AND state = 'waiting' RETURNING id", [accountId, target.seq])) settled.push(r.id);
  } else {
    const purpose = entry.op === "replace_root" ? "root" : "approver";
    for (const c of credentialsIn(entry)) {
      const rows = await d.db.all<{ id: string }>(
        "UPDATE enrollments SET state = $4, seq = $5, effective_at = $6 WHERE account_id = $1 AND kid = $2 AND purpose = $3 AND state = 'pending' RETURNING id",
        [accountId, c.kid, purpose, delayed ? "waiting" : "completed", out.seq, out.effective_at]);
      settled.push(...rows.map((r) => r.id));
    }
  }
  for (const e of settled) await notifyOwner(d, accountId, { type: "enrollment.completed", id: e });
}

/** Credentials an entry introduces. */
const credentialsIn = (e: any): any[] =>
  ({ genesis: [e.body?.root, e.body?.approver], add_approver: [e.body?.approver], recover: e.body?.approvers ?? [], replace_root: [e.body?.root] } as Record<string, unknown[]>)[e.op]
    ?.filter((c) => c && typeof c === "object") ?? [];

/** Genesis carries the root passkey this account registered (POST /v1/auth/passkey/verify, mode register), key and all. */
async function rootIsTheAccountsPasskey(d: Deps, accountId: string, root: any) {
  const m = await d.db.first<{ data: string }>("SELECT data FROM methods WHERE account_id = $1 AND type = 'passkey' AND subject = $2", [accountId, String(root?.credential_id ?? "")]);
  const jwk = m ? JSON.parse(m.data).jwk : null;
  if (!jwk || jwk.x !== root?.jwk?.x || jwk.y !== root?.jwk?.y) fail(422, "invalid_entry", "the genesis root must be a passkey registered to this account");
}

/** RFC 7638 thumbprint of a P-256 public JWK of exactly kty, crv, x and y with a point on the curve; null otherwise. */
export function thumbprint(j: any): string | null {
  if (!j || typeof j !== "object" || Object.keys(j).sort().join() !== "crv,kty,x,y" || j.kty !== "EC" || j.crv !== "P-256") return null;
  if (![j.x, j.y].every((v) => typeof v === "string" && /^[A-Za-z0-9_-]{43}$/.test(v) && Buffer.from(v, "base64url").toString("base64url") === v)) return null;
  try { createPublicKey({ key: j, format: "jwk" }); } catch { return null; }
  return createHash("sha256").update(`{"crv":"P-256","kty":"EC","x":"${j.x}","y":"${j.y}"}`).digest("base64url");
}

/** Every kid any entry of the log introduced (a key enters a log once). */
async function kidsIn(d: Deps, id: string): Promise<Set<string>> {
  const kids = new Set<string>();
  for (const e of await rows(d, id)) for (const c of credentialsIn(JSON.parse(e.line))) kids.add(c.kid);
  return kids;
}

/**
 * A device key that claims a verified attestation must carry this service's receipt for it (POST /v1/keylog/attestations).
 * `required` (enrollments): every device key needs one, else 403 attestation_invalid.
 */
async function receiptHolds(d: Deps, c: any, required = false) {
  if (c.type !== "p256" || (!required && c.attestation?.verified !== true)) return;
  const bad = (why: string): never => required ? fail(403, "attestation_invalid", why) : fail(422, "invalid_entry", `attestation: ${why}`);
  if (c.attestation?.verified !== true) bad("a device key needs a verified attestation from POST /v1/keylog/attestations");
  const jws = c.attestation.receipt;
  if (typeof jws !== "string") bad("verified needs the receipt from POST /v1/keylog/attestations");
  let claims: any;
  try {
    const { payload, protectedHeader: h } = await compactVerify(jws, await importJWK({ ...d.keys.did.jwk, alg: "EdDSA" }));
    if (h.typ !== "oe-key-attestation+jwt" || h.kid !== `did:web:${d.host}#${d.keys.did.kid}`) throw 0;
    claims = JSON.parse(new TextDecoder().decode(payload));
  } catch { bad("the receipt is not this service's"); }
  if (claims.iss !== `did:web:${d.host}` || claims.kid !== c.kid || claims.verified !== true) bad("the receipt names another key");
  if (claims.type !== c.attestation.type || claims.key_storage !== c.key_storage || claims.platform !== c.platform) bad("the credential does not match its receipt");
  if (JSON.stringify(claims.integrity ?? null) !== JSON.stringify(c.integrity ?? null)) bad("the integrity verdict does not match the receipt");
}

interface EnrollmentRow { id: string; account_id: string; purpose: string; kid: string; credential: string; code: string; state: string; seq: number | null; effective_at: number | null; created_at: number; expires_at: number }

/** Enrollment (openapi.yaml): pending ones past 10 minutes read as expired, waiting ones past effective_at as completed. */
function enrollmentView(e: EnrollmentRow) {
  const t = now();
  const state = e.state === "pending" && Number(e.expires_at) <= t ? "expired" : e.state === "waiting" && Number(e.effective_at) <= t ? "completed" : e.state;
  return {
    enrollment_id: e.id, purpose: e.purpose, code: e.code, credential: JSON.parse(e.credential), state,
    seq: e.seq === null ? null : Number(e.seq), effective_at: e.effective_at === null ? null : Number(e.effective_at),
    created_at: Number(e.created_at), expires_at: Number(e.expires_at),
  };
}

export function routes(app: Hono, d: Deps) {
  // ---------------------------------------------------------------- attestation receipts (PLAN 3.2, ADR 0007)
  app.post("/v1/keylog/attestations", async (c) => {
    const o = await bearer(c, d);
    const b = await json(c);
    const raw = str(b.nonce, "nonce", 64);
    if (b.platform !== "ios" && b.platform !== "android") fail(400, "bad_request", "platform is ios or android");
    const kid = thumbprint(b.jwk) ?? fail(400, "bad_request", "jwk must be a P-256 public key {kty, crv, x, y}");
    if ((await bump(d.db, `attest:${o.accountId}`, String(Math.floor(now() / 3600)))) > ATTESTATIONS_PER_HOUR) fail(429, "rate_limited", "too many attestations this hour", { retry_after: 3600 });
    // The nonce is single use and must have been issued to this install.
    const t = now();
    const n = await d.db.first<{ platform: string; install_id: string | null }>("UPDATE auth_nonces SET used_at = $2 WHERE hash = $1 AND used_at IS NULL AND expires_at > $2 RETURNING platform, install_id", [nonceHash(raw), t]);
    const s = await d.db.first<{ install_id: string | null }>("SELECT install_id FROM sessions WHERE id = $1", [o.sid]);
    if (!n || n.platform !== b.platform || !n.install_id || n.install_id !== s?.install_id) fail(401, "nonce_invalid", "the nonce is unknown, expired, used, or was issued to another install");
    if (b.platform === "android") {
      // The approver key's own attestation (biometric on every use), and Play Integrity with requestHash = kid.
      const k = verifyAndroidKey({ chain: b.android?.certificate_chain, biometric: true, packageName: BUNDLE_ID, revoked: await revokedSerials(d), roots: d.attestRoots?.google });
      if (k.jwk.x !== b.jwk.x || k.jwk.y !== b.jwk.y) fail(403, "attestation_invalid", "the attested key is not jwk");
      if (!k.challenge.equals(Buffer.from(raw))) fail(403, "attestation_invalid", "the attestation challenge is not the nonce");
      const verdict = (await integrity(d, b.android?.integrity_token, kid, "approver"))!;
      const claims = receiptClaims(d, kid, "android", { type: "android_key", key_storage: k.keyStorage, integrity: verdict });
      return c.json({ receipt: await receipt(d, claims), claims });
    }
    const aa = b.app_attest;
    if (!aa || typeof aa.key_id !== "string" || aa.key_id.length > 128 || typeof aa.attestation_object !== "string") fail(400, "bad_request", "app_attest needs key_id and attestation_object");
    verifyAppAttest({
      attestationObject: Buffer.from(aa.attestation_object, "base64url"), keyId: aa.key_id,
      clientDataHash: createHash("sha256").update(`${raw}|${kid}`).digest(), production: d.stage === "production", roots: d.attestRoots?.apple,
    });
    const claims = receiptClaims(d, kid, "ios", { type: "app_attest", key_storage: "secure_enclave", integrity: null });
    return c.json({ receipt: await receipt(d, claims), claims });
  });

  // ---------------------------------------------------------------- enrollments (Add an approver, Add a backup, Replace root)
  app.post("/v1/keylog/enrollments", async (c) => {
    const o = await bearer(c, d);
    if (!o.ownerDid) fail(403, "key_log_required", "this account has no key log yet");
    const b = await json(c);
    if (Object.keys(b).sort().join() !== "credential,purpose" || (b.purpose !== "approver" && b.purpose !== "root")) fail(400, "bad_request", "send exactly {purpose: approver or root, credential}");
    const cred = b.credential;
    if (!cred || typeof cred !== "object" || (cred.type !== "p256" && cred.type !== "webauthn") || thumbprint(cred.jwk) !== cred.kid) fail(400, "bad_request", "credential needs type p256 or webauthn, a P-256 jwk and kid = its RFC 7638 thumbprint");
    if (b.purpose === "root" && cred.type !== "webauthn") fail(400, "bad_request", "a root is a passkey (type webauthn)");
    if (cred.type === "webauthn") {
      if (cred.rp_id !== d.rp.id || typeof cred.credential_id !== "string") fail(400, "bad_request", `a passkey needs credential_id and rp_id ${d.rp.id}`);
      // A passkey registered after the key log is kept as pending (signin.ts): an approver or root key, not a sign-in method.
      const m = await d.db.first<{ data: string }>("SELECT data FROM methods WHERE account_id = $1 AND type = 'passkey' AND subject = $2", [o.accountId, cred.credential_id]);
      const data = m ? JSON.parse(m.data) : null;
      if (!data?.pending || data.jwk?.x !== cred.jwk.x || data.jwk?.y !== cred.jwk.y) fail(400, "bad_request", "register the passkey with this account first (POST /v1/auth/passkey/verify, mode register)");
    }
    await receiptHolds(d, cred, true);
    const id = idOf(d, o.ownerDid!)!;
    if ((await kidsIn(d, id)).has(cred.kid)) fail(409, "key_reused", "this key is already in the key log; a key enters a log once");
    const t = now();
    const pending = await d.db.first<{ n: number }>("SELECT count(*) AS n FROM enrollments WHERE account_id = $1 AND state = 'pending' AND expires_at > $2", [o.accountId, t]);
    if (Number(pending!.n) >= PENDING_MAX) fail(409, "too_many_pending", `at most ${PENDING_MAX} pending enrollments; finish or withdraw one`);
    const row: EnrollmentRow = {
      id: newId("enr"), account_id: o.accountId, purpose: b.purpose, kid: cred.kid, credential: JSON.stringify(cred),
      code: String(randomInt(0, 1_000_000)).padStart(6, "0"), state: "pending", seq: null, effective_at: null, created_at: t, expires_at: t + ENROLL_TTL,
    };
    await d.db.run("INSERT INTO enrollments (id, account_id, purpose, kid, credential, code, state, created_at, expires_at) VALUES ($1, $2, $3, $4, $5, $6, 'pending', $7, $8)",
      [row.id, row.account_id, row.purpose, row.kid, row.credential, row.code, row.created_at, row.expires_at]);
    await notifyOwner(d, o.accountId, { type: "enrollment.pending", id: row.id });
    return c.json(enrollmentView(row), 201);
  });

  app.get("/v1/keylog/enrollments", async (c) => {
    const o = await bearer(c, d);
    const list = await d.db.all<EnrollmentRow>("SELECT * FROM enrollments WHERE account_id = $1 AND created_at > $2 ORDER BY created_at DESC, id DESC LIMIT 50", [o.accountId, now() - DAY]);
    return c.json({ enrollments: list.map(enrollmentView) });
  });

  const ownEnrollment = async (c: Context) => {
    const o = await bearer(c, d);
    return (await d.db.first<EnrollmentRow>("SELECT * FROM enrollments WHERE id = $1 AND account_id = $2", [c.req.param("id"), o.accountId])) ?? fail(404, "not_found", "no such enrollment");
  };
  app.get("/v1/keylog/enrollments/:id", async (c) => c.json(enrollmentView(await ownEnrollment(c))));
  app.delete("/v1/keylog/enrollments/:id", async (c) => {
    const e = await ownEnrollment(c);
    const r = await d.db.run("UPDATE enrollments SET state = 'cancelled' WHERE id = $1 AND state = 'pending' AND expires_at > $2", [e.id, now()]);
    if (!r.changes) fail(409, "not_pending", "only a pending enrollment can be withdrawn");
    return c.body(null, 204);
  });

  // ---------------------------------------------------------------- the log
  const idParam = (c: Context) => {
    const id = c.req.param("id")!;
    return ID.test(id) ? id : fail(404, "not_found", "no such key log");
  };

  app.get("/o/:id/log", async (c) => {
    const id = idParam(c);
    const from = Number(c.req.query("from") ?? 1);
    if (!Number.isSafeInteger(from) || from < 1) fail(400, "bad_request", "from must be a seq, 1 or more");
    const log = await rows(d, id);
    if (!log.length) fail(404, "not_found", "no such key log");
    const out = log.filter((e) => e.seq >= from);
    c.header("x-oe-log-head", String(log.length));
    if (out.length) c.header("x-oe-first-seen-at", out.map((e) => e.first_seen_at).join(","));
    return c.body(out.map((e) => `${e.line}\n`).join(""), 200, { "content-type": "application/jsonl; charset=utf-8" });
  });

  app.post("/o/:id/log", async (c) => {
    const id = idParam(c);
    const b = await json(c);
    if (Object.keys(b).length !== 1 || typeof b.line !== "string" || !b.line || b.line.length > 65_536) fail(400, "bad_request", "the body is exactly {line}: the entry as its JCS line");
    // Only genesis needs the owner; every other entry authenticates itself, so a stale token never blocks a revoke.
    let op: unknown;
    try { op = JSON.parse(b.line)?.op; } catch { /* append answers invalid_entry */ }
    const account = op === "genesis" ? (await bearer(c, d)).accountId : undefined;
    return c.json(await append(d, id, b.line, { account }), 201);
  });

  app.get("/o/:id/did.json", async (c) => {
    const id = idParam(c), did = ownerDidOf(d, id);
    const s = await keyLogState(d, did) ?? fail(404, "not_found", "no such owner");
    const creds = s.closed ? [] : [s.root, ...s.approvers.filter((a) => a.kid !== s.root.kid)];
    const ref = (k: Credential) => `${did}#${k.kid}`;
    return c.json({
      "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/jwk/v1"],
      id: did,
      verificationMethod: creds.map((k) => ({ id: ref(k), type: "JsonWebKey", controller: did, publicKeyJwk: k.jwk })),
      authentication: s.closed ? [] : s.approvers.map(ref),
      assertionMethod: s.closed ? [] : s.approvers.map(ref),
      service: [{ id: `${did}#keylog`, type: "OpenEntityKeyLog", serviceEndpoint: `https://${d.host}/o/${id}/log` }],
    }, 200, { "cache-control": "public, max-age=60" });
  });
}
