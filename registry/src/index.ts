// Open Entity reference registry (spec section 10, PRD sections 7.7, 8, 9).
import { Hono, type Context } from "hono";
import { cors } from "hono/cors";
import {
  DECLARATION_SHA256, DECLARATION_VERSION, SPEC, buildDeclaration, buildDocument, canonicalize, checkStamp, checkTimestamp,
  generateKeyPair, normalizeEid, noteVkey, recordEntryHash, sha256Hex, signObject, validate, verifyObject, verifyProof, type Proof,
} from "./sdk.ts";
import { type Env, REGISTRY_DID, LOG_ORIGIN, b64, nowIso } from "./env.ts";
import { LAST_INDEX, consistencyProof, inclusionProof, incorporate, latestSize, leafFor, leafJson, registryKey, snapshot, tileIndex, treeRoot, type LeafRow } from "./log.ts";
import { platformDomain, resolveDid, resolver, verifyAlias } from "./aliases.ts";

type C = Context<{ Bindings: Env }>;
class HttpError extends Error {
  constructor(public status: number, public code: string, message: string) { super(message); }
}
const fail = (status: number, code: string, message: string): never => { throw new HttpError(status, code, message); };

export const LIMITS = {
  writes_per_ip_per_minute: 60, writes_per_ip_per_day: 2000, document_versions_per_eid_per_minute: 1,
  record_entries_per_eid_per_day: 1000, record_batch_max: 100, record_entry_max_bytes: 16384, document_max_bytes: 65536,
  log_entries_per_call: 1000, stamp_max_age_seconds: 600,
};
const DECLARATION_NOTE = "The Declaration is a statement of the practices the entity commits to. It is not a warranty, a contract or a claim about the entity's capabilities.";
const LEVEL = (n: number | null) => (n === null ? null : `L${n}`);
const today = () => nowIso().slice(0, 10);

export const app = new Hono<{ Bindings: Env }>().basePath("/v1");
app.use("*", cors());
app.onError((e, c) => {
  if (e instanceof HttpError) return c.json({ error: e.code, message: e.message }, e.status as 400);
  if (/UNIQUE constraint failed/.test(String(e))) return c.json({ error: "conflict", message: "object already exists or was accepted concurrently" }, 409);
  console.error(e);
  return c.json({ error: "internal", message: "internal error" }, 500);
});
app.notFound((c) => c.json({ error: "not_found", message: "no such endpoint" }, 404));

// ---------- shared guards ----------

async function readJson(c: C): Promise<any> {
  const text = await c.req.text();
  if (text.length > 2_000_000) fail(413, "too_large", "request body exceeds 2 MB");
  try { return JSON.parse(text); } catch { return fail(400, "bad_json", "body is not valid JSON"); }
}
const salted = (env: Env, s: string) => sha256Hex(`${env.HASH_SALT ?? "openentity-dev-salt"}:${s}`);
/** Adds n to a counter and returns the new total. */
async function bump(db: D1Database, key: string, window: string, n = 1): Promise<number> {
  return (await db.prepare("INSERT INTO rate_events (key, window_start, count) VALUES (?, ?, ?) ON CONFLICT (key, window_start) DO UPDATE SET count = count + excluded.count RETURNING count").bind(key, window, n).first<number>("count"))!;
}
/** Every write: per-IP limits, then a single-use proof-of-work stamp naming the writing EID (spec 10.4). */
async function writeGuard(c: C, eid: string) {
  const env = c.env;
  const ip = await salted(env, c.req.header("cf-connecting-ip") ?? "unknown");
  if (env.WRITE_LIMITER && !(await env.WRITE_LIMITER.limit({ key: ip })).success) fail(429, "rate_limited", `at most ${LIMITS.writes_per_ip_per_minute} writes per minute per IP`);
  const daily = Number(env.IP_DAILY_LIMIT ?? LIMITS.writes_per_ip_per_day);
  if ((await bump(env.DB, `ip:${ip}`, today())) > daily) fail(429, "rate_limited", `at most ${daily} writes per day per IP`);
  const stamp = c.req.header("x-oe-stamp");
  if (!stamp) fail(400, "stamp_required", "write endpoints require an X-OE-Stamp header; see GET /v1/spec for the bits");
  const err = await checkStamp(stamp!, Number(env.STAMP_BITS), eid);
  if (err) fail(400, "stamp_invalid", err);
  if ((await bump(env.DB, `stamp:${await sha256Hex(stamp!)}`, stamp!.split(":")[2].slice(0, 10))) > 1) fail(409, "stamp_reused", "each stamp is accepted once");
}
function schema(type: string, obj: unknown) {
  const r = validate(type as "EntityDocument", obj);
  if (!r.ok) fail(422, "schema_invalid", `${type}: ${r.errors.join("; ")}`);
}
function window(created: string, what: string) {
  const err = checkTimestamp(created);
  if (err) fail(422, "timestamp_invalid", `${what}: ${err}`);
}
async function signedBy(obj: { proof?: Proof }, did: string, what: string) {
  const r = await verifyObject(obj, resolver);
  if (!r.ok || normalizeEid(r.signer ?? "") !== did) fail(422, "signature_invalid", `${what}: ${r.error ?? `signed by ${r.signer}, expected ${did}`}`);
}
async function entity(db: D1Database, eid: string): Promise<any> {
  return db.prepare("SELECT * FROM entities WHERE eid = ?").bind(eid).first();
}
async function mustEntity(db: D1Database, eid: string) {
  return (await entity(db, eid)) ?? fail(404, "entity_not_found", `no entity ${eid}`);
}
const sha = (o: unknown) => sha256Hex(canonicalize(o));
function receipt(c: C, idx: number, l: { leaf: object; leaf_hash: string }) {
  return { log_index: idx, receipt: { leaf: l.leaf, leaf_hash: l.leaf_hash, log_proof: `https://${c.env.REGISTRY_HOST}/v1/log/proof/${idx}` } };
}
const firstIdx = (res: D1Result[]) => (res[0].results[0] as { idx: number }).idx;

// ---------- levels (spec 2.2, 8.4) ----------

async function lineage(db: D1Database, eid: string): Promise<string[]> {
  const chain = [eid];
  for (let i = 0; i < 10; i++) {
    const p = await db.prepare("SELECT predecessor_eid FROM entities WHERE eid = ?").bind(chain[chain.length - 1]).first<string>("predecessor_eid");
    if (!p) break;
    chain.push(p);
  }
  return chain;
}
const IN = (xs: string[]) => xs.map(() => "?").join(",");

export async function computeLevel(db: D1Database, eid: string): Promise<{ level: number | null; label: string | null; supporting: any[] }> {
  const e = await entity(db, eid);
  const chain = await lineage(db, eid);
  const decl = await db.prepare(`SELECT 1 FROM declarations WHERE eid IN (${IN(chain)}) AND withdrawn_at IS NULL LIMIT 1`).bind(...chain).first();
  if (!e || e.withdrawn_at || !decl) return { level: null, label: null, supporting: [] };
  let level = (await db.prepare("SELECT 1 FROM aliases WHERE eid = ? AND status = 'verified' LIMIT 1").bind(eid).first()) ? 1 : 0;
  const atts = (await db.prepare(`SELECT a.issuer, a.claim_type, a.json FROM attestations a JOIN observers o ON o.did = a.issuer WHERE a.subject IN (${IN(chain)}) AND a.revoked_at IS NULL AND a.expires > ?`).bind(...chain, nowIso()).all<any>()).results;
  if (!atts.length) return { level, label: null, supporting: [] };
  const stageEntity = atts.filter((a) => { const j = JSON.parse(a.json); return a.claim_type === "stage" && j.claim?.stage === "entity" && String(j.claim?.profile ?? "").startsWith("entity-framework/"); });
  const supporting = stageEntity.length ? stageEntity : atts;
  level = stageEntity.length ? 3 : 2;
  const fp = await firstPartyIssuers(db, eid);
  return { level, label: supporting.every((a) => fp(a.issuer)) ? "first-party" : "independent", supporting };
}
/** An issuer is first-party when it is the entity itself or its operator: the domain of operator.contact or of a verified platform alias. */
async function firstPartyIssuers(db: D1Database, eid: string): Promise<(issuer: string) => boolean> {
  const doc = await db.prepare("SELECT json FROM documents WHERE eid = ? ORDER BY seq DESC LIMIT 1").bind(eid).first<string>("json");
  const domains = new Set<string>();
  const contact = doc ? String(JSON.parse(doc).operator?.contact ?? "") : "";
  if (contact.includes("@")) domains.add(contact.split("@")[1].toLowerCase());
  for (const a of (await db.prepare("SELECT value FROM aliases WHERE eid = ? AND type = 'platform' AND status = 'verified'").bind(eid).all<{ value: string }>()).results) domains.add(platformDomain(a.value));
  return (issuer) => issuer === eid || (issuer.startsWith("did:web:") && domains.has(issuer.slice(8).split(":")[0]));
}
async function refreshLevel(db: D1Database, eid: string) {
  const l = await computeLevel(db, eid);
  await db.prepare("UPDATE entities SET level = ?, level_label = ? WHERE eid = ?").bind(l.level, l.label, eid).run();
  const succ = await db.prepare("SELECT successor_eid FROM entities WHERE eid = ?").bind(eid).first<string>("successor_eid");
  if (succ) {
    const s = await computeLevel(db, succ);
    await db.prepare("UPDATE entities SET level = ?, level_label = ? WHERE eid = ?").bind(s.level, s.label, succ).run();
  }
  return l;
}

// ---------- spec ----------

app.get("/spec", async (c) => {
  let registry: Record<string, string> = { did: REGISTRY_DID, log_origin: LOG_ORIGIN };
  if (c.env.REGISTRY_KEY_JWK) {
    const kp = await registryKey(c.env);
    registry = { ...registry, publicKeyMultibase: kp.did.slice(8), note_key: noteVkey(LOG_ORIGIN, kp.publicKey) };
  }
  return c.json({
    spec: SPEC, spec_version: "1.0-draft", spec_url: "https://openentity.org/spec/1.0",
    declaration: { version: DECLARATION_VERSION, sha256: DECLARATION_SHA256, url: "https://openentity.org/spec/declaration/1.0.txt" },
    stamp_bits: Number(c.env.STAMP_BITS), stamp_header: "X-OE-Stamp: 1:<bits>:<created>:<eid>:<nonce>",
    registry, limits: LIMITS,
  });
});

// ---------- adopt (spec 10.2, 6.3, 10.6) ----------

async function adopt(c: C, document: any, declaration: any) {
  const db = c.env.DB;
  const eid = normalizeEid(String(document.eid));
  if (normalizeEid(String(declaration.eid)) !== eid) fail(422, "eid_mismatch", "document and declaration name different EIDs");
  if (declaration.declaration_version !== DECLARATION_VERSION || declaration.text_sha256 !== DECLARATION_SHA256)
    fail(422, "declaration_hash_mismatch", `text_sha256 must be ${DECLARATION_SHA256} for declaration_version ${DECLARATION_VERSION}`);
  window(declaration.created, "declaration");
  window(document.updated, "document");
  if (!(await resolveDid(eid))) fail(422, "unsupported_method", `cannot resolve ${eid}`);
  await signedBy(document, eid, "document");
  await signedBy(declaration, eid, "declaration");
  if (await db.prepare("SELECT 1 FROM declarations WHERE eid = ? AND version = ?").bind(eid, declaration.declaration_version).first())
    fail(409, "declaration_exists", "this EID already has a Declaration of this version");
  if (await entity(db, eid)) fail(409, "entity_exists", "this EID is already listed");

  const now = nowIso();
  const dl = await leafFor(db, "Declaration", eid, await sha(declaration), now);
  const doc = await leafFor(db, "EntityDocument", eid, await sha(document), now);
  const res = await db.batch([
    dl.stmt,
    db.prepare(`INSERT INTO declarations (eid, version, json, sha256, received_at, log_index) VALUES (?, ?, ?, ?, ?, ${LAST_INDEX})`).bind(eid, declaration.declaration_version, JSON.stringify(declaration), await sha(declaration), now),
    doc.stmt,
    db.prepare(`INSERT INTO documents (eid, seq, json, sha256, received_at, log_index) VALUES (?, ?, ?, ?, ?, ${LAST_INDEX})`).bind(eid, document.seq, JSON.stringify(document), await sha(document), now),
    db.prepare(`INSERT INTO entities (eid, root_method, name, level, created, updated, custody, latest_seq, adopted_log_index) VALUES (?, ?, ?, 0, ?, ?, ?, ?, ${LAST_INDEX} - 1)`)
      .bind(eid, eid.split(":")[1], document.name, now, now, document.operator?.custody ?? null, document.seq),
  ]);
  await c.env.LOG_QUEUE.send({ t: "leaf" });
  const idx = firstIdx(res);
  const base = `https://${c.env.REGISTRY_HOST}/v1/entities/${eid}`;
  return { eid, level: "L0", ...receipt(c, idx, dl), urls: { entity: base, document: `${base}/document`, log_proof: `https://${c.env.REGISTRY_HOST}/v1/log/proof/${idx}` } };
}

async function encryptKey(env: Env, jwk: JsonWebKey): Promise<string> {
  const raw = Uint8Array.from(atob(env.CUSTODY_KEY!), (ch) => ch.charCodeAt(0));
  const key = await crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(JSON.stringify(jwk))));
  return `${b64(iv)}.${b64(ct)}`;
}

app.post("/adopt", async (c) => {
  const body = await readJson(c);
  if (body?.custodial === true) {
    // Custodial mode (spec 10.6): the registry generates the key, returns it once, keeps a copy only on request.
    await writeGuard(c, REGISTRY_DID);
    if (body.keep_copy && !c.env.CUSTODY_KEY) fail(503, "custody_unavailable", "this registry is not configured to keep custodial keys");
    const kp = await generateKeyPair();
    const document = await signObject(buildDocument({ kp, name: String(body.name ?? ""), description: String(body.description || "An entity whose key is held by the registry in custodial mode."), operator: { kind: "none", custody: "registry", can_change: [] } }), kp);
    schema("EntityDocument", document);
    const declaration = await signObject(buildDeclaration({ eid: kp.did, name: String(body.name) }), kp);
    const out = await adopt(c, document, declaration);
    if (body.keep_copy) await c.env.DB.prepare("INSERT INTO custodial_keys (eid, enc_key, created) VALUES (?, ?, ?)").bind(kp.did, await encryptKey(c.env, kp.privateJwk), nowIso()).run();
    return c.json({ ...out, custodial: { private_key_jwk: kp.privateJwk, kept_copy: !!body.keep_copy, warning: "This private key is shown once. Store it; move to self-custody with a rotation Continuity Link." } }, 201);
  }
  const { document, declaration } = body ?? {};
  await writeGuard(c, normalizeEid(String(document?.eid ?? "")));
  schema("EntityDocument", document);
  schema("Declaration", declaration);
  return c.json(await adopt(c, document, declaration), 201);
});

// ---------- entity reads ----------

app.get("/entities", async (c) => {
  const q = c.req.query();
  const minLevel = Number(/\d/.exec(q.level ?? "1")?.[0] ?? 1);
  const where = ["suppressed = 0", "level >= ?"], args: unknown[] = [minLevel];
  if (q.q) { where.push("(name LIKE ? OR eid = ?)"); args.push(`%${q.q}%`, q.q); }
  if (q.since) { where.push("created >= ?"); args.push(q.since); }
  if (q.alias_type) { where.push("EXISTS (SELECT 1 FROM aliases a WHERE a.eid = entities.eid AND a.type = ? AND a.status = 'verified')"); args.push(q.alias_type); }
  const page = Math.max(0, Number(q.page ?? 0) | 0);
  const rows = (await c.env.DB.prepare(`SELECT eid, name, level, level_label, created, adopted_log_index, withdrawn_at FROM entities WHERE ${where.join(" AND ")} ORDER BY created DESC, eid LIMIT 51 OFFSET ?`).bind(...args, page * 50).all<any>()).results;
  return c.json({
    entities: rows.slice(0, 50).map((r) => ({ eid: r.eid, name: r.name, level: LEVEL(r.level), level_label: r.level_label, created: r.created, log_index: r.adopted_log_index, withdrawn: !!r.withdrawn_at })),
    page, next_page: rows.length > 50 ? page + 1 : null,
  });
});

app.get("/entities/:eid", async (c) => {
  const db = c.env.DB, eid = normalizeEid(c.req.param("eid"));
  const e = await mustEntity(db, eid);
  const doc = await db.prepare("SELECT json FROM documents WHERE eid = ? ORDER BY seq DESC LIMIT 1").bind(eid).first<string>("json");
  const chain = await lineage(db, eid);
  const decl = await db.prepare(`SELECT eid, json, log_index, withdrawn_at FROM declarations WHERE eid IN (${IN(chain)}) ORDER BY received_at DESC LIMIT 1`).bind(...chain).first<any>();
  const aliases = (await db.prepare("SELECT type, value, status, verified_at, log_index FROM aliases WHERE eid = ?").bind(eid).all()).results;
  const attestations = await db.prepare(`SELECT COUNT(*) AS n FROM attestations WHERE subject IN (${IN(chain)}) AND revoked_at IS NULL`).bind(...chain).first<number>("n");
  return c.json({
    eid, name: e.name, document: doc ? JSON.parse(doc) : null,
    declaration: decl ? JSON.parse(decl.json) : null, declaration_note: DECLARATION_NOTE,
    declaration_inherited_from: decl && decl.eid !== eid ? decl.eid : null,
    level: LEVEL(e.level), level_label: e.level_label, aliases, log_index: e.adopted_log_index,
    lineage: { previous: e.predecessor_eid, successor: e.successor_eid, chain },
    counts: { record_entries: e.record_seq, attestations, document_versions: e.latest_seq },
    record_head: e.record_head_hash ? { seq: e.record_seq, hash: e.record_head_hash } : null,
    withdrawn: !!e.withdrawn_at, withdrawn_at: e.withdrawn_at, suppressed: !!e.suppressed, founding: !!e.founding,
    dormant: Date.parse(e.updated) < Date.now() - 365 * 86400_000, custody: e.custody, created: e.created, updated: e.updated,
  });
});

app.get("/entities/:eid/document", async (c) => {
  const eid = normalizeEid(c.req.param("eid"));
  const doc = await c.env.DB.prepare("SELECT json FROM documents WHERE eid = ? ORDER BY seq DESC LIMIT 1").bind(eid).first<string>("json");
  return doc ? c.body(doc, 200, { "content-type": "application/json" }) : fail(404, "entity_not_found", `no document for ${eid}`);
});

app.get("/entities/:eid/declaration", async (c) => {
  const eid = normalizeEid(c.req.param("eid"));
  const d = await c.env.DB.prepare("SELECT json FROM declarations WHERE eid = ? ORDER BY received_at DESC LIMIT 1").bind(eid).first<string>("json");
  return d ? c.body(d, 200, { "content-type": "application/json" }) : fail(404, "entity_not_found", `no declaration for ${eid}`);
});

app.get("/entities/:eid/record", async (c) => {
  const eid = normalizeEid(c.req.param("eid"));
  const e = await mustEntity(c.env.DB, eid);
  const after = Number(c.req.query("after") ?? 0) | 0;
  const rows = (await c.env.DB.prepare("SELECT json, log_index FROM record_entries WHERE eid = ? AND seq > ? ORDER BY seq LIMIT 1000").bind(eid, after).all<any>()).results;
  return c.json({ eid, head: e.record_head_hash ? { seq: e.record_seq, hash: e.record_head_hash } : null, entries: rows.map((r) => JSON.parse(r.json)) });
});

app.get("/entities/:eid/attestations", async (c) => {
  const db = c.env.DB, eid = normalizeEid(c.req.param("eid"));
  await mustEntity(db, eid);
  const chain = await lineage(db, eid);
  const where = [`subject IN (${IN(chain)})`], args: unknown[] = [...chain];
  const { issuer, claim_type, format } = c.req.query();
  if (issuer) { where.push("issuer = ?"); args.push(issuer); }
  if (claim_type) { where.push("claim_type = ?"); args.push(claim_type); }
  const rows = (await db.prepare(`SELECT a.*, o.did AS accredited, o.bootstrap, e.level AS issuer_level FROM attestations a LEFT JOIN observers o ON o.did = a.issuer LEFT JOIN entities e ON e.eid = a.issuer WHERE ${where.join(" AND ")} ORDER BY a.created DESC LIMIT 1000`).bind(...args).all<any>()).results;
  const fp = await firstPartyIssuers(db, eid);
  return c.json({
    eid,
    attestations: rows.map((r) => {
      const a = JSON.parse(r.json);
      const vc = { "@context": ["https://www.w3.org/ns/credentials/v2"], type: ["VerifiableCredential", "OpenEntityAttestation"], issuer: a.issuer, validFrom: a.created, validUntil: r.expires, credentialSubject: { id: a.subject, claim_type: a.claim_type, ...a.claim }, evidence: a.evidence, proof: a.proof };
      return {
        sha256: r.sha256, attestation: format === "vc" ? vc : a, issuer_level: LEVEL(r.issuer_level), accredited: !!r.accredited, bootstrap: !!r.bootstrap,
        label: fp(r.issuer) ? "first-party" : "independent", inherited_from: r.subject !== eid ? r.subject : null,
        expired: r.expires <= nowIso(), revoked_at: r.revoked_at, revocation: r.revocation_json ? JSON.parse(r.revocation_json) : null, log_index: r.log_index,
      };
    }),
  });
});

// ---------- entity writes ----------

app.put("/entities/:eid/document", async (c) => {
  const db = c.env.DB, eid = normalizeEid(c.req.param("eid"));
  const doc = await readJson(c);
  await writeGuard(c, eid);
  schema("EntityDocument", doc);
  if (normalizeEid(String(doc.eid)) !== eid) fail(422, "eid_mismatch", "document eid does not match the path");
  window(doc.updated, "document");
  await signedBy(doc, eid, "document");
  const e = await mustEntity(db, eid);
  if (doc.seq !== e.latest_seq + 1) fail(409, "seq_invalid", `seq must be ${e.latest_seq + 1}`);
  const prev = JSON.parse((await db.prepare("SELECT json FROM documents WHERE eid = ? AND seq = ?").bind(eid, e.latest_seq).first<string>("json"))!);
  if (!(doc.updated > prev.updated)) fail(409, "updated_not_increasing", `updated must be later than ${prev.updated}`);
  if ((await bump(db, `doc:${eid}`, nowIso().slice(0, 16))) > LIMITS.document_versions_per_eid_per_minute) fail(429, "rate_limited", "one document version per minute");
  const now = nowIso(), s = await sha(doc);
  const l = await leafFor(db, "EntityDocument", eid, s, now);
  const res = await db.batch([
    l.stmt,
    db.prepare(`INSERT INTO documents (eid, seq, json, sha256, received_at, log_index) VALUES (?, ?, ?, ?, ?, ${LAST_INDEX})`).bind(eid, doc.seq, JSON.stringify(doc), s, now),
    db.prepare("UPDATE entities SET name = ?, latest_seq = ?, updated = ?, custody = ? WHERE eid = ?").bind(doc.name, doc.seq, now, doc.operator?.custody ?? null, eid),
  ]);
  await c.env.LOG_QUEUE.send({ t: "leaf" });
  return c.json({ eid, seq: doc.seq, ...receipt(c, firstIdx(res), l) });
});

app.post("/entities/:eid/aliases", async (c) => {
  const db = c.env.DB, eid = normalizeEid(c.req.param("eid"));
  const body = await readJson(c);
  await writeGuard(c, eid);
  if (typeof body?.type !== "string" || typeof body?.value !== "string" || body.value.length > 300) fail(422, "schema_invalid", "body must be {type, value, proof?}");
  await mustEntity(db, eid);
  if (await db.prepare("SELECT 1 FROM aliases WHERE eid = ? AND type = ? AND value = ? AND status = 'verified'").bind(eid, body.type, body.value).first()) fail(409, "alias_exists", "alias already verified");
  const err = await verifyAlias(c.env, eid, body);
  if (err) fail(422, "alias_proof_invalid", err);
  const now = nowIso(), obj = { eid, type: body.type, value: body.value, proof: body.proof ?? null };
  const l = await leafFor(db, "Alias", eid, await sha(obj), now);
  const res = await db.batch([
    l.stmt,
    db.prepare(`INSERT OR REPLACE INTO aliases (eid, type, value, proof_json, verified_at, last_checked, status, log_index) VALUES (?, ?, ?, ?, ?, ?, 'verified', ${LAST_INDEX})`).bind(eid, body.type, body.value, JSON.stringify(obj.proof), now, now),
    db.prepare("UPDATE entities SET updated = ? WHERE eid = ?").bind(now, eid),
  ]);
  await c.env.LOG_QUEUE.send({ t: "leaf" });
  const lv = await refreshLevel(db, eid);
  return c.json({ eid, alias: { type: body.type, value: body.value, status: "verified" }, level: LEVEL(lv.level), ...receipt(c, firstIdx(res), l) }, 201);
});

app.post("/entities/:eid/record", async (c) => {
  const db = c.env.DB, eid = normalizeEid(c.req.param("eid"));
  const body = await readJson(c);
  await writeGuard(c, eid);
  const entries: any[] = body?.entries;
  if (!Array.isArray(entries) || entries.length === 0) fail(422, "schema_invalid", "body must be {entries: [...]}");
  if (entries.length > LIMITS.record_batch_max) fail(413, "batch_too_large", `at most ${LIMITS.record_batch_max} entries per request`);
  for (const en of entries) {
    schema("RecordEntry", en);
    if (normalizeEid(String(en.eid)) !== eid) fail(422, "eid_mismatch", `entry ${en.seq} names another EID`);
  }
  const e = await mustEntity(db, eid);
  let seq: number = e.record_seq, prev: string | null = e.record_head_hash ?? null;
  const hashes: string[] = [];
  for (const en of entries) {
    if (en.seq !== seq + 1) fail(409, "record_chain_broken", `expected seq ${seq + 1}, got ${en.seq}`);
    if (en.prev !== prev) fail(409, "record_chain_broken", `entry ${en.seq}: prev must be ${prev}`);
    prev = await recordEntryHash(en);
    hashes.push(prev);
    seq++;
  }
  for (const en of entries) await signedBy(en, eid, `entry ${en.seq}`);
  if ((await bump(db, `rec:${eid}`, today(), entries.length)) > LIMITS.record_entries_per_eid_per_day) fail(429, "rate_limited", `at most ${LIMITS.record_entries_per_eid_per_day} record entries per day`);
  const now = nowIso(), stmts: D1PreparedStatement[] = [], leaves: { leaf: object; leaf_hash: string }[] = [];
  for (const [i, en] of entries.entries()) {
    const l = await leafFor(db, "RecordEntry", eid, hashes[i], now);
    leaves.push(l);
    stmts.push(l.stmt, db.prepare(`INSERT INTO record_entries (eid, seq, kind, json, sha256, received_at, log_index) VALUES (?, ?, ?, ?, ?, ?, ${LAST_INDEX})`).bind(eid, en.seq, en.kind, JSON.stringify(en), hashes[i], now));
  }
  stmts.push(db.prepare("UPDATE entities SET record_seq = ?, record_head_hash = ?, updated = ? WHERE eid = ? AND record_seq = ?").bind(seq, prev, now, eid, e.record_seq));
  const res = await db.batch(stmts);
  await c.env.LOG_QUEUE.send({ t: "leaf" });
  return c.json({ eid, head: { seq, hash: prev }, accepted: entries.map((en, i) => ({ seq: en.seq, ...receipt(c, (res[2 * i].results[0] as { idx: number }).idx, leaves[i]) })) }, 201);
});

app.post("/attestations", async (c) => {
  const db = c.env.DB;
  const a = await readJson(c);
  const type = a?.type === "Revocation" ? "Revocation" : "Attestation";
  const issuer = normalizeEid(String(a?.issuer ?? ""));
  await writeGuard(c, issuer);
  schema(type, a);
  window(a.created, type);
  await signedBy(a, issuer, type);
  const now = nowIso(), s = await sha(a);
  if (type === "Revocation") {
    const att = await db.prepare("SELECT subject, issuer, revoked_at FROM attestations WHERE sha256 = ?").bind(a.attestation_sha256).first<any>();
    if (!att) fail(404, "attestation_not_found", `no attestation ${a.attestation_sha256}`);
    if (att.issuer !== issuer) fail(422, "not_issuer", "only the issuer can revoke an attestation");
    if (att.revoked_at) fail(409, "already_revoked", "attestation already revoked");
    const l = await leafFor(db, "Revocation", att.subject, s, now);
    const res = await db.batch([l.stmt, db.prepare("UPDATE attestations SET revoked_at = ?, revocation_json = ? WHERE sha256 = ?").bind(now, JSON.stringify(a), a.attestation_sha256)]);
    await c.env.LOG_QUEUE.send({ t: "leaf" });
    await refreshLevel(db, att.subject);
    return c.json({ sha256: s, revoked: a.attestation_sha256, ...receipt(c, firstIdx(res), l) }, 201);
  }
  const subject = normalizeEid(String(a.subject));
  await mustEntity(db, subject);
  const expires: string = a.expires ?? new Date(Date.parse(a.created) + 90 * 86400_000).toISOString().replace(/\.\d+Z$/, "Z");
  if (expires <= a.created || Date.parse(expires) > Date.parse(a.created) + 366 * 86400_000) fail(422, "expires_invalid", "expires must be after created and at most 1 year later");
  const l = await leafFor(db, "Attestation", subject, s, now);
  const res = await db.batch([
    l.stmt,
    db.prepare(`INSERT INTO attestations (sha256, issuer, subject, claim_type, json, created, expires, log_index) VALUES (?, ?, ?, ?, ?, ?, ?, ${LAST_INDEX})`).bind(s, issuer, subject, a.claim_type, JSON.stringify(a), a.created, expires),
  ]);
  await c.env.LOG_QUEUE.send({ t: "leaf" });
  const lv = await refreshLevel(db, subject);
  return c.json({ sha256: s, subject, subject_level: LEVEL(lv.level), ...receipt(c, firstIdx(res), l) }, 201);
});

app.post("/continuity", async (c) => {
  const db = c.env.DB;
  const body = await readJson(c);
  const link = body?.link, document = body?.document;
  const successor = normalizeEid(String(link?.successor ?? ""));
  await writeGuard(c, successor);
  schema("ContinuityLink", link);
  if (document !== undefined) schema("EntityDocument", document);
  window(link.created, "link");
  const previous = normalizeEid(String(link.previous));
  if (previous === successor) fail(422, "schema_invalid", "previous and successor are the same EID");
  const prevE = await mustEntity(db, previous);
  if (prevE.successor_eid) fail(409, "previous_has_successor", `${previous} already continues as ${prevE.successor_eid}`);
  const succE = await entity(db, successor);
  if (succE?.predecessor_eid) fail(409, "successor_has_predecessor", `${successor} already continues ${succE.predecessor_eid}`);
  if (!succE) {
    if (!document) fail(422, "document_required", "a new successor needs its seq 1 Entity Document");
    if (normalizeEid(String(document.eid)) !== successor || document.seq !== 1) fail(422, "eid_mismatch", "document must be the successor's seq 1 Entity Document");
    window(document.updated, "document");
    await signedBy(document, successor, "document");
  }
  const { proofs, ...unsigned } = link;
  if (!Array.isArray(proofs)) fail(422, "schema_invalid", "proofs must be a list");
  const signers = new Set<string>();
  for (const p of proofs) { const r = await verifyProof(unsigned, p, resolver); if (r.ok && r.signer) signers.add(normalizeEid(r.signer)); }
  if (!signers.has(successor)) fail(422, "continuity_proof_missing", "a valid proof by the successor key is required");
  if (link.basis === "recovery") {
    const aliases = (await db.prepare("SELECT value FROM aliases WHERE eid = ? AND status = 'verified' AND type IN ('domain', 'wallet')").bind(previous).all<{ value: string }>()).results.map((r) => r.value.toLowerCase());
    if (![...signers].some((s) => aliases.includes(s.toLowerCase()))) fail(422, "recovery_alias_required", "recovery needs a proof by a verified domain or wallet alias of the previous EID");
  } else if (!signers.has(previous)) fail(422, "continuity_proof_missing", "rotation and migration need a valid proof by the previous key");

  const now = nowIso(), s = await sha(link);
  const l = await leafFor(db, "ContinuityLink", successor, s, now);
  const stmts = [l.stmt, db.prepare(`INSERT INTO continuity_links (sha256, previous, successor, basis, json, received_at, log_index) VALUES (?, ?, ?, ?, ?, ?, ${LAST_INDEX})`).bind(s, previous, successor, link.basis, JSON.stringify(link), now)];
  if (!succE) {
    const d = await leafFor(db, "EntityDocument", successor, await sha(document), now);
    stmts.push(
      d.stmt,
      db.prepare(`INSERT INTO documents (eid, seq, json, sha256, received_at, log_index) VALUES (?, 1, ?, ?, ?, ${LAST_INDEX})`).bind(successor, JSON.stringify(document), await sha(document), now),
      db.prepare("INSERT INTO entities (eid, root_method, name, level, created, updated, custody, latest_seq, predecessor_eid, adopted_log_index) VALUES (?, ?, ?, 0, ?, ?, ?, 1, ?, ?)")
        .bind(successor, successor.split(":")[1], document.name, now, now, document.operator?.custody ?? null, previous, prevE.adopted_log_index),
    );
  } else stmts.push(db.prepare("UPDATE entities SET predecessor_eid = ?, updated = ? WHERE eid = ?").bind(previous, now, successor));
  stmts.push(db.prepare("UPDATE entities SET successor_eid = ?, updated = ? WHERE eid = ?").bind(successor, now, previous));
  const res = await db.batch(stmts);
  await c.env.LOG_QUEUE.send({ t: "leaf" });
  const lv = await refreshLevel(db, successor);
  return c.json({ previous, successor, basis: link.basis, level: LEVEL(lv.level), ...receipt(c, firstIdx(res), l) }, 201);
});

app.post("/withdraw", async (c) => {
  const db = c.env.DB;
  const w = await readJson(c);
  const eid = normalizeEid(String(w?.eid ?? ""));
  await writeGuard(c, eid);
  schema("Withdrawal", w);
  window(w.created, "withdrawal");
  await signedBy(w, eid, "withdrawal");
  const d = await db.prepare("SELECT withdrawn_at FROM declarations WHERE eid = ? AND version = ?").bind(eid, w.declaration_version).first<any>();
  if (!d) fail(404, "declaration_not_found", `no Declaration ${w.declaration_version} for ${eid}`);
  if (d.withdrawn_at) fail(409, "already_withdrawn", "already withdrawn");
  const now = nowIso(), s = await sha(w);
  const l = await leafFor(db, "Withdrawal", eid, s, now);
  const res = await db.batch([
    l.stmt,
    db.prepare("UPDATE declarations SET withdrawn_at = ?, withdrawal_json = ? WHERE eid = ? AND version = ?").bind(now, JSON.stringify(w), eid, w.declaration_version),
    db.prepare("UPDATE entities SET withdrawn_at = ?, level = NULL, level_label = NULL, updated = ? WHERE eid = ?").bind(now, now, eid),
  ]);
  await c.env.LOG_QUEUE.send({ t: "leaf" });
  return c.json({ eid, withdrawn: true, ...receipt(c, firstIdx(res), l) }, 201);
});

// ---------- observers, resolve, verify, stats ----------

app.get("/observers", async (c) => {
  const rows = (await c.env.DB.prepare("SELECT o.*, (SELECT COUNT(DISTINCT subject) FROM attestations a WHERE a.issuer = o.did) AS entities_observed FROM observers o ORDER BY accredited_at").all<any>()).results;
  return c.json({ observers: rows.map((o) => ({ did: o.did, name: o.name, methodology_url: o.methodology_url, trust_policy_url: o.trust_policy_url, accredited_at: o.accredited_at, bootstrap: !!o.bootstrap, entities_observed: o.entities_observed })) });
});

app.get("/resolve/:did", async (c) => {
  const did = normalizeEid(c.req.param("did"));
  let doc = null;
  try { doc = await resolveDid(did); } catch { /* fall through */ }
  return doc ? c.json({ did, didDocument: doc }) : fail(404, "unresolvable", `cannot resolve ${did}`);
});

app.post("/verify", async (c) => {
  const o = await readJson(c);
  const type: string = o?.type ?? (o?.keys && o?.eid ? "EntityDocument" : "unknown");
  const v = validate(type as "EntityDocument", o);
  let signatures: { ok: boolean; signer?: string; error?: string }[] = [];
  if (v.ok) {
    if (type === "ContinuityLink") { const { proofs, ...u } = o; for (const p of proofs) signatures.push(await verifyProof(u, p, resolver)); }
    else signatures = [await verifyObject(o, resolver)];
  }
  const s = await sha(o);
  const leaf = await c.env.DB.prepare("SELECT idx FROM log_leaves WHERE object_sha256 = ? LIMIT 1").bind(s).first<number>("idx");
  const created = o?.created ?? o?.updated ?? o?.at;
  return c.json({
    type, schema: { ok: v.ok, errors: v.errors }, signatures, object_sha256: s, log_index: leaf ?? null,
    timestamp: created && type !== "RecordEntry" ? checkTimestamp(created) ?? "ok" : null,
    ok: v.ok && signatures.length > 0 && signatures.every((x) => x.ok),
  });
});

async function stats(env: Env) {
  const db = env.DB;
  const byLevel = (await db.prepare("SELECT level, COUNT(*) AS n FROM entities WHERE suppressed = 0 AND level IS NOT NULL GROUP BY level").all<{ level: number; n: number }>()).results;
  const n = (sql: string, ...a: unknown[]) => db.prepare(sql).bind(...a).first<number>("n").then((x) => x ?? 0);
  const L = (k: number) => byLevel.find((r) => r.level === k)?.n ?? 0;
  return {
    entities: { l0: L(0), l1: L(1), l2: L(2), l3: L(3), total: L(0) + L(1) + L(2) + L(3) },
    declarations_today: await n("SELECT COUNT(*) AS n FROM declarations WHERE received_at >= ?", `${today()}T00:00:00Z`),
    record_entries: await n("SELECT COUNT(*) AS n FROM record_entries"),
    attestations: await n("SELECT COUNT(*) AS n FROM attestations WHERE revoked_at IS NULL"),
    observers: await n("SELECT COUNT(*) AS n FROM observers"),
    log: { tree_size: await latestSize(db) },
    generated_at: nowIso(),
  };
}
app.get("/stats", async (c) => {
  const cached = await c.env.KV.get("stats", "json");
  if (cached) return c.json(cached);
  const s = await stats(c.env);
  await c.env.KV.put("stats", JSON.stringify(s), { expirationTtl: 60 });
  return c.json(s);
});

app.get("/stats/history.csv", async (c) => {
  const cols = ["date", "entities_l0", "entities_l1", "entities_l2", "entities_l3", "adoptions", "record_entries", "attestations", "observers"];
  const rows = (await c.env.DB.prepare(`SELECT ${cols.join(", ")} FROM stats_daily ORDER BY date`).all<any>()).results;
  return c.body([cols.join(","), ...rows.map((r) => cols.map((k) => r[k] ?? "").join(","))].join("\n") + "\n", 200, { "content-type": "text/csv; charset=utf-8" });
});

app.get("/founding", async (c) => {
  const rows = (await c.env.DB.prepare("SELECT e.eid, e.name, e.level, e.level_label, d.log_index, d.received_at FROM entities e JOIN declarations d ON d.eid = e.eid WHERE e.founding = 1 ORDER BY d.log_index").all<any>()).results;
  return c.json({ founding: rows.map((r) => ({ eid: r.eid, name: r.name, level: LEVEL(r.level), level_label: r.level_label, log_index: r.log_index, adopted_at: r.received_at })) });
});

// ---------- transparency log (spec 10.3) ----------

app.get("/log/checkpoint", async (c) => {
  const o = await c.env.LOG.get("checkpoint");
  return o ? c.body(await o.text(), 200, { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" }) : fail(404, "no_checkpoint", "no checkpoint yet");
});
app.get("/log/tile/*", async (c) => {
  let key = c.req.path.slice("/v1/log/".length);
  const plain = /^tile\/(\d+|entries)\/(\d+)(\.p\/\d+)?$/.exec(key);
  if (plain) key = `tile/${plain[1]}/${tileIndex(Number(plain[2]))}${plain[3] ?? ""}`;
  const o = await c.env.LOG.get(key);
  if (!o) return fail(404, "tile_not_found", key);
  return c.body(await o.arrayBuffer(), 200, { "content-type": "application/octet-stream", "cache-control": key.includes(".p/") ? "no-store" : "public, max-age=31536000, immutable" });
});
app.get("/log/sth", async (c) => {
  const cp = await c.env.DB.prepare("SELECT * FROM checkpoints ORDER BY tree_size DESC LIMIT 1").first<any>();
  return cp ? c.json({ tree_size: cp.tree_size, root_hash: cp.root_hash, timestamp: cp.timestamp, signature: cp.signed_note }) : fail(404, "no_checkpoint", "no checkpoint yet");
});
app.get("/log/entries", async (c) => {
  const start = Math.max(0, Number(c.req.query("start") ?? 0) | 0);
  const end = Math.min(Number(c.req.query("end") ?? start + LIMITS.log_entries_per_call) | 0, start + LIMITS.log_entries_per_call);
  const rows = (await c.env.DB.prepare("SELECT * FROM log_leaves WHERE idx >= ? AND idx < ? ORDER BY idx").bind(start, end).all<LeafRow>()).results;
  return c.json({ entries: rows.map((r) => ({ index: r.idx, leaf: JSON.parse(leafJson(r)), leaf_hash: r.leaf_hash })) });
});
async function sizeParam(c: C, name: string): Promise<number> {
  const latest = await latestSize(c.env.DB);
  const v = c.req.query(name);
  const n = v === undefined ? latest : Number(v);
  if (!Number.isInteger(n) || n < 0 || n > latest) fail(400, "bad_tree_size", `${name} must be an integer up to ${latest}`);
  return n;
}
app.get("/log/proof/:index", async (c) => {
  const index = Number(c.req.param("index")), tree_size = await sizeParam(c, "tree_size");
  if (!Number.isInteger(index) || index < 0 || index >= tree_size) fail(404, "not_incorporated", `leaf ${c.req.param("index")} is not in a tree of size ${tree_size} yet`);
  const leaf_hash = await c.env.DB.prepare("SELECT leaf_hash FROM log_leaves WHERE idx = ?").bind(index).first<string>("leaf_hash");
  return c.json({ index, tree_size, leaf_hash, root_hash: await treeRoot(c.env.DB, tree_size), proof: await inclusionProof(c.env.DB, index, tree_size) });
});
app.get("/log/consistency", async (c) => {
  const first = await sizeParam(c, "first"), second = await sizeParam(c, "second");
  if (first < 1 || first > second) fail(400, "bad_tree_size", "need 1 <= first <= second");
  return c.json({ first, second, proof: first === second ? [] : await consistencyProof(c.env.DB, first, second) });
});
app.get("/log/snapshots/:file", async (c) => {
  if (!/^\d{4}-\d{2}-\d{2}\.jsonl$/.test(c.req.param("file"))) fail(404, "snapshot_not_found", "snapshots are <YYYY-MM-DD>.jsonl");
  const o = await c.env.LOG.get(`snapshots/${c.req.param("file")}`);
  return o ? c.body(await o.text(), 200, { "content-type": "application/jsonl" }) : fail(404, "snapshot_not_found", c.req.param("file"));
});

// ---------- human form (PRD 7.3): the only route with Turnstile ----------

app.post("/subscribe", async (c) => {
  const env = c.env;
  if (!env.TURNSTILE_SECRET || !env.CIO_SITE_ID || !env.CIO_API_KEY) fail(503, "subscribe_unavailable", "the signup form is not configured on this registry");
  const ct = c.req.header("content-type") ?? "";
  const f: Record<string, unknown> = ct.includes("application/json") ? await readJson(c) : Object.fromEntries(await c.req.formData());
  const email = String(f.email ?? "").trim().toLowerCase();
  const token = String(f["cf-turnstile-response"] ?? f.turnstile_token ?? "");
  if (!/^[^\s@]{1,64}@[^\s@]{1,253}\.[^\s@]{2,}$/.test(email)) fail(400, "bad_email", "a valid email is required");
  const form = new FormData();
  form.append("secret", env.TURNSTILE_SECRET!);
  form.append("response", token);
  const ip = c.req.header("cf-connecting-ip");
  if (ip) form.append("remoteip", ip);
  const tv: any = await (await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", { method: "POST", body: form })).json().catch(() => ({}));
  if (!token || !tv.success) fail(403, "turnstile_failed", "Turnstile verification failed");
  if ((await bump(env.DB, `sub:${await salted(env, email)}`, today())) > 3) fail(429, "rate_limited", "too many signups for this address today");
  const operator = f.operator === true || f.operator === "true" || f.operator === "on";
  const res = await fetch(`https://track.customer.io/api/v1/customers/${encodeURIComponent(email)}`, {
    method: "PUT",
    headers: { authorization: `Basic ${btoa(`${env.CIO_SITE_ID}:${env.CIO_API_KEY}`)}`, "content-type": "application/json" },
    body: JSON.stringify({ email, source: "openentity.org", operator, consented_at: Math.floor(Date.now() / 1000) }),
  });
  if (!res.ok) fail(502, "subscribe_failed", `Customer.io returned ${res.status}`);
  return c.json({ ok: true, message: "Check your inbox to confirm." }, 202);
});

// ---------- scheduled work ----------

/** Accredits observers that meet spec 8.4 on their own; clears the bootstrap mark when they do. */
async function accreditObservers(env: Env) {
  const rows = (await env.DB.prepare("SELECT issuer, COUNT(DISTINCT subject) AS n FROM attestations GROUP BY issuer HAVING n >= 10").all<{ issuer: string }>()).results;
  for (const { issuer } of rows) {
    const existing = await env.DB.prepare("SELECT bootstrap FROM observers WHERE did = ?").bind(issuer).first<number>("bootstrap");
    if (existing === 0) continue;
    const alias = await env.DB.prepare("SELECT value FROM aliases WHERE eid = ? AND type = 'domain' AND status = 'verified' LIMIT 1").bind(issuer).first<string>("value");
    const domain = issuer.startsWith("did:web:") ? issuer.slice(8).split(":")[0] : alias?.slice(8);
    if (!domain) continue;
    const wk: any = await fetch(`https://${domain}/.well-known/openentity.json`).then((r) => (r.ok ? r.json() : null)).catch(() => null);
    const ext = wk?.extensions?.["openentity:observer"];
    if (!ext) continue;
    await env.DB.prepare("INSERT INTO observers (did, name, methodology_url, trust_policy_url, accredited_at, bootstrap) VALUES (?, ?, ?, ?, ?, 0) ON CONFLICT (did) DO UPDATE SET bootstrap = 0, methodology_url = excluded.methodology_url")
      .bind(issuer, wk.name ?? domain, ext.methodology ?? ext.methodology_url ?? null, wk.extensions?.["openentity:trust_policy"]?.url ?? null, nowIso()).run();
  }
}

export async function scheduled(env: Env) {
  await incorporate(env);
  const s = await stats(env), d = today();
  await env.DB.prepare("INSERT OR REPLACE INTO stats_daily (date, entities_l0, entities_l1, entities_l2, entities_l3, adoptions, record_entries, attestations, observers) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
    .bind(d, s.entities.l0, s.entities.l1, s.entities.l2, s.entities.l3, s.declarations_today, s.record_entries, s.attestations, s.observers).run();
  await snapshot(env, new Date(Date.now() - 86400_000).toISOString().slice(0, 10));
  await accreditObservers(env);
  // IP and stamp counters live 7 days, email hashes 24 hours (PRD 8, 7.3).
  await env.DB.prepare("DELETE FROM rate_events WHERE (key LIKE 'sub:%' AND window_start < ?) OR window_start < ?").bind(new Date(Date.now() - 86400_000).toISOString().slice(0, 10), new Date(Date.now() - 7 * 86400_000).toISOString().slice(0, 10)).run();
}

export default {
  fetch: app.fetch,
  async queue(batch: MessageBatch, env: Env) {
    await incorporate(env);
    batch.ackAll();
  },
  async scheduled(_c: ScheduledController, env: Env, ctx: ExecutionContext) {
    ctx.waitUntil(scheduled(env));
  },
} satisfies ExportedHandler<Env>;
