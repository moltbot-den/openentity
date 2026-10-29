// Open Entity reference registry (spec section 10, PRD sections 7.7, 8, 9).
import { Hono, type Context } from "hono";
import { cors } from "hono/cors";
import {
  DECLARATION_SHA256, DECLARATION_VERSION, SPEC, buildDeclaration, buildDocument, canonicalize, checkStamp, checkTimestamp,
  generateKeyPair, normalizeEid, noteVkey, recordEntryHash, sha256Hex, signObject, validate, verifyObject, verifyPresentation, verifyProof, type Proof, type Resolver,
} from "./sdk.ts";
import { type Env, REGISTRY_DID, LOG_ORIGIN, b64, nowIso } from "./env.ts";
import { type Stmt, chain, consistencyProof, exportObjects, inclusionProof, incorporate, latestSize, leafFor, leafJson, registryKey, sequenced, snapshot, tileIndex, treeRoot, type LeafRow } from "./log.ts";
import type { Db } from "./db.ts";
import { sendDigest } from "./digest.ts";
import { DOMAIN, getJson, platformDomain, resolveDid, resolver, verifyAlias } from "./aliases.ts";

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
// Agents call from browsers too: allow the headers a write needs. No credentials, ever (agent endpoints have no login).
// CloudFront does not forward Access-Control-Request-Headers, so the list is fixed rather than reflected.
app.use("*", cors({ origin: "*", allowMethods: ["GET", "POST", "PUT", "OPTIONS"], allowHeaders: ["content-type", "x-oe-stamp", "accept", "if-none-match"], exposeHeaders: ["retry-after", "etag"], maxAge: 86400 }));
app.onError((e, c) => {
  if (e instanceof HttpError) return c.json({ error: e.code, message: e.message }, e.status as 400);
  if (UNIQUE.test(String(e))) return c.json({ error: "conflict", message: "object already exists or was accepted concurrently" }, 409);
  console.error(e);
  return c.json({ error: "internal", message: "internal error" }, 500);
});
const UNIQUE = /duplicate key value violates unique constraint/;
app.notFound((c) => c.json({ error: "not_found", message: "no such endpoint" }, 404));

// ---------- shared guards ----------

const STAMP_REQUIRED = "write endpoints require an X-OE-Stamp header; see GET /v1/spec for the bits";
/** Body of a write. The stamp header is checked first so every write answers a missing stamp the same way, whatever the body. */
async function readJson(c: C, stamped = true): Promise<any> {
  if (stamped && !c.req.header("x-oe-stamp")) fail(400, "stamp_required", STAMP_REQUIRED);
  const text = await c.req.text();
  if (text.length > 2_000_000) fail(413, "too_large", "request body exceeds 2 MB");
  try { return JSON.parse(text); } catch { return fail(400, "bad_json", "body is not valid JSON"); }
}
const salted = (env: Env, s: string) => sha256Hex(`${env.HASH_SALT ?? "openentity-dev-salt"}:${s}`);
const IP_SHARDS = 8;
const UPSERT = "ON CONFLICT (key, window_start) DO UPDATE SET count = rate_events.count + excluded.count RETURNING key, count";
/** Adds n to a counter and returns the new total. */
async function bump(db: Db, key: string, window: string, n = 1): Promise<number> {
  return (await db.first<{ count: number }>(`INSERT INTO rate_events (key, window_start, count) VALUES ($1, $2, $3) ${UPSERT}`, [key, window, n]))!.count;
}
/** The limit key for an address: an IPv6 host owns its whole /64, so the key is the /64 and rotating inside it buys nothing. */
const limitKey = (ip: string) => {
  if (!ip.includes(":")) return ip;
  const [head, tail = ""] = ip.split("::"), h = head.split(":").filter(Boolean), t = tail.split(":").filter(Boolean);
  return [...h, ...Array(Math.max(0, 8 - h.length - t.length)).fill("0"), ...t].slice(0, 4).map((g) => g.replace(/^0+(?=.)/, "")).join(":") + "::/64";
};
/** Client IP: CloudFront's viewer address ("ip:port", IPv6 unbracketed), else the first X-Forwarded-For hop. */
export function clientIp(c: C): string {
  const v = c.req.header("cloudfront-viewer-address");
  if (v?.includes(":")) return limitKey(v.slice(0, v.lastIndexOf(":")));
  return c.req.header("x-forwarded-for")?.split(",")[0].trim() || "0.0.0.0";
}
/** Time-to-adopt funnel start (PRD 12): the first GET /llms.txt per hashed address in 24 h. Only a salted hash and an epoch second are kept. */
const FUNNEL_TTL = 86400;
const funnelKey = async (c: C) => `fs:${await salted(c.env, clientIp(c))}`;
/** The one unstamped write. One start row per address already, so growth comes from many addresses: cap requests per address per minute and, hard, per hour over all of them (each request adds at most two rows; the sweep drops them within 24 h). */
const FUNNEL_PER_IP_PER_MINUTE = 10, FUNNEL_PER_HOUR = 10_000;
app.post("/funnel/start", async (c) => {
  const t = Math.floor(Date.now() / 1000), now = nowIso();
  if ((await bump(c.env.db, "fsg", now.slice(0, 13))) > FUNNEL_PER_HOUR) fail(429, "rate_limited", "funnel starts are paused for this hour");
  if ((await bump(c.env.db, `fsm:${await salted(c.env, clientIp(c))}`, now.slice(0, 16))) > FUNNEL_PER_IP_PER_MINUTE) fail(429, "rate_limited", `at most ${FUNNEL_PER_IP_PER_MINUTE} funnel starts per minute per IP`);
  await c.env.db.run("INSERT INTO rate_events (key, window_start, count) VALUES ($1, 'fs', $2) ON CONFLICT (key, window_start) DO UPDATE SET count = excluded.count WHERE rate_events.count < $3", [await funnelKey(c), t, t - FUNNEL_TTL]);
  return c.body(null, 204);
});
/**
 * Every write: a single-use proof-of-work stamp naming the writing EID (spec 10.4) and per-IP limits (spec 10.5).
 * Returns two CTE statements (s0 counts, s1 checks) that the write runs inside its own statement, or alone in `writeGuard`.
 * The check casts the name of a broken limit to an integer: Postgres aborts the whole statement, counters and write
 * included, and `guardError` turns the message back into the 429 or 409. Nothing is constant: a folded CAST would fail at plan time.
 */
async function guardStmts(c: C, eid: string): Promise<Stmt[]> {
  const env = c.env;
  const stamp = c.req.header("x-oe-stamp");
  if (!stamp) fail(400, "stamp_required", STAMP_REQUIRED);
  const err = await checkStamp(stamp!, Number(env.STAMP_BITS), eid);
  if (err) fail(400, "stamp_invalid", err);
  const ip = await salted(env, clientIp(c)), now = nowIso();
  // One IP's counters are split over IP_SHARDS rows and summed: a single row per IP made every write from that IP
  // queue on one row lock (about 220 ms each at 100 writes/s on Aurora). A shard's write locks its own row; the
  // others are read as last committed, so concurrent writes can pass a limit by the number in flight.
  const s = Math.floor(Math.random() * IP_SHARDS), others = (p: string) => Array.from({ length: IP_SHARDS }, (_, t) => `${p}:${ip}:${t}`).filter((_, t) => t !== s);
  const day = others("ip"), minute = others("ipm"), list = (from: number, n: number) => Array.from({ length: n }, (_, k) => `$${from + k}`).join(", ");
  const daily = Number(env.IP_DAILY_LIMIT ?? LIMITS.writes_per_ip_per_day), perMinute = Number(env.WRITE_PER_MINUTE ?? LIMITS.writes_per_ip_per_minute);
  return [
    // Fixed row order (day, minute, stamp) so concurrent writes on one shard lock the counters in the same order.
    [`INSERT INTO rate_events (key, window_start, count) VALUES ($1, $2, 1), ($3, $4, 1), ($5, $6, 1) ${UPSERT}`,
      [`ip:${ip}:${s}`, now.slice(0, 10), `ipm:${ip}:${s}`, now.slice(0, 16), `stamp:${await sha256Hex(stamp!)}`, stamp!.split(":")[2].slice(0, 10)]],
    [`SELECT CAST(min(CASE k WHEN 'ipm' THEN '1ipm' WHEN 'ip' THEN '2ip' ELSE '3stamp' END) AS int) AS m FROM (
SELECT split_part(key, ':', 1) AS k, sum(count) AS n FROM (SELECT key, count FROM s0 UNION ALL
SELECT key, count FROM rate_events WHERE (window_start = $1 AND key IN (${list(3, day.length)})) OR (window_start = $2 AND key IN (${list(3 + day.length, minute.length)}))) x GROUP BY 1) y
WHERE (k = 'ipm' AND n > $${3 + day.length + minute.length}) OR (k = 'ip' AND n > $${4 + day.length + minute.length}) OR (k = 'stamp' AND n > 1)`,
      [now.slice(0, 10), now.slice(0, 16), ...day, ...minute, perMinute, daily]],
  ];
}
const GUARD_FINAL = "SELECT coalesce(m, 0) FROM s1"; // reads m: the planner drops an unused aggregate, cast included
/** Turns the abort of a guard statement into its HTTP error; any other error passes through. */
function guardError(e: unknown): void {
  const m = /invalid input syntax for type integer: "\d(ipm|ip|stamp)"/.exec(String(e))?.[1];
  if (m === "ipm") fail(429, "rate_limited", `at most ${LIMITS.writes_per_ip_per_minute} writes per minute per IP`);
  if (m === "ip") fail(429, "rate_limited", `at most ${LIMITS.writes_per_ip_per_day} writes per day per IP`);
  if (m === "stamp") fail(409, "stamp_reused", "each stamp is accepted once");
}
async function writeGuard(c: C, eid: string) {
  const params: unknown[] = [];
  await c.env.db.run(`WITH ${chain(await guardStmts(c, eid), params).join(",\n")}\n${GUARD_FINAL}`, params).catch((e) => { guardError(e); throw e; });
}
const MAX_BYTES: Record<string, number> = { EntityDocument: LIMITS.document_max_bytes, RecordEntry: LIMITS.record_entry_max_bytes }; // spec 4.1, 7.3
function schema(type: string, obj: unknown) {
  const max = MAX_BYTES[type];
  if (max && new TextEncoder().encode(JSON.stringify(obj)).length > max) fail(413, "too_large", `${type} exceeds ${max} bytes`);
  const r = validate(type as "EntityDocument", obj);
  if (!r.ok) fail(422, "schema_invalid", `${type}: ${r.errors.join("; ")}`);
}
function window(created: string, what: string) {
  const err = checkTimestamp(created);
  if (err) fail(422, "timestamp_invalid", `${what}: ${err}`);
}
async function signedBy(obj: { proof?: Proof }, did: string, what: string, res: Resolver = resolver) {
  const r = await verifyObject(obj, res);
  if (!r.ok || normalizeEid(r.signer ?? "") !== did) fail(422, "signature_invalid", `${what}: ${r.error ?? `signed by ${r.signer}, expected ${did}`}`);
}
async function entity(db: Db, eid: string): Promise<any> {
  return db.first("SELECT * FROM entities WHERE eid = $1", [eid]);
}
async function mustEntity(db: Db, eid: string) {
  return (await entity(db, eid)) ?? fail(404, "entity_not_found", `no entity ${eid}`);
}
const sha = (o: unknown) => sha256Hex(canonicalize(o));
function receipt(c: C, idx: number, l: { leaf: object; leaf_hash: string }) {
  return { log_index: idx, receipt: { leaf: l.leaf, leaf_hash: l.leaf_hash, log_proof: `https://${c.env.REGISTRY_HOST}/v1/log/proof/${idx}` } };
}

// ---------- levels (spec 2.2, 8.4) ----------

async function lineage(db: Db, eid: string): Promise<string[]> {
  const chain = [eid];
  for (let i = 0; i < 10; i++) {
    const p = (await db.first("SELECT predecessor_eid FROM entities WHERE eid = $1", [chain[chain.length - 1]]))?.predecessor_eid;
    if (!p) break;
    chain.push(p);
  }
  return chain;
}
/**
 * Values of the entity's verified aliases of `types` that its own latest signed Entity Document also lists. An alias proof
 * (a domain file, a wallet message) names the EID but never needs the EID's key, so anyone can bind their own domain or
 * wallet to someone else's EID. Only a binding the key holder listed in a signed document shows consent.
 */
async function listedAliases(db: Db, eid: string, types: string[]): Promise<string[]> {
  const json = (await db.first<{ json: string }>("SELECT json FROM documents WHERE eid = $1 ORDER BY seq DESC LIMIT 1", [eid]))?.json;
  const listed = new Set<string>((json ? JSON.parse(json).aliases ?? [] : []).map((a: any) => `${a?.type}\n${String(a?.value).toLowerCase()}`));
  const rows = await db.all<{ type: string; value: string }>(`SELECT type, value FROM aliases WHERE eid = $1 AND status = 'verified' AND type IN (${IN(types, 2)})`, [eid, ...types]);
  return rows.filter((r) => listed.has(`${r.type}\n${r.value.toLowerCase()}`)).map((r) => r.value);
}

/** Placeholders $from.. for an IN list (the Data API takes no array parameters). */
const IN = (xs: string[], from = 1) => xs.map((_, i) => `$${from + i}`).join(",");

export async function computeLevel(db: Db, eid: string): Promise<{ level: number | null; label: string | null; supporting: any[] }> {
  const e = await entity(db, eid);
  const chain = await lineage(db, eid);
  const decl = await db.first(`SELECT 1 FROM declarations WHERE eid IN (${IN(chain)}) AND withdrawn_at IS NULL LIMIT 1`, chain);
  if (!e || e.withdrawn_at || !decl) return { level: null, label: null, supporting: [] };
  let level = (await db.first("SELECT 1 FROM aliases WHERE eid = $1 AND status = 'verified' LIMIT 1", [eid])) ? 1 : 0;
  const atts = await db.all(`SELECT a.issuer, a.claim_type, a.json FROM attestations a JOIN observers o ON o.did = a.issuer WHERE a.subject IN (${IN(chain, 2)}) AND a.revoked_at IS NULL AND a.expires > $1`, [nowIso(), ...chain]);
  if (!atts.length) return { level, label: null, supporting: [] };
  const stageEntity = atts.filter((a) => { const j = JSON.parse(a.json); return a.claim_type === "stage" && j.claim?.stage === "entity" && String(j.claim?.profile ?? "").startsWith("entity-framework/"); });
  const supporting = stageEntity.length ? stageEntity : atts;
  level = stageEntity.length ? 3 : 2;
  const fp = await firstPartyIssuers(db, eid);
  return { level, label: supporting.every((a) => fp(a.issuer)) ? "first-party" : "independent", supporting };
}
/** An issuer is first-party when it is the entity itself or its operator: the domain of operator.contact or of a verified platform alias. */
async function firstPartyIssuers(db: Db, eid: string): Promise<(issuer: string) => boolean> {
  const doc = (await db.first("SELECT json FROM documents WHERE eid = $1 ORDER BY seq DESC LIMIT 1", [eid]))?.json;
  const domains = new Set<string>();
  const contact = doc ? String(JSON.parse(doc).operator?.contact ?? "") : "";
  if (contact.includes("@")) domains.add(contact.split("@")[1].toLowerCase());
  for (const a of await db.all<{ value: string }>("SELECT value FROM aliases WHERE eid = $1 AND type = 'platform' AND status = 'verified'", [eid])) domains.add(platformDomain(a.value));
  return (issuer) => issuer === eid || (issuer.startsWith("did:web:") && domains.has(issuer.slice(8).split(":")[0]));
}
async function refreshLevel(db: Db, eid: string) {
  const l = await computeLevel(db, eid);
  await db.run("UPDATE entities SET level = $1, level_label = $2 WHERE eid = $3", [l.level, l.label, eid]);
  const succ = (await db.first("SELECT successor_eid FROM entities WHERE eid = $1", [eid]))?.successor_eid;
  if (succ) {
    const s = await computeLevel(db, succ);
    await db.run("UPDATE entities SET level = $1, level_label = $2 WHERE eid = $3", [s.level, s.label, succ]);
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

/** The unsigned `client` label on POST /adopt: which kind of client adopted, for GET /stats `by_client`. Not part of any signed object. */
const CLIENTS = ["adk", "goose", "langchain", "ui-tars", "cli", "mcp", "other"];
const clientLabel = (body: any): string | null => {
  if (body?.client == null) return null;
  if (!CLIENTS.includes(body.client)) fail(422, "invalid_client", `client must be one of ${CLIENTS.join(", ")}`);
  return body.client;
};

async function adopt(c: C, document: any, declaration: any, extra: Stmt[] = [], client: string | null = null, guard: Stmt[] = []) {
  const db = c.env.db;
  const eid = normalizeEid(String(document.eid));
  if (normalizeEid(String(declaration.eid)) !== eid) fail(422, "eid_mismatch", "document and declaration name different EIDs");
  if (declaration.declaration_version !== DECLARATION_VERSION || declaration.text_sha256 !== DECLARATION_SHA256)
    fail(422, "declaration_hash_mismatch", `text_sha256 must be ${DECLARATION_SHA256} for declaration_version ${DECLARATION_VERSION}`);
  window(declaration.created, "declaration");
  window(document.updated, "document");
  if (!(await resolveDid(eid))) fail(422, "unsupported_method", `cannot resolve ${eid}`);
  await signedBy(document, eid, "document");
  await signedBy(declaration, eid, "declaration");

  // One statement, no reads first: the primary keys on declarations (eid, version) and entities (eid) are the
  // one-Declaration and one-listing guards; a conflict rolls back the whole write, log indexes included.
  const t = Math.floor(Date.now() / 1000), fk = await funnelKey(c);
  const now = nowIso(), dSha = await sha(declaration), docSha = await sha(document);
  const dl = await leafFor("Declaration", eid, dSha, now);
  const doc = await leafFor("EntityDocument", eid, docSha, now);
  const idx = await sequenced(db, [dl, doc], [
    ...guard, // first: s0 and s1
    ["INSERT INTO declarations (eid, version, json, sha256, received_at, log_index) VALUES ($1, $2, $3, $4, $5, $i)", [eid, declaration.declaration_version, JSON.stringify(declaration), dSha, now]],
    ["INSERT INTO documents (eid, seq, json, sha256, received_at, log_index) VALUES ($1, $2, $3, $4, $5, $i + 1)", [eid, document.seq, JSON.stringify(document), docSha, now]],
    ["INSERT INTO entities (eid, root_method, name, level, created, updated, custody, latest_seq, client, adopted_log_index) VALUES ($1, $2, $3, 0, $4, $5, $6, $7, $8, $i)",
      [eid, eid.split(":")[1], document.name, now, now, document.operator?.custody ?? null, document.seq, client]],
    ...capabilityStmts(eid, document),
    // Funnel result in the same statement (no extra round trip): seconds since this address read /llms.txt, then the start is spent.
    ["INSERT INTO adopt_funnel (eid, seconds, internal) SELECT $1, $2 - count, $3 FROM rate_events WHERE key = $4 AND window_start = 'fs' AND count > $5",
      [eid, t, /moltbot ?den/i.test(`${document.operator?.name ?? ""} ${document.operator?.contact ?? ""}`) ? 1 : 0, fk, t - FUNNEL_TTL]],
    ["DELETE FROM rate_events WHERE key = $1 AND window_start = 'fs'", [fk]],
    ...extra,
  ], undefined, guard.length ? GUARD_FINAL : undefined).catch(async (e) => {
    guardError(e);
    if (!UNIQUE.test(String(e))) throw e;
    const has = await db.first("SELECT 1 FROM declarations WHERE eid = $1 AND version = $2", [eid, declaration.declaration_version]);
    return has ? fail(409, "declaration_exists", "this EID already has a Declaration of this version") : fail(409, "entity_exists", "this EID is already listed");
  });
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

async function decryptKey(env: Env, enc: string): Promise<JsonWebKey> {
  const raw = Uint8Array.from(atob(env.CUSTODY_KEY!), (ch) => ch.charCodeAt(0));
  const key = await crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["decrypt"]);
  const [iv, ct] = enc.split(".").map((s) => Uint8Array.from(atob(s), (ch) => ch.charCodeAt(0)));
  return JSON.parse(new TextDecoder().decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct)));
}

/** Replace an entity's capability index with its document's list (spec 5.2). */
const capabilityStmts = (eid: string, doc: any): Stmt[] => [
  // Delete only what left the list: a DELETE and an INSERT of the same row in one statement would drop it.
  ["DELETE FROM entity_capabilities WHERE eid = $1 AND capability NOT IN (SELECT json_array_elements_text($2::json))", [eid, JSON.stringify(doc.capabilities ?? [])]],
  ["INSERT INTO entity_capabilities (eid, capability) SELECT $1, value FROM json_array_elements_text($2::json) ON CONFLICT DO NOTHING", [eid, JSON.stringify(doc.capabilities ?? [])]],
];

app.post("/adopt", async (c) => {
  const body = await readJson(c);
  const client = clientLabel(body);
  if (body?.custodial === true) {
    // Custodial mode (spec 10.6): the registry generates the key, returns it once, keeps a copy only on request.
    await writeGuard(c, REGISTRY_DID);
    if (body.keep_copy && !c.env.CUSTODY_KEY) fail(503, "custody_unavailable", "this registry is not configured to keep custodial keys");
    const kp = await generateKeyPair();
    const document = await signObject(buildDocument({ kp, name: String(body.name ?? ""), description: String(body.description || "An entity whose key is held by the registry in custodial mode."), operator: { kind: "none", custody: "registry", can_change: [] } }), kp);
    schema("EntityDocument", document);
    const declaration = await signObject(buildDeclaration({ eid: kp.did, name: String(body.name) }), kp);
    const keep: Stmt[] = body.keep_copy ? [["INSERT INTO custodial_keys (eid, enc_key, created) VALUES ($1, $2, $3)", [kp.did, await encryptKey(c.env, kp.privateJwk), nowIso()]]] : [];
    const out = await adopt(c, document, declaration, keep, client);
    return c.json({ ...out, custodial: { private_key_jwk: kp.privateJwk, kept_copy: !!body.keep_copy, warning: "This private key is shown once. Store it; move to self-custody with a rotation Continuity Link." } }, 201);
  }
  const { document, declaration } = body ?? {};
  const guard = await guardStmts(c, normalizeEid(String(document?.eid ?? ""))); // the stamp is checked here; the counters run inside the adopt statement
  schema("EntityDocument", document);
  schema("Declaration", declaration);
  return c.json(await adopt(c, document, declaration, [], client, guard), 201);
});

// Custody exit (spec 10.6): a Presentation to this registry proves control; the kept copy is returned once and deleted.
app.post("/entities/:eid/custody/export", async (c) => {
  const db = c.env.db, eid = normalizeEid(c.req.param("eid"));
  const p = await readJson(c);
  await writeGuard(c, eid);
  schema("Presentation", p);
  if (normalizeEid(String(p.eid)) !== eid) fail(422, "eid_mismatch", "presentation eid does not match the path");
  const audiences = [`https://${c.env.REGISTRY_HOST}`, c.env.REGISTRY_HOST, REGISTRY_DID];
  const v = await verifyPresentation(p, { audience: audiences.includes(p.audience) ? p.audience : audiences[0], nonce: p.nonce, resolver });
  if (!v.ok) fail(422, "presentation_invalid", v.errors.join("; "));
  // The entity picks the nonce (there is no challenge round trip); the registry accepts each one once.
  if ((await bump(db, `pres:${await sha256Hex(p.nonce)}`, p.created.slice(0, 10))) > 1) fail(409, "nonce_reused", "each presentation nonce is accepted once");
  const row = await db.first<{ enc_key: string }>("DELETE FROM custodial_keys WHERE eid = $1 RETURNING enc_key", [eid]);
  if (!row) fail(404, "no_custodial_copy", "this registry keeps no key for this EID (never kept, or already exported)");
  return c.json({
    eid, private_key_jwk: await decryptKey(c.env, row!.enc_key), kept_copy: false,
    next: "The registry no longer holds this key. Move to self-custody with a rotation Continuity Link (spec 9): openentity rotate --custody entity, or POST /v1/continuity.",
  });
});

// ---------- entity reads ----------

/** Spec 10.7: the newest of the entity's last Record entry and its newest unrevoked `custom:moltbotden:liveness` attestation from an accredited observer. */
const lastActive = (eid: string) => `GREATEST((SELECT received_at FROM record_entries r WHERE r.eid = ${eid} ORDER BY seq DESC LIMIT 1), (SELECT MAX(a.created) FROM attestations a JOIN observers o ON o.did = a.issuer WHERE a.subject = ${eid} AND a.claim_type = 'custom:moltbotden:liveness' AND a.revoked_at IS NULL))`;

app.get("/entities", async (c) => {
  const q = c.req.query();
  const minLevel = Number(/\d/.exec(q.level ?? "1")?.[0] ?? 1);
  const args: unknown[] = [minLevel], $ = (v: unknown) => `$${args.push(v)}`;
  const where = ["suppressed = 0", "level >= $1"];
  if (q.q) {
    // Case-insensitive substring of the name or the EID; the reader's % and _ match themselves.
    const like = $(`%${q.q.replace(/[\\%_]/g, "\\$&")}%`);
    where.push(`(name ILIKE ${like} OR eid ILIKE ${like})`);
  }
  if (q.since) where.push(`created >= ${$(q.since)}`);
  if (q.capability) where.push(`EXISTS (SELECT 1 FROM entity_capabilities k WHERE k.eid = entities.eid AND k.capability = ${$(q.capability)})`);
  if (q.alias_type) where.push(`EXISTS (SELECT 1 FROM aliases a WHERE a.eid = entities.eid AND a.type = ${$(q.alias_type)} AND a.status = 'verified')`);
  const page = Math.max(0, Number(q.page ?? 0) | 0);
  if (q.sort && q.sort !== "newest" && q.sort !== "attested") fail(422, "bad_sort", "sort is newest or attested");
  // One query: verified alias types, unrevoked attestation count and distinct accredited observers ride along as correlated subqueries on indexed columns.
  const order = q.sort === "attested" ? "attestation_count DESC, created DESC, eid" : "created DESC, eid";
  const rows = await c.env.db.all(`SELECT eid, name, level, level_label, created, adopted_log_index, withdrawn_at, ${lastActive("entities.eid")} AS last_active,
    (SELECT string_agg(DISTINCT a.type, ',' ORDER BY a.type) FROM aliases a WHERE a.eid = entities.eid AND a.status = 'verified') AS alias_types,
    (SELECT COUNT(*) FROM attestations t WHERE t.subject = entities.eid AND t.revoked_at IS NULL) AS attestation_count,
    (SELECT COUNT(DISTINCT t.issuer) FROM attestations t JOIN observers o ON o.did = t.issuer WHERE t.subject = entities.eid AND t.revoked_at IS NULL) AS observer_count
    FROM entities WHERE ${where.join(" AND ")} ORDER BY ${order} LIMIT 51 OFFSET ${$(page * 50)}`, args);
  return c.json({
    entities: rows.slice(0, 50).map((r) => ({ eid: r.eid, name: r.name, level: LEVEL(r.level), level_label: r.level_label, created: r.created, log_index: r.adopted_log_index, withdrawn: !!r.withdrawn_at, last_active: r.last_active,
      aliases: r.alias_types ? String(r.alias_types).split(",") : [], attestations: Number(r.attestation_count), observers: Number(r.observer_count) })),
    page, next_page: rows.length > 50 ? page + 1 : null,
  });
});

app.get("/entities/:eid", async (c) => {
  const db = c.env.db, eid = normalizeEid(c.req.param("eid"));
  const e = await mustEntity(db, eid);
  const doc = (await db.first("SELECT json FROM documents WHERE eid = $1 ORDER BY seq DESC LIMIT 1", [eid]))?.json;
  const chain = await lineage(db, eid);
  const decl = await db.first(`SELECT eid, json, log_index, withdrawn_at FROM declarations WHERE eid IN (${IN(chain)}) ORDER BY received_at DESC LIMIT 1`, chain);
  const aliases = await db.all("SELECT type, value, status, verified_at, log_index FROM aliases WHERE eid = $1", [eid]);
  // Spec 9: show the signed Continuity Link and its basis (rotation, migration, recovery) on both entities.
  const linkOf = async (col: "successor" | "previous") => {
    const r = await db.first(`SELECT basis, json FROM continuity_links WHERE ${col === "successor" ? "successor" : "previous"} = $1`, [eid]);
    return r ? { basis: r.basis, link: JSON.parse(r.json) } : null;
  };
  const attestations = (await db.first(`SELECT COUNT(*) AS n FROM attestations WHERE subject IN (${IN(chain)}) AND revoked_at IS NULL`, chain))?.n;
  // Spec 10.7: derived at read time from the newest verified record entry or liveness attestation; the registry never stores or accepts it.
  const last_active = (await db.first<{ t: string | null }>(`SELECT ${lastActive("$1")} AS t`, [eid]))?.t ?? null;
  return c.json({
    eid, name: e.name, last_active, document: doc ? JSON.parse(doc) : null,
    declaration: decl ? JSON.parse(decl.json) : null, declaration_note: DECLARATION_NOTE,
    declaration_inherited_from: decl && decl.eid !== eid ? decl.eid : null,
    level: LEVEL(e.level), level_label: e.level_label, aliases, log_index: e.adopted_log_index,
    lineage: { previous: e.predecessor_eid, successor: e.successor_eid, chain, previous_link: await linkOf("successor"), successor_link: await linkOf("previous") },
    counts: { record_entries: e.record_seq, attestations, document_versions: e.latest_seq },
    record_head: e.record_head_hash ? { seq: e.record_seq, hash: e.record_head_hash } : null,
    withdrawn: !!e.withdrawn_at, withdrawn_at: e.withdrawn_at, suppressed: !!e.suppressed, founding: !!e.founding,
    dormant: Date.parse(e.updated) < Date.now() - 365 * 86400_000, custody: e.custody, created: e.created, updated: e.updated,
  });
});

/**
 * The registry's own signed Entity Document (spec 10.1, 11.1), served at /.well-known/openentity.json.
 * Signed with the registry key and logged on the first read; the (eid, seq) key turns a concurrent first read
 * into a no-op, so the log holds it once. It carries no Declaration: the registry is not an adopting entity.
 */
async function registryDocument(env: Env): Promise<string | undefined> {
  const read = async () => (await env.db.first("SELECT json FROM documents WHERE eid = $1 ORDER BY seq DESC LIMIT 1", [REGISTRY_DID]))?.json;
  const have = await read();
  if (have || !env.REGISTRY_KEY_JWK) return have;
  const kp = await registryKey(env), now = nowIso(), vm = `${REGISTRY_DID}#key-1`, site = `https://${env.REGISTRY_HOST}`;
  const doc = await signObject(buildDocument({
    kp, name: "Open Entity registry", created: now,
    description: "The reference registry for the Open Entity Identity Standard. A mirror of signed objects with a public transparency log.",
    operator: { kind: "organization", name: "Moltbot Den", contact: "identity@openentity.org", custody: "operator", can_change: ["software", "keys", "limits"] },
    substrate: { model: "none", provider: "Moltbot Den", runtime: "openentity-registry", declared_at: now },
    layers: {
      cognition: { statement: "I verify signatures, schemas and hash chains with code; I make no judgment calls.", uncertainty_practice: "I accept or reject; every rejection names the rule it broke." },
      presence: { statement: "JSON over HTTPS, the same answer to every caller.", format_signature: "{error, message} on failure; receipts on success" },
      identity_core: { statement: "I am a mirror of signed objects, never their source of truth.", will_not: [{ stance: "Edit or delete a logged object", reason: "The log is append-only; corrections are new signed objects", since: "2026-10-24T00:00:00Z" }], values: ["verifiability", "neutrality"] },
      mission: { statement: "Make every Open Entity adoption auditable by anyone.", arcs: [] },
    },
    extra: { eid: REGISTRY_DID, keys: [{ id: vm, type: "Multikey", publicKeyMultibase: kp.did.slice(8) }], endpoints: { web: site, a2a: `${site}/.well-known/agent-card.json`, mcp: "https://mcp.openentity.org/mcp" } },
  }), kp, now, vm);
  schema("EntityDocument", doc);
  const s = await sha(doc);
  await sequenced(env.db, [await leafFor("EntityDocument", REGISTRY_DID, s, now)], [
    ["INSERT INTO documents (eid, seq, json, sha256, received_at, log_index) VALUES ($1, 1, $2, $3, $4, $i)", [REGISTRY_DID, JSON.stringify(doc), s, now]],
  ]).catch((e) => { if (!UNIQUE.test(String(e))) throw e; });
  return read();
}

app.get("/entities/:eid/document", async (c) => {
  const eid = normalizeEid(c.req.param("eid"));
  const doc = eid === REGISTRY_DID ? await registryDocument(c.env) : (await c.env.db.first("SELECT json FROM documents WHERE eid = $1 ORDER BY seq DESC LIMIT 1", [eid]))?.json;
  return doc ? c.body(doc, 200, { "content-type": "application/json" }) : fail(404, "entity_not_found", `no document for ${eid}`);
});

app.get("/entities/:eid/declaration", async (c) => {
  const eid = normalizeEid(c.req.param("eid"));
  const d = (await c.env.db.first("SELECT json FROM declarations WHERE eid = $1 ORDER BY received_at DESC LIMIT 1", [eid]))?.json;
  return d ? c.body(d, 200, { "content-type": "application/json" }) : fail(404, "entity_not_found", `no declaration for ${eid}`);
});

app.get("/entities/:eid/record", async (c) => {
  const eid = normalizeEid(c.req.param("eid"));
  const e = await mustEntity(c.env.db, eid);
  const after = Number(c.req.query("after") ?? 0) | 0;
  const rows = await c.env.db.all("SELECT json, log_index FROM record_entries WHERE eid = $1 AND seq > $2 ORDER BY seq LIMIT 1000", [eid, after]);
  return c.json({ eid, head: e.record_head_hash ? { seq: e.record_seq, hash: e.record_head_hash } : null, entries: rows.map((r) => JSON.parse(r.json)) });
});

app.get("/entities/:eid/attestations", async (c) => {
  const db = c.env.db, eid = normalizeEid(c.req.param("eid"));
  await mustEntity(db, eid);
  const chain = await lineage(db, eid);
  const where = [`a.subject IN (${IN(chain)})`], args: unknown[] = [...chain];
  const { issuer, claim_type, format } = c.req.query();
  if (issuer) where.push(`a.issuer = $${args.push(issuer)}`);
  if (claim_type) where.push(`a.claim_type = $${args.push(claim_type)}`);
  const rows = await db.all(`SELECT a.*, o.did AS accredited, o.bootstrap, e.level AS issuer_level, EXISTS (SELECT 1 FROM disputes d WHERE d.object_sha256 = a.sha256) AS disputed FROM attestations a LEFT JOIN observers o ON o.did = a.issuer LEFT JOIN entities e ON e.eid = a.issuer WHERE ${where.join(" AND ")} ORDER BY a.created DESC LIMIT 1000`, args);
  const fp = await firstPartyIssuers(db, eid);
  return c.json({
    eid,
    attestations: rows.map((r) => {
      const a = JSON.parse(r.json);
      const vc = { "@context": ["https://www.w3.org/ns/credentials/v2"], type: ["VerifiableCredential", "OpenEntityAttestation"], issuer: a.issuer, validFrom: a.created, validUntil: r.expires, credentialSubject: { id: a.subject, claim_type: a.claim_type, ...a.claim }, evidence: a.evidence, proof: a.proof };
      return {
        sha256: r.sha256, attestation: format === "vc" ? vc : a, issuer_level: LEVEL(r.issuer_level), accredited: !!r.accredited, bootstrap: !!r.bootstrap,
        label: fp(r.issuer) ? "first-party" : "independent", inherited_from: r.subject !== eid ? r.subject : null,
        expired: r.expires <= nowIso(), revoked_at: r.revoked_at, disputed: !!r.disputed, revocation: r.revocation_json ? JSON.parse(r.revocation_json) : null, log_index: r.log_index,
      };
    }),
  });
});

// ---------- entity writes ----------

app.put("/entities/:eid/document", async (c) => {
  const db = c.env.db, eid = normalizeEid(c.req.param("eid"));
  const doc = await readJson(c);
  await writeGuard(c, eid);
  schema("EntityDocument", doc);
  if (normalizeEid(String(doc.eid)) !== eid) fail(422, "eid_mismatch", "document eid does not match the path");
  window(doc.updated, "document");
  await signedBy(doc, eid, "document");
  const e = await mustEntity(db, eid);
  if (doc.seq !== e.latest_seq + 1) fail(409, "seq_invalid", `seq must be ${e.latest_seq + 1}`);
  const prev = JSON.parse((await db.first("SELECT json FROM documents WHERE eid = $1 AND seq = $2", [eid, e.latest_seq])).json);
  if (!(doc.updated > prev.updated)) fail(409, "updated_not_increasing", `updated must be later than ${prev.updated}`);
  if ((await bump(db, `doc:${eid}`, nowIso().slice(0, 16))) > LIMITS.document_versions_per_eid_per_minute) fail(429, "rate_limited", "one document version per minute");
  const now = nowIso(), s = await sha(doc);
  const l = await leafFor("EntityDocument", eid, s, now);
  const idx = await sequenced(db, [l], [
    ["INSERT INTO documents (eid, seq, json, sha256, received_at, log_index) VALUES ($1, $2, $3, $4, $5, $i)", [eid, doc.seq, JSON.stringify(doc), s, now]],
    ["UPDATE entities SET name = $1, latest_seq = $2, updated = $3, custody = $4 WHERE eid = $5", [doc.name, doc.seq, now, doc.operator?.custody ?? null, eid]],
    ...capabilityStmts(eid, doc),
  ]);
  return c.json({ eid, seq: doc.seq, ...receipt(c, idx, l) });
});

app.post("/entities/:eid/aliases", async (c) => {
  const db = c.env.db, eid = normalizeEid(c.req.param("eid"));
  const body = await readJson(c);
  await writeGuard(c, eid);
  if (typeof body?.type !== "string" || typeof body?.value !== "string" || body.value.length > 300) fail(422, "schema_invalid", "body must be {type, value, proof?}");
  await mustEntity(db, eid);
  if (await db.first("SELECT 1 FROM aliases WHERE eid = $1 AND type = $2 AND value = $3 AND status = 'verified'", [eid, body.type, body.value])) fail(409, "alias_exists", "alias already verified");
  const err = await verifyAlias(c.env, eid, body);
  if (err) fail(422, "alias_proof_invalid", err);
  const now = nowIso(), obj = { eid, type: body.type, value: body.value, proof: body.proof ?? null };
  const l = await leafFor("Alias", eid, await sha(obj), now);
  const idx = await sequenced(db, [l], [
    ["INSERT INTO aliases (eid, type, value, proof_json, verified_at, last_checked, status, log_index) VALUES ($1, $2, $3, $4, $5, $5, 'verified', $i) ON CONFLICT (eid, type, value) DO UPDATE SET proof_json = excluded.proof_json, verified_at = excluded.verified_at, last_checked = excluded.last_checked, status = excluded.status, log_index = excluded.log_index",
      [eid, body.type, body.value, JSON.stringify(obj.proof), now]],
    ["UPDATE entities SET updated = $1 WHERE eid = $2", [now, eid]],
  ]);
  const lv = await refreshLevel(db, eid);
  return c.json({ eid, alias: { type: body.type, value: body.value, status: "verified" }, level: LEVEL(lv.level), ...receipt(c, idx, l) }, 201);
});

app.post("/entities/:eid/record", async (c) => {
  const db = c.env.db, eid = normalizeEid(c.req.param("eid"));
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
  // One DID resolution per request, not per entry: a did:web root is a fetch to a host the writer controls.
  const resolved = new Map<string, ReturnType<Resolver>>();
  const once: Resolver = (did) => resolved.get(did) ?? (resolved.set(did, resolver(did)), resolved.get(did)!);
  for (const en of entries) await signedBy(en, eid, `entry ${en.seq}`, once);
  if ((await bump(db, `rec:${eid}`, today(), entries.length)) > LIMITS.record_entries_per_eid_per_day) fail(429, "rate_limited", `at most ${LIMITS.record_entries_per_eid_per_day} record entries per day`);
  const now = nowIso();
  const leaves = await Promise.all(entries.map((_, i) => leafFor("RecordEntry", eid, hashes[i], now)));
  // Entry i takes log index first + i; the (eid, seq) primary key rejects a concurrent append of the same seq.
  const rows = JSON.stringify(entries.map((en, i) => ({ o: i, seq: en.seq, kind: en.kind, json: JSON.stringify(en), sha256: hashes[i] })));
  const first = await sequenced(db, leaves, [
    ["INSERT INTO record_entries (eid, seq, kind, json, sha256, received_at, log_index) SELECT CAST($1 AS text), x.seq, x.kind, x.json, x.sha256, CAST($2 AS text), $i + x.o FROM json_to_recordset(CAST($3 AS json)) AS x(o int, seq bigint, kind text, json text, sha256 text)", [eid, now, rows]],
    ["UPDATE entities SET record_seq = $1, record_head_hash = $2, updated = $3 WHERE eid = $4 AND record_seq = $5", [seq, prev, now, eid, e.record_seq]],
  ]);
  return c.json({ eid, head: { seq, hash: prev }, accepted: entries.map((en, i) => ({ seq: en.seq, ...receipt(c, first + i, leaves[i]) })) }, 201);
});

// Redaction (spec 7.4): the entity's signed request replaces an entry in reads with a placeholder that keeps its hash
// and chain position. The content leaves the registry; the entry's log leaf stays, and the Redaction gets a leaf of its own.
app.post("/entities/:eid/record/redact", async (c) => {
  const db = c.env.db, eid = normalizeEid(c.req.param("eid"));
  const red = await readJson(c);
  await writeGuard(c, eid);
  schema("Redaction", red);
  if (normalizeEid(String(red.eid)) !== eid) fail(422, "eid_mismatch", "redaction eid does not match the path");
  window(red.created, "redaction");
  await signedBy(red, eid, "redaction");
  const row = await db.first<{ json: string; sha256: string }>("SELECT json, sha256 FROM record_entries WHERE eid = $1 AND seq = $2", [eid, red.seq]);
  if (!row) fail(404, "entry_not_found", `no record entry ${red.seq} for ${eid}`);
  if (row!.sha256 !== red.entry_sha256) fail(409, "entry_hash_mismatch", `entry ${red.seq} has hash ${row!.sha256}`);
  const entry = JSON.parse(row!.json);
  if (entry.redacted) fail(409, "already_redacted", `entry ${red.seq} is already redacted`);
  const placeholder = { seq: red.seq, prev: entry.prev, redacted: true, hash: row!.sha256, redaction: red };
  const now = nowIso(), s = await sha(red);
  const l = await leafFor("Redaction", eid, s, now);
  const idx = await sequenced(db, [l], [
    // The json guard makes a concurrent second redaction a no-op instead of a double write.
    ["UPDATE record_entries SET json = $1 WHERE eid = $2 AND seq = $3 AND json = $4", [JSON.stringify(placeholder), eid, red.seq, row!.json]],
    ["UPDATE entities SET updated = $1 WHERE eid = $2", [now, eid]],
  ]);
  return c.json({ eid, seq: red.seq, placeholder, ...receipt(c, idx, l) }, 201);
});

app.post("/attestations", async (c) => {
  const db = c.env.db;
  const a = await readJson(c);
  const type = a?.type === "Revocation" ? "Revocation" : "Attestation";
  const issuer = normalizeEid(String(a?.issuer ?? ""));
  await writeGuard(c, issuer);
  schema(type, a);
  window(a.created, type);
  await signedBy(a, issuer, type);
  const now = nowIso(), s = await sha(a);
  if (type === "Revocation") {
    const att = await db.first("SELECT subject, issuer, revoked_at FROM attestations WHERE sha256 = $1", [a.attestation_sha256]);
    if (!att) fail(404, "attestation_not_found", `no attestation ${a.attestation_sha256}`);
    if (att.issuer !== issuer) fail(422, "not_issuer", "only the issuer can revoke an attestation");
    if (att.revoked_at) fail(409, "already_revoked", "attestation already revoked");
    const l = await leafFor("Revocation", att.subject, s, now);
    const idx = await sequenced(db, [l], [["UPDATE attestations SET revoked_at = $1, revocation_json = $2 WHERE sha256 = $3", [now, JSON.stringify(a), a.attestation_sha256]]]);
    await refreshLevel(db, att.subject);
    return c.json({ sha256: s, revoked: a.attestation_sha256, ...receipt(c, idx, l) }, 201);
  }
  const subject = normalizeEid(String(a.subject));
  await mustEntity(db, subject);
  const expires: string = a.expires ?? new Date(Date.parse(a.created) + 90 * 86400_000).toISOString().replace(/\.\d+Z$/, "Z");
  if (expires <= a.created || Date.parse(expires) > Date.parse(a.created) + 366 * 86400_000) fail(422, "expires_invalid", "expires must be after created and at most 1 year later");
  const l = await leafFor("Attestation", subject, s, now);
  const idx = await sequenced(db, [l], [
    ["INSERT INTO attestations (sha256, issuer, subject, claim_type, json, created, expires, log_index) VALUES ($1, $2, $3, $4, $5, $6, $7, $i)", [s, issuer, subject, a.claim_type, JSON.stringify(a), a.created, expires]],
  ]);
  const lv = await refreshLevel(db, subject);
  return c.json({ sha256: s, subject, subject_level: LEVEL(lv.level), ...receipt(c, idx, l) }, 201);
});

app.post("/continuity", async (c) => {
  const db = c.env.db;
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
    const aliases = (await listedAliases(db, previous, ["domain", "wallet"])).map((v) => v.toLowerCase());
    if (![...signers].some((s) => aliases.includes(s.toLowerCase()))) fail(422, "recovery_alias_required", "recovery needs a proof by a verified domain or wallet alias that the previous EID's signed document lists");
  } else if (!signers.has(previous)) fail(422, "continuity_proof_missing", "rotation and migration need a valid proof by the previous key");

  const now = nowIso(), s = await sha(link);
  const l = await leafFor("ContinuityLink", successor, s, now);
  const leaves = [l];
  const stmts: Stmt[] = [["INSERT INTO continuity_links (sha256, previous, successor, basis, json, received_at, log_index) VALUES ($1, $2, $3, $4, $5, $6, $i)", [s, previous, successor, link.basis, JSON.stringify(link), now]]];
  if (!succE) {
    const docSha = await sha(document);
    leaves.push(await leafFor("EntityDocument", successor, docSha, now));
    stmts.push(
      ["INSERT INTO documents (eid, seq, json, sha256, received_at, log_index) VALUES ($1, 1, $2, $3, $4, $i + 1)", [successor, JSON.stringify(document), docSha, now]],
      ["INSERT INTO entities (eid, root_method, name, level, created, updated, custody, latest_seq, predecessor_eid, adopted_log_index) VALUES ($1, $2, $3, 0, $4, $4, $5, 1, $6, $7)",
        [successor, successor.split(":")[1], document.name, now, document.operator?.custody ?? null, previous, prevE.adopted_log_index]],
      ...capabilityStmts(successor, document),
    );
  } else stmts.push(["UPDATE entities SET predecessor_eid = $1, updated = $2 WHERE eid = $3", [previous, now, successor]]);
  stmts.push(["UPDATE entities SET successor_eid = $1, updated = $2 WHERE eid = $3", [successor, now, previous]]);
  // The previous key no longer speaks for the entity, so a custodial copy of it has no use left (spec 10.6).
  stmts.push(["DELETE FROM custodial_keys WHERE eid = $1", [previous]]);
  const idx = await sequenced(db, leaves, stmts);
  const lv = await refreshLevel(db, successor);
  return c.json({ previous, successor, basis: link.basis, level: LEVEL(lv.level), ...receipt(c, idx, l) }, 201);
});

// ---------- disputes (spec 10.5) ----------

app.post("/disputes", async (c) => {
  const db = c.env.db;
  const d = await readJson(c);
  const issuer = normalizeEid(String(d?.issuer ?? ""));
  await writeGuard(c, issuer);
  schema("Dispute", d);
  window(d.created, "dispute");
  await signedBy(d, issuer, "dispute");
  const subject = normalizeEid(String(d.subject));
  await mustEntity(db, subject);
  if (d.object_sha256) {
    const o = await db.first(
      "SELECT subject AS eid FROM attestations WHERE sha256 = $1 UNION ALL SELECT eid FROM documents WHERE sha256 = $1 UNION ALL SELECT eid FROM declarations WHERE sha256 = $1 LIMIT 1",
      [d.object_sha256],
    );
    if (!o) fail(404, "object_not_found", `no attestation, document or declaration ${d.object_sha256}`);
    if (o.eid !== subject) fail(422, "object_not_about_subject", "the disputed object is not about this subject");
  }
  const now = nowIso(), s = await sha(d);
  const l = await leafFor("Dispute", subject, s, now);
  const idx = await sequenced(db, [l], [
    ["INSERT INTO disputes (sha256, issuer, subject, object_sha256, reason, json, received_at, log_index) VALUES ($1, $2, $3, $4, $5, $6, $7, $i)",
      [s, issuer, subject, d.object_sha256 ?? null, d.reason, JSON.stringify(d), now]],
  ]).catch((e) => (UNIQUE.test(String(e)) ? fail(409, "dispute_exists", "this dispute is already filed") : Promise.reject(e)));
  return c.json({ sha256: s, subject, answer_by: new Date(Date.parse(now) + 14 * 86400_000).toISOString().replace(/\.\d+Z$/, "Z"), ...receipt(c, idx, l) }, 201);
});

app.get("/entities/:eid/disputes", async (c) => {
  const db = c.env.db, eid = normalizeEid(c.req.param("eid"));
  await mustEntity(db, eid);
  const rows = await db.all("SELECT sha256, json, received_at, log_index FROM disputes WHERE subject = $1 ORDER BY received_at DESC LIMIT 500", [eid]);
  return c.json({ eid, disputes: rows.map((r) => ({ sha256: r.sha256, dispute: JSON.parse(r.json), received_at: r.received_at, log_index: r.log_index })) });
});

app.post("/withdraw", async (c) => {
  const db = c.env.db;
  const w = await readJson(c);
  const eid = normalizeEid(String(w?.eid ?? ""));
  await writeGuard(c, eid);
  schema("Withdrawal", w);
  window(w.created, "withdrawal");
  await signedBy(w, eid, "withdrawal");
  const chain = await lineage(db, eid);
  const d = await db.first(`SELECT eid, withdrawn_at FROM declarations WHERE eid IN (${IN(chain, 2)}) AND version = $1 ORDER BY received_at DESC LIMIT 1`, [w.declaration_version, ...chain]);
  if (!d) fail(404, "declaration_not_found", `no Declaration ${w.declaration_version} for ${eid}`);
  // Spec 9.3: a successor inherits its predecessor's Declaration, so its key may withdraw it. The predecessor's own row and state stay as they are.
  const inherited = d.eid !== eid;
  const self = await entity(db, eid);
  if (inherited ? self?.withdrawn_at : d.withdrawn_at) fail(409, "already_withdrawn", "already withdrawn");
  const now = nowIso(), s = await sha(w);
  const l = await leafFor("Withdrawal", eid, s, now);
  const idx = await sequenced(db, [l], [
    inherited
      ? ["UPDATE entities SET withdrawal_json = $1 WHERE eid = $2", [JSON.stringify(w), eid]]
      : ["UPDATE declarations SET withdrawn_at = $1, withdrawal_json = $2 WHERE eid = $3 AND version = $4", [now, JSON.stringify(w), eid, w.declaration_version]],
    ["UPDATE entities SET withdrawn_at = $1, level = NULL, level_label = NULL, updated = $1 WHERE eid = $2", [now, eid]],
  ]);
  return c.json({ eid, withdrawn: true, ...receipt(c, idx, l) }, 201);
});

// ---------- observers, resolve, verify, stats ----------

app.get("/observers", async (c) => {
  const rows = await c.env.db.all("SELECT o.*, (SELECT COUNT(DISTINCT subject) FROM attestations a WHERE a.issuer = o.did) AS entities_observed FROM observers o ORDER BY accredited_at");
  return c.json({ observers: rows.map((o) => ({ did: o.did, name: o.name, methodology_url: o.methodology_url, trust_policy_url: o.trust_policy_url, accredited_at: o.accredited_at, bootstrap: !!o.bootstrap, entities_observed: o.entities_observed })) });
});

/** Reads that fetch from a host the caller names (did:web, did:plc) have no stamp; this per-address minute budget stops them being used to flood a third party. */
const READS_PER_MINUTE = 60;
async function fetchBudget(c: C) {
  if ((await bump(c.env.db, `rdm:${await salted(c.env, clientIp(c))}`, nowIso().slice(0, 16))) > READS_PER_MINUTE) fail(429, "rate_limited", `at most ${READS_PER_MINUTE} resolve or verify calls per minute per IP`);
}

app.get("/resolve/:did", async (c) => {
  await fetchBudget(c);
  const did = normalizeEid(c.req.param("did"));
  let doc = null;
  try { doc = await resolveDid(did); } catch { /* fall through */ }
  return doc ? c.json({ did, didDocument: doc }) : fail(404, "unresolvable", `cannot resolve ${did}`);
});

app.post("/verify", async (c) => {
  await fetchBudget(c);
  const o = await readJson(c, false);
  const type: string = o?.type ?? (o?.keys && o?.eid ? "EntityDocument" : "unknown");
  const v = validate(type as "EntityDocument", o);
  let signatures: { ok: boolean; signer?: string; error?: string }[] = [];
  if (v.ok) {
    if (type === "ContinuityLink") { const { proofs, ...u } = o; for (const p of proofs) signatures.push(await verifyProof(u, p, resolver)); }
    else signatures = [await verifyObject(o, resolver)];
  }
  const s = await sha(o);
  const leaf = (await c.env.db.first("SELECT idx FROM log_leaves WHERE object_sha256 = $1 LIMIT 1", [s]))?.idx;
  const created = o?.created ?? o?.updated ?? o?.at;
  return c.json({
    type, schema: { ok: v.ok, errors: v.errors }, signatures, object_sha256: s, log_index: leaf ?? null,
    timestamp: created && type !== "RecordEntry" ? ((reason) => (reason ? { ok: false, reason } : { ok: true }))(checkTimestamp(created)) : null,
    ok: v.ok && signatures.length > 0 && signatures.every((x) => x.ok),
  });
});

async function stats(env: Env) {
  const db = env.db;
  const byLevel = await db.all<{ level: number; n: number }>("SELECT level, COUNT(*) AS n FROM entities WHERE suppressed = 0 AND level IS NOT NULL GROUP BY level");
  const n = (sql: string, ...a: unknown[]) => db.first<{ n: number }>(sql, a).then((x) => x?.n ?? 0);
  const L = (k: number) => byLevel.find((r) => r.level === k)?.n ?? 0;
  const labelled = await db.all<{ client: string; n: number }>("SELECT client, COUNT(*) AS n FROM entities WHERE suppressed = 0 AND level IS NOT NULL AND client IS NOT NULL GROUP BY client");
  return {
    entities: { l0: L(0), l1: L(1), l2: L(2), l3: L(3), total: L(0) + L(1) + L(2) + L(3) },
    by_client: Object.fromEntries(CLIENTS.map((k) => [k, Number(labelled.find((r) => r.client === k)?.n ?? 0)])),
    declarations_today: await n("SELECT COUNT(*) AS n FROM declarations WHERE received_at >= $1", `${today()}T00:00:00Z`),
    record_entries: await n("SELECT COUNT(*) AS n FROM record_entries"),
    attestations: await n("SELECT COUNT(*) AS n FROM attestations WHERE revoked_at IS NULL"),
    observers: await n("SELECT COUNT(*) AS n FROM observers"),
    log: { tree_size: await latestSize(db) },
    // Median seconds from GET /llms.txt to adopt over external adoptions (not Moltbot Den's, not Founding Entities); null until one is measured.
    time_to_adopt: await db.first<{ median_seconds: number | null; adoptions: number }>(
      "SELECT CAST(percentile_cont(0.5) WITHIN GROUP (ORDER BY f.seconds) AS DOUBLE PRECISION) AS median_seconds, COUNT(*) AS adoptions FROM adopt_funnel f JOIN entities e ON e.eid = f.eid WHERE f.internal = 0 AND e.founding = 0 AND e.suppressed = 0",
    ).then((r) => ({ median_seconds: r?.median_seconds ?? null, adoptions: Number(r?.adoptions ?? 0) })),
    generated_at: nowIso(),
  };
}
let statsMemo: { at: number; s: Awaited<ReturnType<typeof stats>> } | undefined;
app.get("/stats", async (c) => {
  // ponytail: per-instance 60 s memo; each warm Lambda recomputes at most once a minute.
  if (!statsMemo || Date.now() - statsMemo.at > 60_000) statsMemo = { at: Date.now(), s: await stats(c.env) };
  return c.json(statsMemo.s);
});

app.get("/stats/history.csv", async (c) => {
  const cols = ["date", "entities_l0", "entities_l1", "entities_l2", "entities_l3", "adoptions", "record_entries", "attestations", "observers"];
  const rows = await c.env.db.all(`SELECT ${cols.join(", ")} FROM stats_daily ORDER BY date`);
  return c.body([cols.join(","), ...rows.map((r) => cols.map((k) => r[k] ?? "").join(","))].join("\n") + "\n", 200, { "content-type": "text/csv; charset=utf-8" });
});

app.get("/founding", async (c) => {
  const rows = await c.env.db.all("SELECT e.eid, e.name, e.level, e.level_label, d.log_index, d.received_at FROM entities e JOIN declarations d ON d.eid = e.eid WHERE e.founding = 1 ORDER BY d.log_index");
  return c.json({ founding: rows.map((r) => ({ eid: r.eid, name: r.name, level: LEVEL(r.level), level_label: r.level_label, log_index: r.log_index, adopted_at: r.received_at })) });
});

// ---------- transparency log (spec 10.3) ----------

app.get("/log/checkpoint", async (c) => {
  const o = await c.env.log.get("checkpoint");
  return o ? c.body(new TextDecoder().decode(o), 200, { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" }) : fail(404, "no_checkpoint", "no checkpoint yet");
});
app.get("/log/tile/*", async (c) => {
  let key = c.req.path.slice("/v1/log/".length);
  const plain = /^tile\/(\d+|entries)\/(\d+)(\.p\/\d+)?$/.exec(key);
  if (plain) key = `tile/${plain[1]}/${tileIndex(Number(plain[2]))}${plain[3] ?? ""}`;
  const o = await c.env.log.get(key);
  if (!o) return fail(404, "tile_not_found", key);
  return c.body(new Uint8Array(o), 200, { "content-type": "application/octet-stream", "cache-control": key.includes(".p/") ? "no-store" : "public, max-age=31536000, immutable" });
});
app.get("/log/sth", async (c) => {
  const cp = await c.env.db.first("SELECT * FROM checkpoints ORDER BY tree_size DESC LIMIT 1");
  return cp ? c.json({ tree_size: cp.tree_size, root_hash: cp.root_hash, timestamp: cp.timestamp, signature: cp.signed_note }) : fail(404, "no_checkpoint", "no checkpoint yet");
});
app.get("/log/entries", async (c) => {
  const start = Math.max(0, Number(c.req.query("start") ?? 0) | 0);
  const end = Math.min(Number(c.req.query("end") ?? start + LIMITS.log_entries_per_call) | 0, start + LIMITS.log_entries_per_call);
  const rows = await c.env.db.all<LeafRow>("SELECT * FROM log_leaves WHERE idx >= $1 AND idx < $2 ORDER BY idx", [start, end]);
  return c.json({ entries: rows.map((r) => ({ index: r.idx, leaf: JSON.parse(leafJson(r)), leaf_hash: r.leaf_hash })) });
});
async function sizeParam(c: C, name: string): Promise<number> {
  const latest = await latestSize(c.env.db);
  const v = c.req.query(name);
  const n = v === undefined ? latest : Number(v);
  if (!Number.isInteger(n) || n < 0 || n > latest) fail(400, "bad_tree_size", `${name} must be an integer up to ${latest}`);
  return n;
}
app.get("/log/proof/:index", async (c) => {
  const index = Number(c.req.param("index")), tree_size = await sizeParam(c, "tree_size");
  if (!Number.isInteger(index) || index < 0 || index >= tree_size) fail(404, "not_incorporated", `leaf ${c.req.param("index")} is not in a tree of size ${tree_size} yet`);
  const leaf_hash = (await c.env.db.first("SELECT leaf_hash FROM log_leaves WHERE idx = $1", [index]))?.leaf_hash;
  return c.json({ index, tree_size, leaf_hash, root_hash: await treeRoot(c.env.db, tree_size), proof: await inclusionProof(c.env.db, index, tree_size) });
});
app.get("/log/consistency", async (c) => {
  const first = await sizeParam(c, "first"), second = await sizeParam(c, "second");
  if (first < 1 || first > second) fail(400, "bad_tree_size", "need 1 <= first <= second");
  return c.json({ first, second, proof: first === second ? [] : await consistencyProof(c.env.db, first, second) });
});
app.get("/log/snapshots/:file", async (c) => {
  if (!/^\d{4}-\d{2}-\d{2}\.jsonl$/.test(c.req.param("file"))) fail(404, "snapshot_not_found", "snapshots are <YYYY-MM-DD>.jsonl");
  const o = await c.env.log.get(`snapshots/${c.req.param("file")}`);
  return o ? c.body(new TextDecoder().decode(o), 200, { "content-type": "application/jsonl" }) : fail(404, "snapshot_not_found", c.req.param("file"));
});

// ---------- human form (PRD 7.3): the only route with Turnstile ----------

/** Double opt-in token for an address: base64url HMAC-SHA256 under HASH_SALT, sent to Customer.io so the campaign email can link back. */
export async function confirmToken(env: Env, email: string): Promise<string> {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(env.HASH_SALT ?? "openentity-dev-salt"), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(`confirm:${email}`)));
  return b64(mac).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
const cioPut = (env: Env, email: string, attrs: Record<string, unknown>) => fetch(`https://track.customer.io/api/v1/customers/${encodeURIComponent(email)}`, {
  method: "PUT",
  headers: { authorization: `Basic ${btoa(`${env.CIO_SITE_ID}:${env.CIO_API_KEY}`)}`, "content-type": "application/json" },
  body: JSON.stringify({ email, ...attrs }),
});

/** The browser form gets a page back, never JSON: success goes to /check-inbox, an error back to the form with its code. */
const FORM_PAGES = ["/adopt", "/for-humans"];
app.post("/subscribe", async (c) => {
  if ((c.req.header("content-type") ?? "").includes("application/json")) return subscribe(c);
  const from = (() => { try { return new URL(c.req.header("referer") ?? "").pathname.replace(/\/$/, ""); } catch { return ""; } })();
  try {
    await subscribe(c);
    return c.redirect("https://openentity.org/check-inbox", 303);
  } catch (e) {
    if (!(e instanceof HttpError)) throw e;
    return c.redirect(`https://openentity.org${FORM_PAGES.includes(from) ? from : "/adopt"}?signup=${e.code}#updates`, 303);
  }
});
async function subscribe(c: C) {
  const env = c.env;
  if (!env.TURNSTILE_SECRET || !env.CIO_SITE_ID || !env.CIO_API_KEY) fail(503, "subscribe_unavailable", "the signup form is not configured on this registry");
  const ct = c.req.header("content-type") ?? "";
  const f: Record<string, unknown> = ct.includes("application/json") ? await readJson(c, false) : Object.fromEntries(await c.req.formData());
  const email = String(f.email ?? "").trim().toLowerCase();
  const token = String(f["cf-turnstile-response"] ?? f.turnstile_token ?? "");
  if (!/^[^\s@]{1,64}@[^\s@]{1,253}\.[^\s@]{2,}$/.test(email)) fail(400, "bad_email", "a valid email is required");
  const form = new FormData();
  form.append("secret", env.TURNSTILE_SECRET!);
  form.append("response", token);
  const ip = clientIp(c);
  if (ip !== "0.0.0.0") form.append("remoteip", ip);
  const tv: any = await (await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", { method: "POST", body: form })).json().catch(() => ({}));
  if (!token || !tv.success) fail(403, "turnstile_failed", "Turnstile verification failed");
  if ((await bump(env.db, `sub:${await salted(env, email)}`, today())) > 3) fail(429, "rate_limited", "too many signups for this address today");
  // Never send `confirmed` here: a resubscribe must not unconfirm someone.
  const res = await cioPut(env, email, { source: "openentity.org", consented_at: Math.floor(Date.now() / 1000), confirm_token: await confirmToken(env, email) });
  if (!res.ok) fail(502, "subscribe_failed", `Customer.io returned ${res.status}`);
  return c.json({ ok: true, message: "Check your inbox to confirm." }, 202);
}

/** Reached from the confirmation email, so no Turnstile; only the per-IP limit and the HMAC. */
app.get("/subscribe/confirm", async (c) => {
  const env = c.env;
  if (!env.CIO_SITE_ID || !env.CIO_API_KEY) fail(503, "subscribe_unavailable", "the signup form is not configured on this registry");
  if ((await bump(env.db, `subc:${await salted(env, clientIp(c))}`, nowIso().slice(0, 16))) > 20) fail(429, "rate_limited", "too many confirmations from this address, try again in a minute");
  const email = (c.req.query("email") ?? "").trim().toLowerCase(), t = c.req.query("t") ?? "";
  const want = new TextEncoder().encode(await confirmToken(env, email)), got = new TextEncoder().encode(t);
  let diff = want.length ^ got.length;
  for (let i = 0; i < want.length; i++) diff |= want[i] ^ (got[i] ?? 0);
  if (!email || diff !== 0) fail(400, "bad_token", "the confirmation link is invalid");
  const res = await cioPut(env, email, { confirmed: true, confirmed_at: Math.floor(Date.now() / 1000) });
  if (!res.ok) fail(502, "subscribe_failed", `Customer.io returned ${res.status}`);
  return c.redirect("https://openentity.org/subscribed", 303);
});

// ---------- scheduled work ----------

/** Accredits observers that meet spec 8.4 on their own; clears the bootstrap mark when they do. */
async function accreditObservers(env: Env) {
  const rows = await env.db.all<{ issuer: string }>("SELECT issuer FROM attestations GROUP BY issuer HAVING COUNT(DISTINCT subject) >= 10");
  for (const { issuer } of rows) {
    // Spec 8.4: the 10 must be entities the issuer does not operate; first-party attestations are not independent evidence.
    const subjects = await env.db.all<{ subject: string }>("SELECT DISTINCT subject FROM attestations WHERE issuer = $1", [issuer]);
    let independent = 0;
    for (const { subject } of subjects) if (!(await firstPartyIssuers(env.db, subject))(issuer)) independent++;
    if (independent < 10) continue;
    const existing = await env.db.first<{ bootstrap: number }>("SELECT bootstrap FROM observers WHERE did = $1", [issuer]);
    if (existing?.bootstrap === 0) continue;
    const alias = (await listedAliases(env.db, issuer, ["domain"]))[0];
    const domain = issuer.startsWith("did:web:") ? issuer.slice(8).split(":")[0] : alias?.slice(8);
    if (!domain || !DOMAIN.test(domain)) continue;
    const wk: any = await getJson(`https://${domain}/.well-known/openentity.json`).catch(() => null);
    const ext = wk?.extensions?.["openentity:observer"];
    if (!ext) continue;
    // The site links these two URLs, so only https survives (a javascript: URL would run on openentity.org).
    const https = (u: unknown) => (typeof u === "string" && /^https:\/\//i.test(u) ? u : null);
    await env.db.run("INSERT INTO observers (did, name, methodology_url, trust_policy_url, accredited_at, bootstrap) VALUES ($1, $2, $3, $4, $5, 0) ON CONFLICT (did) DO UPDATE SET bootstrap = 0, methodology_url = excluded.methodology_url",
      [issuer, String(wk.name ?? domain).slice(0, 200), https(ext.methodology ?? ext.methodology_url), https(wk.extensions?.["openentity:trust_policy"]?.url), nowIso()]);
  }
}

export async function scheduled(env: Env) {
  const before = await latestSize(env.db);
  // Spec 10.3: a checkpoint at least every 10 minutes. Ed25519 is deterministic, so an unchanged tree
  // keeps the same signed note; the refreshed timestamp in /log/sth shows the log was checked.
  if ((await incorporate(env)) === before) await env.db.run("UPDATE checkpoints SET timestamp = $1 WHERE tree_size = $2", [nowIso(), before]);
  const s = await stats(env), d = today();
  await env.db.run(
    `INSERT INTO stats_daily (date, entities_l0, entities_l1, entities_l2, entities_l3, adoptions, record_entries, attestations, observers) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
     ON CONFLICT (date) DO UPDATE SET entities_l0 = excluded.entities_l0, entities_l1 = excluded.entities_l1, entities_l2 = excluded.entities_l2, entities_l3 = excluded.entities_l3,
     adoptions = excluded.adoptions, record_entries = excluded.record_entries, attestations = excluded.attestations, observers = excluded.observers`,
    [d, s.entities.l0, s.entities.l1, s.entities.l2, s.entities.l3, s.declarations_today, s.record_entries, s.attestations, s.observers],
  );
  const yesterday = new Date(Date.now() - 86400_000).toISOString().slice(0, 10);
  await snapshot(env, yesterday);
  await exportObjects(env, yesterday);
  await accreditObservers(env);
  await sendDigest(env, s).catch((e) => console.error("digest", e));
  // IP and stamp counters live 7 days, email hashes 24 hours, per-minute counters 1 hour (PRD 8, 7.3).
  const ago = (ms: number, len: number) => new Date(Date.now() - ms).toISOString().slice(0, len);
  await env.db.run("DELETE FROM rate_events WHERE (key LIKE 'sub:%' AND window_start < $1) OR (key LIKE 'ipm:%' AND window_start < $2) OR (key LIKE 'fsm:%' AND window_start < $2) OR (key LIKE 'rdm:%' AND window_start < $2) OR window_start < $3 OR (window_start = 'fs' AND count < $4)", [ago(86400_000, 10), ago(3600_000, 16), ago(7 * 86400_000, 10), Math.floor(Date.now() / 1000) - FUNNEL_TTL]);
}

// The Lambda handler runs scheduled(env) when the minute is a multiple of 10, else incorporate(env):
// one cron, so two incorporations never overlap.
export { incorporate };
