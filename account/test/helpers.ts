import { createHash, generateKeyPairSync, randomUUID, sign as nodeSign, type KeyObject } from "node:crypto";
import { readFile } from "node:fs/promises";
import { canonicalize } from "@openentity/sdk";
import { type Hono } from "hono";
import type { Deps } from "../src/app.ts";
import { type Db, splitSql } from "../src/db.ts";
import { derToJose, publicKey } from "../src/keys.ts";
import { lowS } from "../src/keylog.ts";
import { rpFor } from "../src/passkey.ts";

/** Tests only: an in-memory Postgres with account/schema.sql applied statement by statement, as the migration does. */
export async function pgliteDb(): Promise<Db> {
  const { PGlite } = await import("@electric-sql/pglite");
  const pg = new PGlite();
  for (const s of splitSql(await readFile(new URL("../schema.sql", import.meta.url), "utf8"))) await pg.exec(s);
  type Q = Pick<InstanceType<typeof PGlite>, "query">;
  const make = (q: Q, inTx: boolean): Db => ({
    all: async (sql, params) => (await q.query<any>(sql, params)).rows,
    first: async (sql, params) => (await q.query<any>(sql, params)).rows[0] ?? null,
    run: async (sql, params) => ({ changes: (await q.query(sql, params)).affectedRows ?? 0 }),
    tx(fn) { return inTx ? fn(this) : pg.transaction((t) => fn(make(t, true))); },
  });
  return make(pg, false);
}

/** An account row to hang sessions on. */
export async function account(db: Db, id = `acct_${Math.random().toString(36).slice(2, 12)}`): Promise<string> {
  await db.run("INSERT INTO accounts (id, app_account_token, created_at) VALUES ($1, $2, $3)", [id, crypto.randomUUID(), 1]);
  return id;
}

export const HOST = "staging.account.openentity.org", ORIGIN = `https://${HOST}`, SERVICE_DID = `did:web:${HOST}`;
const jwkOf = (k: KeyObject) => k.export({ format: "jwk" }) as any;

/** Throwaway stand-ins for the KMS keys (never real keys) and Deps for a test app. `codes` collects sent email codes. */
export async function testDeps(over: Partial<Deps> = {}): Promise<Deps & { codes: string[] }> {
  const token = generateKeyPairSync("ec", { namedCurve: "P-256" }), did = generateKeyPairSync("ed25519"), close = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const codes: string[] = [];
  return {
    stage: "staging", host: HOST, db: await pgliteDb(), pepper: "test-pepper", rp: rpFor(HOST), web: {},
    keys: {
      token: await publicKey(jwkOf(token.publicKey), async (b) => derToJose(new Uint8Array(nodeSign("sha256", b, { key: token.privateKey, dsaEncoding: "der" })))),
      did: await publicKey(jwkOf(did.publicKey), async (b) => new Uint8Array(nodeSign(null, b, did.privateKey))),
      close: await publicKey(jwkOf(close.publicKey), async (b) => new Uint8Array(nodeSign("sha256", b, { key: close.privateKey, dsaEncoding: "ieee-p1363" }))),
    },
    sendCode: async (_e, code) => { codes.push(code); },
    apple: { native: ["org.openentity.app"], web: [] }, google: [], androidFingerprints: [], signinOpen: true,
    codes, ...over,
  };
}

export type Call = (method: string, path: string, body?: unknown, headers?: Record<string, string>) => Promise<{ status: number; body: any; text: string; headers: Headers }>;
export const caller = (app: Hono): Call => async (method, path, body, headers = {}) => {
  const res = await app.request(`${ORIGIN}${path}`, { method, headers: { "content-type": "application/json", ...headers }, body: body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body) });
  const text = await res.text();
  let json: any = null;
  try { json = JSON.parse(text); } catch { /* not JSON */ }
  return { status: res.status, body: json, text, headers: res.headers };
};

/** Signs in a new owner with the email code; returns the access token and account id. */
export async function signIn(call: Call, d: { codes: string[] }, email = `${randomUUID()}@example.com`) {
  const client = { platform: "ios", install_id: randomUUID() };
  const s = await call("POST", "/v1/auth/email/start", { email, client });
  const r = await call("POST", "/v1/auth/email/verify", { challenge_id: s.body.challenge_id, code: d.codes.at(-1), client });
  return { token: r.body.access_token as string, accountId: r.body.account.id as string, auth: { authorization: `Bearer ${r.body.access_token}` } };
}

/** A throwaway P-256 key: its key log credential, and raw low-S r||s ECDSA over SHA-256 of the bytes given. */
export function p256Key(o: { type?: "p256" | "webauthn"; label?: string } = {}) {
  const k = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const { x, y } = jwkOf(k.publicKey);
  const jwk = { kty: "EC", crv: "P-256", x, y };
  const kid = createHash("sha256").update(`{"crv":"P-256","kty":"EC","x":"${x}","y":"${y}"}`).digest("base64url");
  const type = o.type ?? "p256";
  const credential: Record<string, unknown> = type === "webauthn"
    ? { kid, type, jwk, credential_id: createHash("sha256").update(kid).digest().subarray(0, 16).toString("base64url"), rp_id: HOST, label: "Passkey", platform: "ios" }
    : { kid, type, jwk, label: o.label ?? "iPhone", platform: "ios", key_storage: "secure_enclave", attestation: { type: "none", verified: false } };
  const raw = (data: string | Uint8Array) => lowS(new Uint8Array(nodeSign("sha256", typeof data === "string" ? Buffer.from(data) : data, { key: k.privateKey, dsaEncoding: "ieee-p1363" })));
  const sign = (data: string | Uint8Array) => Buffer.from(raw(data)).toString("base64url");
  let counter = 0;
  /** A WebAuthn get() assertion over `digest` (the challenge), as a passkey on this RP makes it: low-S strict DER. */
  const assert = (digest: Uint8Array) => {
    const clientData = Buffer.from(JSON.stringify({ type: "webauthn.get", challenge: Buffer.from(digest).toString("base64url"), origin: ORIGIN, crossOrigin: false }));
    const authData = Buffer.concat([createHash("sha256").update(HOST).digest(), Buffer.from([0x05]), Buffer.from(new Uint32Array([++counter]).buffer).reverse()]);
    const rs = raw(Buffer.concat([authData, createHash("sha256").update(clientData).digest()]));
    const int = (b: Uint8Array) => { let i = 0; while (i < 31 && b[i] === 0) i++; const v = b.subarray(i); return Buffer.concat([Buffer.from([2, v.length + (v[0] & 0x80 ? 1 : 0)]), v[0] & 0x80 ? Buffer.from([0]) : Buffer.alloc(0), v]); };
    const seq = Buffer.concat([int(rs.subarray(0, 32)), int(rs.subarray(32))]);
    return { signature: Buffer.concat([Buffer.from([0x30, seq.length]), seq]).toString("base64url"), authenticator_data: authData.toString("base64url"), client_data_json: clientData.toString("base64url") };
  };
  return { kid, jwk, credential, sign, assert };
}
export type Key = ReturnType<typeof p256Key>;

/** A key log entry as its JCS line, signed by `by` in its own form (p256, or a WebAuthn assertion for a passkey). */
export function entry(by: Key, e: { seq: number; prev: string | null; op: string; body: unknown; ts?: number }): string {
  const unsigned = { v: 1, ts: e.ts ?? Math.floor(Date.now() / 1000), ...e };
  const auth = by.credential.type === "webauthn"
    ? { kid: by.kid, form: "webauthn", ...by.assert(createHash("sha256").update(canonicalize(unsigned)).digest()) }
    : { kid: by.kid, form: "p256", signature: by.sign(canonicalize(unsigned)) };
  return canonicalize({ ...unsigned, auth });
}
export const lineHash = (line: string) => createHash("sha256").update(line).digest("hex");
export const ownerId = (genesis: string) => {
  const b = createHash("sha256").update(genesis).digest(), A = "abcdefghijklmnopqrstuvwxyz234567";
  let out = "", bits = 0, value = 0;
  for (const x of b) { value = (value << 8) | x; bits += 8; while (bits >= 5) out += A[(value >> (bits -= 5)) & 31]; value &= (1 << bits) - 1; }
  return bits ? out + A[(value << (5 - bits)) & 31] : out;
};

/** Registers `root` as the account's root passkey (what POST /v1/auth/passkey/verify mode register stores). */
export async function registerRoot(db: Db, accountId: string, root: Key) {
  await db.run("INSERT INTO methods (id, account_id, type, subject, data, created_at) VALUES ($1, $2, 'passkey', $3, $4, 1)",
    [`mth_${randomUUID().slice(0, 8)}`, accountId, root.credential.credential_id, JSON.stringify({ jwk: root.jwk, key_id: root.kid })]);
}

/** An approval/2.0 object signed in the p256 form. */
export function approval(by: Key, a: { verifier_did: string; owner_did: string; request_id: string; payload_digest: string; decision?: string; expires_at?: number }) {
  const full = { decision: "approve", expires_at: Math.floor(Date.now() / 1000) + 300, ...a };
  const preimage = ["approval/2.0", full.verifier_did, full.owner_did, full.request_id, full.payload_digest, full.decision, String(full.expires_at)].join("|");
  const fields = { version: "approval/2.0", verifier_did: full.verifier_did, owner_did: full.owner_did, request_id: full.request_id, payload_digest: full.payload_digest, decision: full.decision, expires_at: full.expires_at, device_id: by.kid };
  return by.credential.type === "webauthn"
    ? { ...fields, form: "webauthn", ...by.assert(createHash("sha256").update(preimage).digest()) }
    : { ...fields, form: "p256", signature: by.sign(preimage) };
}
export const approvalHeader = (a: unknown) => ({ "x-oe-approval": Buffer.from(JSON.stringify(a)).toString("base64url") });
