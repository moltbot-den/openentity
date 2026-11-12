import { X509Certificate, createHash, generateKeyPairSync, randomUUID, sign as nodeSign, type KeyObject } from "node:crypto";
import { isoCBOR } from "@simplewebauthn/server/helpers";
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
    // Tests never reach the network: product calls, the registry and did:web lookups need a stand-in fetch.
    fetch: (async (url: RequestInfo | URL) => { throw new Error(`no network in tests: ${String(url)}`); }) as typeof fetch,
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

/** Records what the real notice path delivers (notify.ts notifyOwner): pushes through a stand-in APNs, and mail. */
export function noticeRecorder() {
  const pushes: { type: string; id: string }[] = [], mail: { to: string; subject: string }[] = [];
  const web = {
    apns: async (_t: unknown, m: { type: string; id: string }) => { pushes.push({ type: m.type, id: m.id }); return null; },
    sendMail: async (to: string, subject: string) => { mail.push({ to, subject }); },
  };
  /** Gives the signed-in install a push token, so notices reach it. */
  const device = (db: Db, accountId: string, install: string) =>
    db.run("INSERT INTO push_tokens (install_id, account_id, provider, token, environment, created_at, updated_at) VALUES ($1, $2, 'apns', $3, 'sandbox', 1, 1)", [install, accountId, `tok-${install}`]);
  return { pushes, mail, web: web as any, device };
}

/** Signs in a new owner with the email code; returns the access token and account id. */
export async function signIn(call: Call, d: { codes: string[] }, email = `${randomUUID()}@example.com`) {
  const client = { platform: "ios", install_id: randomUUID() };
  const s = await call("POST", "/v1/auth/email/start", { email, client });
  const r = await call("POST", "/v1/auth/email/verify", { challenge_id: s.body.challenge_id, code: d.codes.at(-1), client });
  return { token: r.body.access_token as string, accountId: r.body.account.id as string, install: client.install_id, auth: { authorization: `Bearer ${r.body.access_token}` } };
}

// ---------------------------------------------------------------- a stand-in App Attest chain (throwaway keys, test root)

const der = (tag: number, ...parts: Buffer[]) => {
  const v = Buffer.concat(parts), n = v.length;
  return Buffer.concat([Buffer.from([tag, ...(n < 128 ? [n] : n < 256 ? [0x81, n] : [0x82, n >> 8, n & 255])]), v]);
};
const hex = (h: string) => Buffer.from(h, "hex");
const ECDSA_SHA256 = der(0x30, hex("06082a8648ce3d040302"));
const cn = (name: string) => der(0x30, der(0x31, der(0x30, hex("0603550403"), der(0x0c, Buffer.from(name)))));
const utc = (t: Date) => der(0x17, Buffer.from(`${t.toISOString().replace(/[-:T]/g, "").slice(2, 14)}Z`));

/** An X.509 v3 certificate signed with ECDSA SHA-256 by `signer`. */
export function testCert(o: { subject: string; issuer: string; key: KeyObject; signer: KeyObject; ca?: boolean; extensions?: Buffer[]; from?: Date; to?: Date }): Buffer {
  // A CA: basicConstraints CA, and keyUsage keyCertSign and cRLSign, as Apple's and Google's issuers carry.
  const exts = [...(o.ca ? [der(0x30, hex("0603551d13"), hex("0101ff"), der(0x04, der(0x30, hex("0101ff")))), der(0x30, hex("0603551d0f"), hex("0101ff"), der(0x04, hex("03020106")))] : []), ...(o.extensions ?? [])];
  const tbs = der(0x30,
    der(0xa0, hex("020102")), hex("020101"), ECDSA_SHA256, cn(o.issuer),
    der(0x30, utc(o.from ?? new Date(Date.now() - 3_600_000)), utc(o.to ?? new Date(Date.now() + 86_400_000))), cn(o.subject),
    o.key.export({ type: "spki", format: "der" }), ...(exts.length ? [der(0xa3, der(0x30, ...exts))] : []));
  return der(0x30, tbs, ECDSA_SHA256, der(0x03, Buffer.from([0]), nodeSign("sha256", tbs, o.signer)));
}

/** A root and an intermediate standing in for Apple's, and attestations of fresh App Attest keys under them. */
export function fakeAppAttest() {
  const root = generateKeyPairSync("ec", { namedCurve: "P-256" }), inter = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const rootDer = testCert({ subject: "Test App Attestation Root", issuer: "Test App Attestation Root", key: root.publicKey, signer: root.privateKey, ca: true });
  const interDer = testCert({ subject: "Test App Attestation CA 1", issuer: "Test App Attestation Root", key: inter.publicKey, signer: root.privateKey, ca: true });
  /** An attestation object for a new App Attest key over `clientDataHash`; `tweak` breaks one part for the guard tests. */
  const attest = (clientDataHash: Uint8Array, tweak: { aaguid?: string; counter?: number; appId?: string; nonce?: Buffer; keyId?: Buffer } = {}) => {
    const leaf = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const point = leaf.publicKey.export({ type: "spki", format: "der" }).subarray(-65);
    const keyId = tweak.keyId ?? createHash("sha256").update(point).digest();
    const counter = Buffer.alloc(4);
    counter.writeUInt32BE(tweak.counter ?? 0);
    const authData = Buffer.concat([
      createHash("sha256").update(tweak.appId ?? "7R835D5LDZ.org.openentity.app").digest(), Buffer.from([0x40]), counter,
      Buffer.from(tweak.aaguid ?? "appattestdevelop"), Buffer.from([0, keyId.length]), keyId, Buffer.from([0xa0]),
    ]);
    const nonce = tweak.nonce ?? createHash("sha256").update(authData).update(clientDataHash).digest();
    const ext = der(0x30, hex("06092a864886f763640802"), der(0x04, der(0x30, der(0xa1, der(0x04, nonce)))));
    const leafDer = testCert({ subject: "App Attest key", issuer: "Test App Attestation CA 1", key: leaf.publicKey, signer: inter.privateKey, extensions: [ext] });
    const obj = isoCBOR.encode(new Map<string, any>([["fmt", "apple-appattest"], ["attStmt", new Map<string, any>([["x5c", [new Uint8Array(leafDer), new Uint8Array(interDer)]], ["receipt", new Uint8Array(4)]])], ["authData", new Uint8Array(authData)]]));
    let uses = 0;
    /** An assertion by this App Attest key over `clientDataHash` (what the app sends in X-OE-App-Attest). */
    const assertion = (clientDataHash: Uint8Array, o: { counter?: number } = {}) => {
      const c = Buffer.alloc(4);
      c.writeUInt32BE(o.counter ?? ++uses);
      const auth = Buffer.concat([createHash("sha256").update("7R835D5LDZ.org.openentity.app").digest(), Buffer.from([0x40]), c]);
      const nonce = createHash("sha256").update(auth).update(clientDataHash).digest();
      return Buffer.from(isoCBOR.encode(new Map<string, any>([["signature", new Uint8Array(nodeSign("sha256", nonce, leaf.privateKey))], ["authenticatorData", new Uint8Array(auth)]]))).toString("base64url");
    };
    return { key_id: Buffer.from(keyId).toString("base64"), attestation_object: Buffer.from(obj).toString("base64url"), assertion };
  };
  return { root: new X509Certificate(rootDer), attest };
}

/** context-specific EXPLICIT [n], with the multi-byte tag form from 31 up. */
const ctx = (n: number, inner: Buffer) => {
  const tag = n < 31 ? [0xa0 | n] : [0xbf, ...(n >= 128 ? [0x80 | (n >> 7)] : []), n & 0x7f];
  const len = inner.length;
  return Buffer.concat([Buffer.from([...tag, ...(len < 128 ? [len] : len < 256 ? [0x81, len] : [0x82, len >> 8, len & 255])]), inner]);
};
const int = (n: number) => der(0x02, n < 128 ? Buffer.from([n]) : Buffer.from([n >> 8, n & 255]));

/** A root and an intermediate standing in for Google's, and Key Attestation chains of fresh Keystore keys under them. */
export function fakeAndroidKey() {
  const root = generateKeyPairSync("ec", { namedCurve: "P-256" }), inter = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const rootDer = testCert({ subject: "Test Key Attestation Root", issuer: "Test Key Attestation Root", key: root.publicKey, signer: root.privateKey, ca: true });
  const interDer = testCert({ subject: "Test Key Attestation CA", issuer: "Test Key Attestation Root", key: inter.publicKey, signer: root.privateKey, ca: true });
  /** A chain for a new P-256 key whose attestationChallenge is `challenge`; `o` changes one property for the guard tests. */
  const attest = (challenge: Uint8Array, o: { level?: number; pkg?: string; origin?: number; biometric?: boolean; noAuth?: boolean } = {}) => {
    const key = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const appId = der(0x30, der(0x31, der(0x30, der(0x04, Buffer.from(o.pkg ?? "org.openentity.app")), int(1))), der(0x31, der(0x04, Buffer.alloc(32, 9))));
    const hw = der(0x30, ctx(702, int(o.origin ?? 0)), ...(o.biometric === false ? [] : [ctx(504, int(2))]), ...(o.noAuth ? [ctx(503, hex("0500"))] : []));
    const desc = der(0x30, int(300), der(0x0a, Buffer.from([o.level ?? 1])), int(300), der(0x0a, Buffer.from([o.level ?? 1])), der(0x04, Buffer.from(challenge)), der(0x04, Buffer.alloc(0)), der(0x30, ctx(709, der(0x04, appId))), hw);
    const ext = der(0x30, hex("060a2b06010401d679020111"), der(0x04, desc));
    const leaf = testCert({ subject: "Android Keystore Key", issuer: "Test Key Attestation CA", key: key.publicKey, signer: inter.privateKey, extensions: [ext] });
    const jwk = key.publicKey.export({ format: "jwk" }) as any;
    return { chain: [leaf, interDer].map((c) => c.toString("base64")), jwk: { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y }, sign: (body: string | Uint8Array) => nodeSign("sha256", Buffer.from(body), key.privateKey).toString("base64url") };
  };
  return { root: new X509Certificate(rootDer), attest };
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

/** Registers `root` as the account's passkey (what POST /v1/auth/passkey/verify mode register stores); `pending` after a key log exists. */
export async function registerRoot(db: Db, accountId: string, root: Key, o: { pending?: boolean } = {}) {
  await db.run("INSERT INTO methods (id, account_id, type, subject, data, created_at) VALUES ($1, $2, 'passkey', $3, $4, 1)",
    [`mth_${randomUUID().slice(0, 8)}`, accountId, root.credential.credential_id, JSON.stringify({ jwk: root.jwk, key_id: root.kid, ...(o.pending ? { pending: true } : {}) })]);
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
