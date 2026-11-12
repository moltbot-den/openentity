// Owner key logs (keylog-1, ADR 0007) and approval/2.0 (ADR 0008). Verify only: devices and passkeys sign, products verify.
// The byte-level format and every rule are in test-vectors/keylog-1/README.md and test-vectors/approval-2.0/README.md;
// test/owner.test.ts runs both vector sets, and so do sdk/python, sdk/swift and sdk/kotlin.
import { p256 } from "@noble/curves/nist.js";
import { OpenEntityError } from "./errors.ts";
import { canonicalize, parseJson, sha256Sync, toHex, b64url, unb64url, concat, equal } from "./core.ts";

const RP_ID = "account.openentity.org";
const DAY = 86_400;
const WEEK = 7 * DAY;
const MAX_TTL = 600;
const HALF_N = p256.Point.Fn.ORDER >> 1n;
const REQUEST_ID = /^[A-Za-z0-9:._-]{1,128}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const DID = /^did:[a-z0-9]+:[A-Za-z0-9._%:-]*[A-Za-z0-9._%-]$/;

/** A key in an owner key log: a device P-256 key (`p256`) or a passkey (`webauthn`). Descriptive fields (label, platform, attestation) pass through. */
export interface Credential {
  kid: string;
  type: "p256" | "webauthn";
  jwk: { kty: "EC"; crv: "P-256"; x: string; y: string };
  credential_id?: string;
  rp_id?: string;
  [field: string]: unknown;
}
/** The verified state of an owner key log as of `now`. `approvers` are the keys that may sign approval/2.0 now: the root passkey alone while it is the log's only credential. */
export interface KeyLogState {
  did: string;
  seq: number;
  head: string;
  root: Credential;
  approvers: Credential[];
  revoked: { kid: string; at: number }[];
  pending: { seq: number; op: "recover" | "replace_root"; hash: string; effective_at: number }[];
  closed: boolean;
}
export type KeyLogError = "malformed" | "bad_first_seen" | "closed" | "bad_seq" | "bad_prev" | "did_mismatch" | "bad_target" | "key_reused" | "unauthorized" | "bad_signature" | "bad_webauthn";
export type KeyLogResult = { ok: true; state: KeyLogState } | { ok: false; error: KeyLogError; seq: number; message: string };
export type ApprovalError = "malformed" | "bad_version" | "wrong_verifier" | "wrong_owner" | "owner_closed" | "wrong_request" | "wrong_payload" | "bad_decision" | "expired" | "expiry_too_far" | "unknown_key" | "bad_signature" | "bad_webauthn" | "counter_replayed";
export type ApprovalResult = { ok: true; kid: string; counter: number } | { ok: false; error: ApprovalError; message: string };

class Fail {
  code: KeyLogError | ApprovalError;
  message: string;
  constructor(code: KeyLogError | ApprovalError, message: string) {
    this.code = code;
    this.message = message;
  }
}
const fail = (code: KeyLogError | ApprovalError, message: string): never => {
  throw new Fail(code, message);
};

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);
const exactKeys = (o: Obj, keys: string[]) => Object.keys(o).length === keys.length && keys.every((k) => Object.hasOwn(o, k));
const isUint = (v: unknown): v is number => Number.isSafeInteger(v) && (v as number) >= 0;

/** Strict base64url: no padding, and only the one encoding of the bytes (re-encoding gives the same string). */
function b64u(s: unknown): Uint8Array | null {
  if (typeof s !== "string" || !/^[A-Za-z0-9_-]*$/.test(s) || s.length % 4 === 1) return null;
  const b = unb64url(s);
  return b64url(b) === s ? b : null;
}

/** RFC 4648 base32, lowercase, no padding: the owner DID suffix. */
function base32(b: Uint8Array): string {
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

/** Only safe integers and well-formed strings, so all four SDKs read an entry or a summary the same way. */
function plainJson(v: unknown): string | null {
  if (typeof v === "number") return Number.isSafeInteger(v) ? null : `number ${v} is not an integer within 2^53`;
  if (typeof v === "string") return /[\uD800-\uDFFF]/u.test(v) ? "string has a lone surrogate" : null;
  if (Array.isArray(v)) for (const x of v) { const e = plainJson(x); if (e) return e; }
  else if (isObj(v)) for (const [k, x] of Object.entries(v)) { const e = plainJson(k) ?? plainJson(x); if (e) return e; }
  return null;
}

// ---------------------------------------------------------------- P-256

function jwkPoint(j: unknown): Uint8Array | null {
  if (!isObj(j) || !exactKeys(j, ["kty", "crv", "x", "y"]) || j.kty !== "EC" || j.crv !== "P-256") return null;
  const x = b64u(j.x), y = b64u(j.y);
  if (x?.length !== 32 || y?.length !== 32) return null;
  const pub = concat(Uint8Array.of(4), x, y);
  try {
    p256.Point.fromBytes(pub).assertValidity();
    return pub;
  } catch {
    return null;
  }
}
/** RFC 7638 JWK thumbprint, base64url: the `kid` of every key in a log. */
const thumbprint = (j: { x: string; y: string }) => b64url(sha256Sync(`{"crv":"P-256","kty":"EC","x":"${j.x}","y":"${j.y}"}`));

/** Strict DER `SEQUENCE { INTEGER r, INTEGER s }` to 64-byte r||s; null for any other encoding. */
function derToRaw(der: Uint8Array): Uint8Array | null {
  if (der.length < 8 || der[0] !== 0x30 || der[1] !== der.length - 2 || der[1] > 0x7f) return null;
  const out = new Uint8Array(64);
  let i = 2;
  for (const at of [0, 32]) {
    if (der[i] !== 0x02) return null;
    const len = der[i + 1], v = der.subarray(i + 2, i + 2 + len);
    if (len < 1 || len > 33 || v.length !== len || v[0] & 0x80 || (len > 1 && v[0] === 0 && !(v[1] & 0x80)) || (len === 33 && v[0])) return null;
    const int = len === 33 ? v.subarray(1) : v;
    out.set(int, at + 32 - int.length);
    i += 2 + len;
  }
  return i === der.length ? out : null;
}

function ecdsa(raw: Uint8Array, msg: Uint8Array, pub: Uint8Array, prehash: boolean, lowS: boolean): boolean {
  if (lowS && BigInt("0x" + toHex(raw.subarray(32))) > HALF_N) return false;
  try {
    return p256.verify(raw, msg, pub, { prehash, lowS: false, format: "compact" });
  } catch {
    return false;
  }
}

interface SigOptions { origins: string[]; rpId: string; lowS: boolean }
interface Signed { form: unknown; signature: unknown; authenticator_data?: unknown; client_data_json?: unknown }

/** Checks a p256 or webauthn signature by `cred` over `digest`; returns the WebAuthn signature counter (0 for p256). */
function checkSignature(cred: Credential, s: Signed, digest: Uint8Array, o: SigOptions): number {
  if (s.form !== cred.type) fail("bad_signature", `a ${cred.type} key cannot present a ${String(s.form)} signature`);
  const pub = jwkPoint(cred.jwk)!;
  const sig = b64u(s.signature)!;
  if (s.form === "p256") {
    if (sig.length !== 64 || !ecdsa(sig, digest, pub, false, o.lowS)) fail("bad_signature", "p256 signature does not verify");
    return 0;
  }
  const authData = b64u(s.authenticator_data)!, clientRaw = b64u(s.client_data_json)!;
  let client: unknown;
  try {
    client = parseJson(new TextDecoder("utf-8", { fatal: true }).decode(clientRaw));
  } catch {
    fail("bad_webauthn", "clientDataJSON is not JSON");
  }
  if (!isObj(client) || client.type !== "webauthn.get") fail("bad_webauthn", "clientDataJSON type must be webauthn.get");
  const c = client as Obj;
  if (c.challenge !== b64url(digest)) fail("bad_webauthn", "challenge is not the digest");
  if (typeof c.origin !== "string" || !o.origins.includes(c.origin)) fail("bad_webauthn", `origin ${String(c.origin)} is not accepted`);
  if (c.crossOrigin === true) fail("bad_webauthn", "cross-origin assertions are not accepted");
  if (authData.length < 37 || !equal(authData.subarray(0, 32), sha256Sync(o.rpId))) fail("bad_webauthn", `rpIdHash is not SHA-256(${o.rpId})`);
  if ((authData[32] & 0x05) !== 0x05) fail("bad_webauthn", "user presence and user verification flags must be set");
  const raw = derToRaw(sig);
  if (!raw || !ecdsa(raw, concat(authData, sha256Sync(clientRaw)), pub, true, o.lowS)) fail("bad_signature", "webauthn signature does not verify");
  return new DataView(authData.buffer, authData.byteOffset).getUint32(33);
}

/** Shape of the signature fields shared by approvals and key log `auth`. */
function signedShape(s: Obj): string | null {
  if (s.form !== "p256" && s.form !== "webauthn") return "form must be p256 or webauthn";
  if (!b64u(s.signature)) return "signature must be base64url";
  if (s.form === "webauthn" && (!b64u(s.authenticator_data) || !b64u(s.client_data_json))) return "webauthn needs authenticator_data and client_data_json in base64url";
  return null;
}

// ---------------------------------------------------------------- approval/2.0

/** ADR 0008: SHA-256 of `approval/2.0|verifier_did|owner_did|request_id|payload_digest|decision|expires_at`. Takes the approval object or the request fields. */
export function approvalDigest(a: { verifier_did: string; owner_did: string; request_id: string; payload_digest: string; decision: string; expires_at: number }): Uint8Array {
  const e = approvalFieldsError(a as unknown as Obj);
  if (e) throw new OpenEntityError("invalid_input", e);
  return sha256Sync(["approval/2.0", a.verifier_did, a.owner_did, a.request_id, a.payload_digest, a.decision, String(a.expires_at)].join("|"));
}
function approvalFieldsError(a: Obj): string | null {
  if (typeof a.verifier_did !== "string" || !DID.test(a.verifier_did)) return "verifier_did must be a DID";
  if (typeof a.owner_did !== "string" || !DID.test(a.owner_did)) return "owner_did must be a DID";
  if (typeof a.request_id !== "string" || !REQUEST_ID.test(a.request_id)) return "request_id must be 1 to 128 of [A-Za-z0-9:._-]";
  if (typeof a.payload_digest !== "string" || !HEX64.test(a.payload_digest)) return "payload_digest must be 64 lowercase hex";
  if (a.decision !== "approve" && a.decision !== "deny") return "decision must be approve or deny";
  if (!isUint(a.expires_at)) return "expires_at must be unix seconds";
  return null;
}

/** Lowercase hex SHA-256 of the RFC 8785 form of the summary the owner saw. Numbers must be integers within 2^53 (put amounts in minor units or strings). */
export function payloadDigest(summary: unknown): string {
  const e = plainJson(summary);
  if (e) throw new OpenEntityError("invalid_input", e);
  return toHex(sha256Sync(canonicalize(summary)));
}

export interface ApprovalOptions {
  /** The owner's verified key log (from verifyKeyLog), or at least its did, approvers and closed flag. */
  keyLog: Pick<KeyLogState, "did" | "approvers" | "closed">;
  /** This verifier's own DID. */
  verifierDid: string;
  /** The principal that owns the action. */
  ownerDid: string;
  /** The id this verifier issued for the action's current state, and the payload digest it recomputes now. Never the client's. */
  requestId: string;
  payloadDigest: string;
  /** Unix seconds; defaults to the clock. */
  now?: number;
  /** Decisions this action accepts; default both. */
  decisions?: string[];
  /** Accepted WebAuthn origins; default `https://<rpId>`. Add the Android app's `android:apk-key-hash:` origin. */
  origins?: string[];
  rpId?: string;
  /** The WebAuthn signature counter stored for this key; store the returned one. */
  counter?: number;
}

/** Verifies an approval/2.0 object against the owner's key log. Rejects approval/1.0. */
export function verifyApproval(approval: unknown, o: ApprovalOptions): ApprovalResult {
  try {
    if (!isObj(approval)) fail("malformed", "approval must be an object");
    const a = approval as Obj;
    if (a.version !== "approval/2.0") fail("bad_version", `version ${String(a.version)} is not approval/2.0`);
    const shape = approvalFieldsError(a) ?? (typeof a.device_id === "string" ? signedShape(a) : "device_id must be a string");
    if (shape) fail("malformed", shape);
    const now = o.now ?? Math.floor(Date.now() / 1000);
    if (a.verifier_did !== o.verifierDid) fail("wrong_verifier", `approval is for ${String(a.verifier_did)}`);
    if (a.owner_did !== o.ownerDid || a.owner_did !== o.keyLog.did) fail("wrong_owner", "approval names another owner");
    if (o.keyLog.closed) fail("owner_closed", "the owner's key log is closed");
    if (a.request_id !== o.requestId) fail("wrong_request", "the request changed; fetch a new one");
    if (a.payload_digest !== o.payloadDigest) fail("wrong_payload", "payload digest does not match the action");
    if (!(o.decisions ?? ["approve", "deny"]).includes(a.decision as string)) fail("bad_decision", `decision ${String(a.decision)} is not accepted here`);
    const exp = a.expires_at as number;
    if (now >= exp) fail("expired", "approval expired");
    if (exp > now + MAX_TTL) fail("expiry_too_far", "expires_at is more than 600 seconds away");
    const cred = o.keyLog.approvers.find((c) => c.kid === a.device_id);
    if (!cred) fail("unknown_key", "device_id is not a current approver in the owner's key log");
    const rpId = o.rpId ?? RP_ID;
    const counter = checkSignature(cred!, a as unknown as Signed, approvalDigest(a as never), { origins: o.origins ?? [`https://${rpId}`], rpId, lowS: false });
    const stored = o.counter ?? 0;
    if (a.form === "webauthn" && (counter || stored) && counter <= stored) fail("counter_replayed", "signature counter did not increase");
    return { ok: true, kid: cred!.kid, counter };
  } catch (x) {
    if (x instanceof Fail) return { ok: false, error: x.code as ApprovalError, message: x.message };
    throw x;
  }
}

// ---------------------------------------------------------------- key log

const BODY: Record<string, string[]> = {
  genesis: ["approver", "root"],
  add_approver: ["approver"],
  recover: ["approvers"],
  replace_root: ["root"],
  cancel: ["target"],
  revoke: ["kid"],
  close: [],
};

function credential(c: unknown, rpId: string, what: string): Credential {
  if (!isObj(c)) fail("malformed", `${what} must be a credential object`);
  const k = c as Obj;
  if (k.type !== "p256" && k.type !== "webauthn") fail("malformed", `${what}.type must be p256 or webauthn`);
  if (!jwkPoint(k.jwk)) fail("malformed", `${what}.jwk must be exactly {kty: EC, crv: P-256, x, y} with a point on the curve`);
  if (k.kid !== thumbprint(k.jwk as Credential["jwk"])) fail("malformed", `${what}.kid must be the RFC 7638 thumbprint of its jwk`);
  if (k.type === "webauthn" && (!b64u(k.credential_id)?.length || k.rp_id !== rpId)) fail("malformed", `${what} needs a credential_id and rp_id ${rpId}`);
  return k as Credential;
}

interface Entry { seq: number; prev: string | null; op: string; body: Obj; auth: Obj & Signed & { kid: string } }

function parseEntry(line: unknown, rpId: string, first: boolean): Entry {
  if (typeof line !== "string") fail("malformed", "entry must be a JSON line");
  let e: unknown;
  try {
    e = parseJson(line as string);
  } catch (x) {
    fail("malformed", `not JSON: ${(x as Error).message}`);
  }
  const bad = plainJson(e);
  if (bad) fail("malformed", bad);
  if (canonicalize(e) !== line) fail("malformed", "line is not the RFC 8785 form of its entry");
  if (!isObj(e) || !exactKeys(e, ["v", "seq", "prev", "op", "ts", "body", "auth"])) fail("malformed", "entry must have exactly v, seq, prev, op, ts, body, auth");
  const x = e as Obj;
  if (x.v !== 1) fail("malformed", "v must be 1");
  if (!isUint(x.seq) || !isUint(x.ts)) fail("malformed", "seq and ts must be unsigned integers");
  if (x.prev !== null && (typeof x.prev !== "string" || !HEX64.test(x.prev))) fail("malformed", "prev must be null or 64 lowercase hex");
  if (typeof x.op !== "string" || !Object.hasOwn(BODY, x.op)) fail("malformed", `unknown op ${String(x.op)}`);
  if ((x.op === "genesis") !== first) fail("malformed", "genesis is the first entry and only the first");
  if (!isObj(x.body) || !exactKeys(x.body, BODY[x.op as string])) fail("malformed", `${String(x.op)} body must have exactly: ${BODY[x.op as string].join(", ") || "nothing"}`);
  const body = x.body as Obj;
  switch (x.op) {
    case "genesis":
      if (credential(body.root, rpId, "root").type !== "webauthn") fail("malformed", "root must be a passkey (webauthn)");
      if (body.approver !== null) credential(body.approver, rpId, "approver");
      break;
    case "add_approver":
      credential(body.approver, rpId, "approver");
      break;
    case "recover":
      if (!Array.isArray(body.approvers) || !body.approvers.length) fail("malformed", "recover needs at least one approver");
      (body.approvers as unknown[]).forEach((c, i) => credential(c, rpId, `approvers[${i}]`));
      break;
    case "replace_root":
      if (credential(body.root, rpId, "root").type !== "webauthn") fail("malformed", "root must be a passkey (webauthn)");
      break;
    case "cancel":
      if (typeof body.target !== "string" || !HEX64.test(body.target)) fail("malformed", "target must be 64 lowercase hex");
      break;
    case "revoke":
      if (typeof body.kid !== "string") fail("malformed", "kid must be a string");
      break;
  }
  const auth = x.auth;
  if (!isObj(auth) || typeof auth.kid !== "string") fail("malformed", "auth must be an object with a kid");
  const a = auth as Obj;
  const keys = a.form === "webauthn" ? ["kid", "form", "signature", "authenticator_data", "client_data_json"] : ["kid", "form", "signature"];
  const shape = signedShape(a) ?? (exactKeys(a, keys) ? null : `auth must have exactly ${keys.join(", ")}`);
  if (shape) fail("malformed", shape);
  return x as unknown as Entry;
}

export interface KeyLogOptions {
  /** Unix seconds; defaults to the clock. Pending operations whose 24 hours have run by `now` take effect. */
  now?: number;
  /** The account service's P-256 public JWKs, which sign `close`. */
  serviceKeys?: { kty: "EC"; crv: "P-256"; x: string; y: string }[];
  /** Accepted WebAuthn origins; default `https://<rpId>`. Add the Android app's `android:apk-key-hash:` origin. */
  origins?: string[];
  rpId?: string;
}

interface Pending { seq: number; op: "recover" | "replace_root"; hash: string; effective_at: number; creds: Credential[] }

/**
 * Verifies an owner key log (JSON Lines, one RFC 8785 entry per line) against the owner DID it must hash to.
 * `firstSeenAt[i]` is when this verifier first held entry i with its whole chain (unix seconds, never decreasing): every delay
 * runs from it, never from the entry's `ts`. Returns the state as of `now`, or the first failing entry's seq and rule.
 */
export function verifyKeyLog(did: string, lines: string[], firstSeenAt: number[], opts: KeyLogOptions = {}): KeyLogResult {
  const rpId = opts.rpId ?? RP_ID;
  const sig: SigOptions = { origins: opts.origins ?? [`https://${rpId}`], rpId, lowS: true };
  const now = opts.now ?? Math.floor(Date.now() / 1000);
  const services: Credential[] = (opts.serviceKeys ?? []).map((jwk) => {
    if (!jwkPoint(jwk)) throw new OpenEntityError("invalid_input", "serviceKeys must be P-256 public JWKs {kty, crv, x, y}");
    return { kid: thumbprint(jwk), type: "p256", jwk };
  });
  let seq = 1;
  try {
    if (!Array.isArray(lines) || !lines.length) fail("malformed", "a key log starts with its genesis entry");
    if (!Array.isArray(firstSeenAt) || firstSeenAt.length !== lines.length) fail("bad_first_seen", "one first_seen_at per entry");
    let root!: Credential, single = false, closed = false, head = "";
    let approvers: Credential[] = [], pending: Pending[] = [];
    const revoked: { cred: Credential; at: number }[] = [];
    const seen = new Set<string>();
    const delayed = new Map<string, "recover" | "replace_root">();
    const approver = (kid: string) => (single ? [root] : approvers).find((c) => c.kid === kid);
    const due = (t: number) => {
      while (pending.length && pending[0].effective_at <= t) {
        const p = pending.shift()!;
        if (p.op === "replace_root") root = p.creds[0];
        else {
          for (const c of approvers) revoked.push({ cred: c, at: p.effective_at });
          approvers = p.creds;
          single = false;
        }
      }
    };
    const fresh = (creds: Credential[]) => {
      for (const c of creds) {
        if (seen.has(c.kid)) fail("key_reused", `key ${c.kid} is already in this log`);
        seen.add(c.kid);
      }
    };

    for (let i = 0; i < lines.length; i++) {
      seq = i + 1;
      const t = firstSeenAt[i];
      if (!isUint(t) || t > now || (i > 0 && t < firstSeenAt[i - 1])) fail("bad_first_seen", "first_seen_at must be unix seconds, never decreasing, not after now");
      if (i > 0) due(t);
      const e = parseEntry(lines[i], rpId, i === 0);
      if (closed) fail("closed", "the log is closed");
      if (e.seq !== seq) fail("bad_seq", `seq must be ${seq}`);
      if (e.prev !== (i ? head : null)) fail("bad_prev", i ? "prev is not the SHA-256 of the previous entry" : "genesis prev must be null");
      const hash = toHex(sha256Sync(lines[i]));
      const { auth: _auth, ...unsigned } = e as unknown as Obj;
      const digest = sha256Sync(canonicalize(unsigned));
      const b = e.body, kid = e.auth.kid;
      let signer: Credential | undefined;
      switch (e.op) {
        case "genesis": {
          if (did !== `did:web:${rpId}:o:${base32(sha256Sync(lines[i]))}`) fail("did_mismatch", "the genesis hash does not match the DID suffix");
          root = b.root as Credential;
          const first = b.approver as Credential | null;
          fresh(first ? [root, first] : [root]);
          single = !first;
          approvers = first ? [first] : [];
          signer = (first ?? root).kid === kid ? (first ?? root) : undefined;
          break;
        }
        case "add_approver":
          fresh([b.approver as Credential]);
          signer = approver(kid);
          break;
        case "recover":
          fresh(b.approvers as Credential[]);
          signer = root.kid === kid ? root : undefined;
          break;
        case "replace_root":
          fresh([b.root as Credential]);
          signer = root.kid === kid ? root : approver(kid);
          break;
        case "cancel": {
          const op = delayed.get(b.target as string);
          if (!op) fail("bad_target", "target is not a recover or replace_root in this log");
          signer = approver(kid) ?? revoked.find((r) => r.cred.kid === kid && t < r.at + WEEK)?.cred ?? (op === "recover" && root.kid === kid ? root : undefined);
          break;
        }
        case "revoke":
          if (!approvers.some((c) => c.kid === b.kid)) fail("bad_target", "kid is not a current approver");
          signer = root.kid === kid ? root : approver(kid);
          break;
        case "close":
          signer = services.find((c) => c.kid === kid);
          break;
      }
      if (!signer) fail("unauthorized", `key ${kid} may not sign ${e.op} here`);
      checkSignature(signer!, e.auth, digest, sig);

      switch (e.op) {
        case "add_approver":
          approvers = [...approvers, b.approver as Credential];
          single = false;
          break;
        case "recover":
          pending.push({ seq, op: "recover", hash, effective_at: t + DAY, creds: b.approvers as Credential[] });
          delayed.set(hash, "recover");
          break;
        case "replace_root":
          if (single) root = b.root as Credential;
          else pending.push({ seq, op: "replace_root", hash, effective_at: t + DAY, creds: [b.root as Credential] });
          delayed.set(hash, "replace_root");
          break;
        case "cancel":
          pending = pending.filter((p) => p.hash !== b.target);
          break;
        case "revoke": {
          const gone = approvers.find((c) => c.kid === b.kid)!;
          approvers = approvers.filter((c) => c !== gone);
          revoked.push({ cred: gone, at: t });
          break;
        }
        case "close":
          closed = true;
          pending = [];
          break;
      }
      head = hash;
    }
    due(now);
    return {
      ok: true,
      state: {
        did,
        seq: lines.length,
        head,
        root,
        approvers: single ? [root] : approvers,
        revoked: revoked.map((r) => ({ kid: r.cred.kid, at: r.at })),
        pending: pending.map(({ creds: _c, ...p }) => p),
        closed,
      },
    };
  } catch (x) {
    if (x instanceof Fail) return { ok: false, error: x.code as KeyLogError, seq, message: x.message };
    throw x;
  }
}
