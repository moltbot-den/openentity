// Generates test-vectors/approval-2.0/, test-vectors/keylog-1/ and test-vectors/pair-sas-1/ from PUBLISHED THROWAWAY keys.
// Never use these keys for anything real. Run: pnpm --filter @openentity/sdk gen:vectors
// Signing lives here only (devices and passkeys sign; the SDKs verify). Expected results are written by hand below, not computed
// by the verifiers they test.
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { p256 } from "@noble/curves/nist.js";
import { sha256 as nobleSha256 } from "@noble/hashes/sha2.js";
import { canonicalize } from "../src/index.ts";
import { PAIR_SAS_WORDS } from "../src/pair.ts";
import { serialize } from "./gen-vectors.ts";

const enc = new TextEncoder();
const sha = (d: string | Uint8Array) => nobleSha256(typeof d === "string" ? enc.encode(d) : d);
const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const b64url = (b: Uint8Array) => Buffer.from(b).toString("base64url");
const cat = (...p: Uint8Array[]) => Uint8Array.from(p.flatMap((x) => [...x]));
const u32 = (n: number) => Uint8Array.of(n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255);
const base32 = (b: Uint8Array) => {
  const A = "abcdefghijklmnopqrstuvwxyz234567";
  const bits = [...b].map((x) => x.toString(2).padStart(8, "0")).join("");
  return (bits.match(/.{1,5}/g) ?? []).map((g) => A[parseInt(g.padEnd(5, "0"), 2)]).join("");
};

const RP = "account.openentity.org";
const WEB_ORIGIN = `https://${RP}`;
/** An example only: the real origin is the SHA-256 of the Play app signing certificate, pinned once assetlinks.json carries it. */
const ANDROID_ORIGIN = `android:apk-key-hash:${b64url(sha("openentity-android example signing certificate"))}`;
const ORIGINS = [WEB_ORIGIN, ANDROID_ORIGIN];
const N = p256.Point.Fn.ORDER;
const T0 = 1794009600; // 2026-11-07T00:00:00Z
const H = 3600, DAY = 86_400, WEEK = 7 * DAY;
/** did:key EIDs of the published OEIS throwaway seeds (test-vectors/keys.json), used as agent DIDs. */
const OEIS_KEYS = JSON.parse(readFileSync(new URL("../../../test-vectors/keys.json", import.meta.url), "utf8"));
const AGENT: string = OEIS_KEYS.entity.eid, AGENT2: string = OEIS_KEYS.second.eid;
const KEY_WARNING = "PUBLISHED THROWAWAY KEYS FOR TEST VECTORS ONLY. Every secret is SHA-256 of a published string (keys.json). Anyone can sign with them. Never use them for anything real.";

// ---------------------------------------------------------------- keys

interface Key { name: string; secret: Uint8Array; jwk: { kty: "EC"; crv: "P-256"; x: string; y: string }; kid: string }
function key(name: string): Key {
  const secret = sha(`openentity throwaway p256 ${name}`);
  if (BigInt("0x" + hex(secret)) >= N) throw new Error(`secret for ${name} is not below the group order`);
  const pub = p256.getPublicKey(secret, false);
  const jwk = { kty: "EC" as const, crv: "P-256" as const, x: b64url(pub.slice(1, 33)), y: b64url(pub.slice(33)) };
  return { name, secret, jwk, kid: b64url(sha(`{"crv":"P-256","kty":"EC","x":"${jwk.x}","y":"${jwk.y}"}`)) };
}
const K = Object.fromEntries(["root", "root2", "ios", "new_ios", "android", "android_tee", "web", "thief", "stranger", "service", "service_retired"].map((n) => [n, key(n)])) as Record<string, Key>;

const ICLOUD = "fbfc3007-154e-4ecc-8c0b-6e020557d7bd";
const GOOGLE_PM = "ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4";
const passkey = (k: Key, label: string, platform: string, aaguid: string) => ({ kid: k.kid, type: "webauthn", jwk: k.jwk, credential_id: b64url(sha(`credential ${k.name}`).slice(0, 16)), rp_id: RP, aaguid, label, platform });
const device = (k: Key, label: string, platform: "ios" | "android", key_storage: string, extra: object = {}) => ({
  kid: k.kid, type: "p256", jwk: k.jwk, label, platform, key_storage,
  attestation: { type: platform === "ios" ? "app_attest" : "android_key", verified: true }, ...extra,
});
const C = {
  root: passkey(K.root, "Passkey", "ios", ICLOUD),
  root2: passkey(K.root2, "New passkey", "android", GOOGLE_PM),
  ios: device(K.ios, "iPhone", "ios", "secure_enclave"),
  new_ios: device(K.new_ios, "New iPhone", "ios", "secure_enclave"),
  android: device(K.android, "Pixel", "android", "strongbox", { integrity: { device: true, strong: true } }),
  android_tee: device(K.android_tee, "Galaxy", "android", "tee", { integrity: { device: true, strong: false } }),
  web: passkey(K.web, "MacBook", "web", ICLOUD),
  thief: device(K.thief, "Thief phone", "android", "tee", { integrity: { device: true, strong: false } }),
  stranger: device(K.stranger, "Stranger", "ios", "secure_enclave"),
};

// ---------------------------------------------------------------- signatures (what devices and passkeys do)

const highS = (sig: Uint8Array) => cat(sig.slice(0, 32), Uint8Array.from(Buffer.from((N - BigInt("0x" + hex(sig.slice(32)))).toString(16).padStart(64, "0"), "hex")));
const der = (sig: Uint8Array) => p256.Signature.fromBytes(sig).toBytes("der");
/** Raw r||s over the 32-byte digest, as the Secure Enclave produces once the app normalizes to low S. */
const rawSign = (k: Key, digest: Uint8Array, high = false) => {
  const sig = p256.sign(digest, k.secret, { prehash: false, lowS: true });
  return high ? highS(sig) : sig;
};
interface Assert { origin?: string; rpId?: string; flags?: number; counter?: number; type?: string; crossOrigin?: boolean; challenge?: Uint8Array; high?: boolean; widenR?: boolean; bom?: boolean; extra?: Record<string, unknown> }
/** A WebAuthn get() assertion with challenge = digest, as a browser or Credential Manager returns it. */
function assertion(k: Key, digest: Uint8Array, o: Assert = {}) {
  const origin = o.origin ?? WEB_ORIGIN;
  const authData = cat(sha(o.rpId ?? RP), Uint8Array.of(o.flags ?? 0x1d), u32(o.counter ?? 0));
  const client: Record<string, unknown> = { type: o.type ?? "webauthn.get", challenge: b64url(o.challenge ?? digest), origin };
  if (origin.startsWith("android:")) client.androidPackageName = "org.openentity.app";
  else client.crossOrigin = o.crossOrigin ?? false;
  Object.assign(client, o.extra);
  const cdj = cat(o.bom ? Uint8Array.of(0xef, 0xbb, 0xbf) : new Uint8Array(), enc.encode(JSON.stringify(client)));
  const sig = p256.sign(cat(authData, sha(cdj)), k.secret, { prehash: true, lowS: true });
  let d = der(o.high ? highS(sig) : sig);
  // r as a 33-byte INTEGER led by 0x01: a lax parser that drops the first byte reads the same r, giving a second encoding.
  if (o.widenR) d = cat(Uint8Array.of(0x30, d[1] + (d[3] === 32 ? 1 : 0), 2, 33, 1), d.slice(d[3] === 33 ? 5 : 4));
  return { signature: b64url(d), authenticator_data: b64url(authData), client_data_json: b64url(cdj) };
}

// ---------------------------------------------------------------- key logs

interface Sign extends Assert { key: Key; form?: "p256" | "webauthn"; highRaw?: boolean }
interface EntryOpts { ts?: number; seq?: number; prev?: string | null; tamper?: (e: Record<string, unknown>) => void; line?: (e: Record<string, unknown>) => string }

class Log {
  lines: string[] = [];
  seen: number[] = [];
  add(op: string, body: object, s: Sign, firstSeen: number, o: EntryOpts = {}): this {
    const seq = o.seq ?? this.lines.length + 1;
    const prev = o.prev !== undefined ? o.prev : this.lines.length ? this.hash(this.lines.length) : null;
    const unsigned = { v: 1, seq, prev, op, ts: o.ts ?? firstSeen - 2, body };
    const digest = sha(canonicalize(unsigned));
    const form = s.form ?? (C[s.key.name as keyof typeof C]?.type === "webauthn" ? "webauthn" : "p256");
    const sig = form === "p256" ? { signature: b64url(rawSign(s.key, digest, s.highRaw)) } : assertion(s.key, digest, s);
    const entry: Record<string, unknown> = { ...unsigned, auth: { kid: s.key.kid, form, ...sig } };
    o.tamper?.(entry);
    this.lines.push(o.line ? o.line(entry) : canonicalize(entry));
    this.seen.push(firstSeen);
    return this;
  }
  hash = (seq: number) => hex(sha(this.lines[seq - 1]));
  get did() {
    return `did:web:${RP}:o:${base32(sha(this.lines[0]))}`;
  }
}
const genesis = (approver: object | null, s: Sign, t = T0, o?: EntryOpts) => new Log().add("genesis", { root: C.root, approver }, s, t, o);
const basic = () => genesis(C.ios, { key: K.ios });

type State = { root: Key; approvers: Key[]; revoked?: [Key, number][]; pending?: [number, "recover" | "replace_root", number][]; closed?: boolean };
function keylogCase(description: string, log: Log, now: number, expect: State | { error: string; seq: number }, did = log.did) {
  return {
    description: `${description} Keys: keys.json (published throwaway seeds).`,
    did,
    log: log.lines,
    first_seen_at: log.seen,
    now,
    origins: ORIGINS,
    // Every close key did:web:account.openentity.org has used, current and retired, from its did.json assertionMethod.
    service_keys: [K.service.jwk, K.service_retired.jwk],
    expect: "error" in expect
      ? { ok: false, error: expect.error, seq: expect.seq }
      : {
          ok: true,
          state: {
            did,
            seq: log.lines.length,
            head: log.hash(log.lines.length),
            root: expect.root.kid,
            approvers: expect.approvers.map((k) => k.kid),
            revoked: (expect.revoked ?? []).map(([k, at]) => ({ kid: k.kid, at })),
            pending: (expect.pending ?? []).map(([seq, op, effective_at]) => ({ seq, op, hash: log.hash(seq), effective_at })),
            closed: expect.closed ?? false,
          },
        },
  };
}

function keylogVectors(): Record<string, object> {
  const v: Record<string, object> = {};
  const add = (name: string, ...a: Parameters<typeof keylogCase>) => (v[name] = keylogCase(...a));

  // Valid logs, one per operation and rule.
  add("genesis-device", "genesis: root passkey plus an iPhone Secure Enclave approver, signed by that approver.", basic(), T0 + 60, { root: K.root, approvers: [K.ios] });
  add("genesis-web-approver", "genesis with a web approver passkey (webauthn, https origin) as first approver.", genesis(C.web, { key: K.web }), T0 + 60, { root: K.root, approvers: [K.web] });
  add("genesis-root-only", "Single-credential log: genesis with no approver, signed by the root passkey from the Android app origin. The root passkey is the approver.",
    genesis(null, { key: K.root, origin: ANDROID_ORIGIN }), T0 + 60, { root: K.root, approvers: [K.root] });
  add("add-approver", "add_approver twice: a StrongBox key signed by the iPhone, then a TEE key (the StrongBox fallback) signed by the StrongBox key.",
    basic().add("add_approver", { approver: C.android }, { key: K.ios }, T0 + H).add("add_approver", { approver: C.android_tee }, { key: K.android }, T0 + 2 * H),
    T0 + 3 * H, { root: K.root, approvers: [K.ios, K.android, K.android_tee] });
  add("add-approver-root-only", "Single-credential exception: the root passkey signs add_approver while it is the only credential; afterwards it is no longer an approver.",
    genesis(null, { key: K.root }).add("add_approver", { approver: C.web }, { key: K.root }, T0 + H), T0 + 2 * H, { root: K.root, approvers: [K.web] });
  add("revoke", "revoke by a current approver takes effect at once.",
    basic().add("add_approver", { approver: C.android }, { key: K.ios }, T0 + H).add("revoke", { kid: K.ios.kid }, { key: K.android }, T0 + 2 * H),
    T0 + 3 * H, { root: K.root, approvers: [K.android], revoked: [[K.ios, T0 + 2 * H]] });
  add("revoke-by-root", "The root passkey may revoke an approver, at once.",
    basic().add("revoke", { kid: K.ios.kid }, { key: K.root }, T0 + H), T0 + 2 * H, { root: K.root, approvers: [], revoked: [[K.ios, T0 + H]] });
  const recover = () => basic().add("recover", { approvers: [C.new_ios] }, { key: K.root }, T0 + H);
  add("recover-pending", "recover signed by the root passkey is pending until 24 hours after first sight (one second before).",
    recover(), T0 + H + DAY - 1, { root: K.root, approvers: [K.ios], pending: [[2, "recover", T0 + H + DAY]] });
  add("recover-effective", "recover takes effect exactly 24 hours after first sight: its approvers replace the old ones, which count as revoked from then.",
    recover(), T0 + H + DAY, { root: K.root, approvers: [K.new_ios], revoked: [[K.ios, T0 + H + DAY]] });
  add("recover-backdated-ts", "A recover whose ts is 30 days old still waits 24 hours from first_seen_at: ts never shortens a delay.",
    basic().add("recover", { approvers: [C.new_ios] }, { key: K.root }, T0 + H, { ts: T0 - 30 * DAY }), T0 + H + DAY - 1,
    { root: K.root, approvers: [K.ios], pending: [[2, "recover", T0 + H + DAY]] });
  const theft = () => basic().add("recover", { approvers: [C.thief] }, { key: K.root }, T0 + H);
  add("recover-cancelled-by-approver", "A cancelled recover never takes effect: cancel by a current approver.",
    (() => { const l = theft(); return l.add("cancel", { target: l.hash(2) }, { key: K.ios }, T0 + 3 * H); })(), T0 + H + 2 * DAY, { root: K.root, approvers: [K.ios] });
  add("recover-cancelled-by-root", "The root passkey may cancel a pending recover.",
    (() => { const l = theft(); return l.add("cancel", { target: l.hash(2) }, { key: K.root }, T0 + 3 * H); })(), T0 + H + 2 * DAY, { root: K.root, approvers: [K.ios] });
  add("recover-cancelled-by-revoked-approver", "Stolen root passkey: root revokes every approver, then signs recover; an approver revoked within 7 days cancels it, so it never takes effect.",
    (() => {
      const l = basic().add("add_approver", { approver: C.android }, { key: K.ios }, T0 + H)
        .add("revoke", { kid: K.ios.kid }, { key: K.root }, T0 + 2 * H).add("revoke", { kid: K.android.kid }, { key: K.root }, T0 + 2 * H + 1)
        .add("recover", { approvers: [C.thief] }, { key: K.root }, T0 + 3 * H);
      return l.add("cancel", { target: l.hash(5) }, { key: K.ios }, T0 + 5 * H);
    })(), T0 + 3 * H + 2 * DAY, { root: K.root, approvers: [], revoked: [[K.ios, T0 + 2 * H], [K.android, T0 + 2 * H + 1]] });
  add("revoked-cancel-last-second", "An approver revoked 7 days minus one second ago may still cancel a pending recover.",
    (() => {
      const l = basic().add("revoke", { kid: K.ios.kid }, { key: K.root }, T0 + H).add("recover", { approvers: [C.thief] }, { key: K.root }, T0 + H + WEEK - H);
      return l.add("cancel", { target: l.hash(3) }, { key: K.ios }, T0 + H + WEEK - 1);
    })(), T0 + H + WEEK + 2 * DAY, { root: K.root, approvers: [], revoked: [[K.ios, T0 + H]] });
  const replace = (by: Key) => basic().add("replace_root", { root: C.root2 }, { key: by }, T0 + H);
  add("replace-root-pending", "replace_root signed by the root passkey has no effect before 24 hours after first sight.",
    replace(K.root), T0 + H + DAY - 1, { root: K.root, approvers: [K.ios], pending: [[2, "replace_root", T0 + H + DAY]] });
  add("replace-root-effective", "replace_root takes effect 24 hours after first sight.", replace(K.root), T0 + H + DAY, { root: K.root2, approvers: [K.ios] });
  add("replace-root-by-approver", "replace_root signed by a current approver also waits 24 hours: whoever signs.",
    replace(K.ios), T0 + H + DAY - 1, { root: K.root, approvers: [K.ios], pending: [[2, "replace_root", T0 + H + DAY]] });
  add("replace-root-root-only", "Single-credential exception: in a log whose only credential is the root passkey, replace_root takes effect at once.",
    genesis(null, { key: K.root }).add("replace_root", { root: C.root2 }, { key: K.root }, T0 + H), T0 + H + 60, { root: K.root2, approvers: [K.root2] });
  add("replace-root-cancelled-by-revoked-approver", "After root revokes the only approver, its replace_root waits 24 hours and the revoked approver cancels it.",
    (() => {
      const l = basic().add("revoke", { kid: K.ios.kid }, { key: K.root }, T0 + H).add("replace_root", { root: C.root2 }, { key: K.root }, T0 + 2 * H);
      return l.add("cancel", { target: l.hash(3) }, { key: K.ios }, T0 + 3 * H);
    })(), T0 + 2 * H + 2 * DAY, { root: K.root, approvers: [], revoked: [[K.ios, T0 + H]] });
  add("late-cancel", "A cancel first seen at the instant its recover took effect is accepted and changes nothing (the signer is an approver the recover just replaced).",
    (() => { const l = recover(); return l.add("cancel", { target: l.hash(2) }, { key: K.ios }, T0 + H + DAY); })(), T0 + H + DAY + 60,
    { root: K.root, approvers: [K.new_ios], revoked: [[K.ios, T0 + H + DAY]] });
  add("close", "close signed by the account service key: the log is closed.",
    basic().add("close", {}, { key: K.service }, T0 + H), T0 + 2 * H, { root: K.root, approvers: [K.ios], closed: true });
  add("close-retired-key", "close signed by a retired account service close key still verifies: did.json keeps every close key under assertionMethod.",
    basic().add("close", {}, { key: K.service_retired }, T0 + H), T0 + 2 * H, { root: K.root, approvers: [K.ios], closed: true });

  // Failure cases: each breaks exactly one rule.
  add("unjustified-key-self-signed", "A key the chain does not justify: add_approver signed by the new key itself (what a compromised server would forge).",
    basic().add("add_approver", { approver: C.stranger }, { key: K.stranger }, T0 + H), T0 + 2 * H, { error: "unauthorized", seq: 2 });
  add("unjustified-key-unknown-signer", "A key the chain does not justify: add_approver signed by a key that is not in the log.",
    basic().add("add_approver", { approver: C.thief }, { key: K.stranger }, T0 + H), T0 + 2 * H, { error: "unauthorized", seq: 2 });
  add("did-mismatch", "The genesis hash does not match the DID suffix (the DID of another log).", basic(), T0 + 60, { error: "did_mismatch", seq: 1 }, genesis(C.web, { key: K.web }).did);
  add("replace-root-not-yet", "replace_root before 24 hours after first sight: the new root passkey cannot sign yet.",
    replace(K.root).add("recover", { approvers: [C.thief] }, { key: K.root2 }, T0 + H + DAY - 1), T0 + H + DAY - 1, { error: "unauthorized", seq: 3 });
  add("revoked-cancel-after-7-days", "An approver revoked exactly 7 days ago may no longer cancel.",
    (() => {
      const l = basic().add("revoke", { kid: K.ios.kid }, { key: K.root }, T0 + H).add("recover", { approvers: [C.thief] }, { key: K.root }, T0 + H + WEEK - H);
      return l.add("cancel", { target: l.hash(3) }, { key: K.ios }, T0 + H + WEEK);
    })(), T0 + H + WEEK + 60, { error: "unauthorized", seq: 4 });
  const revokedIos = () => basic().add("add_approver", { approver: C.android }, { key: K.ios }, T0 + H).add("revoke", { kid: K.ios.kid }, { key: K.android }, T0 + 2 * H);
  add("revoked-signs-add-approver", "A revoked approver signs add_approver.", revokedIos().add("add_approver", { approver: C.thief }, { key: K.ios }, T0 + 3 * H), T0 + 4 * H, { error: "unauthorized", seq: 4 });
  add("revoked-signs-revoke", "A revoked approver signs revoke.", revokedIos().add("revoke", { kid: K.android.kid }, { key: K.ios }, T0 + 3 * H), T0 + 4 * H, { error: "unauthorized", seq: 4 });
  add("revoked-signs-replace-root", "A revoked approver signs replace_root.", revokedIos().add("replace_root", { root: C.root2 }, { key: K.ios }, T0 + 3 * H), T0 + 4 * H, { error: "unauthorized", seq: 4 });
  add("root-signs-add-approver", "The root passkey acts as an approver once another approver exists.",
    basic().add("add_approver", { approver: C.web }, { key: K.root }, T0 + H), T0 + 2 * H, { error: "unauthorized", seq: 2 });
  add("root-after-revoking-all", "Revoking every approver does not make the root passkey an approver again.",
    basic().add("revoke", { kid: K.ios.kid }, { key: K.root }, T0 + H).add("add_approver", { approver: C.thief }, { key: K.root }, T0 + 2 * H), T0 + 3 * H, { error: "unauthorized", seq: 3 });
  add("root-cancels-replace-root", "The root passkey may cancel a recover but not a replace_root.",
    (() => { const l = replace(K.ios); return l.add("cancel", { target: l.hash(2) }, { key: K.root }, T0 + 2 * H); })(), T0 + 3 * H, { error: "unauthorized", seq: 3 });
  add("recover-by-approver", "Only the root passkey signs recover.", basic().add("recover", { approvers: [C.new_ios] }, { key: K.ios }, T0 + H), T0 + 2 * H, { error: "unauthorized", seq: 2 });
  add("close-by-approver", "Only the account service signs close.", basic().add("close", {}, { key: K.ios }, T0 + H), T0 + 2 * H, { error: "unauthorized", seq: 2 });
  add("entry-after-close", "No entry is accepted after close.",
    basic().add("close", {}, { key: K.service }, T0 + H).add("add_approver", { approver: C.android }, { key: K.ios }, T0 + 2 * H), T0 + 3 * H, { error: "closed", seq: 3 });
  add("bad-prev", "prev is not the SHA-256 of the previous entry.", basic().add("add_approver", { approver: C.android }, { key: K.ios }, T0 + H, { prev: hex(sha("not the genesis")) }), T0 + 2 * H, { error: "bad_prev", seq: 2 });
  add("genesis-prev-not-null", "genesis must have prev null.", genesis(C.ios, { key: K.ios }, T0, { prev: "00".repeat(32) }), T0 + 60, { error: "bad_prev", seq: 1 });
  add("bad-seq", "seq skips a number.", basic().add("add_approver", { approver: C.android }, { key: K.ios }, T0 + H, { seq: 3 }), T0 + 2 * H, { error: "bad_seq", seq: 2 });
  add("not-canonical", "The line is valid JSON but not its RFC 8785 form (keys in insertion order).",
    genesis(C.ios, { key: K.ios }, T0, { line: (e) => JSON.stringify(e) }), T0 + 60, { error: "malformed", seq: 1 }, basic().did);
  add("duplicate-key", "A line with a duplicate key.",
    basic().add("add_approver", { approver: C.android }, { key: K.ios }, T0 + H, { line: (e) => canonicalize(e).replace('"op":"add_approver"', '"op":"revoke","op":"add_approver"') }), T0 + 2 * H, { error: "malformed", seq: 2 });
  add("fractional-number", "Numbers in entries are integers: ts 1.5 seconds past a whole second.",
    basic().add("add_approver", { approver: C.android }, { key: K.ios }, T0 + H, { ts: T0 + 0.5 }), T0 + 2 * H, { error: "malformed", seq: 2 });
  add("unknown-op", "An op this version does not define.", basic().add("rotate", { approver: C.android }, { key: K.ios }, T0 + H), T0 + 2 * H, { error: "malformed", seq: 2 });
  add("kid-not-thumbprint", "A credential whose kid is not the RFC 7638 thumbprint of its jwk.",
    basic().add("add_approver", { approver: { ...C.android, kid: K.thief.kid } }, { key: K.ios }, T0 + H), T0 + 2 * H, { error: "malformed", seq: 2 });
  add("root-not-passkey", "The root must be a passkey (webauthn), not a device key.", new Log().add("genesis", { root: C.android, approver: C.ios }, { key: K.ios }, T0), T0 + 60, { error: "malformed", seq: 1 });
  add("high-s", "A p256 signature with the high S value: entry signatures must be low-S so an entry has one hash.",
    genesis(C.ios, { key: K.ios, highRaw: true }), T0 + 60, { error: "bad_signature", seq: 1 });
  add("webauthn-high-s", "A webauthn entry signature with the high S value.", genesis(C.web, { key: K.web, high: true }), T0 + 60, { error: "bad_signature", seq: 1 });
  add("webauthn-wrong-origin", "A webauthn entry signature from an origin that is not accepted.", genesis(C.web, { key: K.web, origin: "https://evil.example" }), T0 + 60, { error: "bad_webauthn", seq: 1 });
  add("webauthn-wrong-rp", "A webauthn entry signature whose rpIdHash is not SHA-256(account.openentity.org).", genesis(C.web, { key: K.web, rpId: "evil.example" }), T0 + 60, { error: "bad_webauthn", seq: 1 });
  add("webauthn-no-uv", "A webauthn entry signature without the user verification flag.", genesis(C.web, { key: K.web, flags: 0x01 }), T0 + 60, { error: "bad_webauthn", seq: 1 });
  add("webauthn-der-wide-r", "A webauthn entry signature whose DER r is 33 bytes led by 0x01: not strict DER, so an entry cannot be re-encoded.",
    genesis(C.web, { key: K.web, widenR: true }), T0 + 60, { error: "bad_signature", seq: 1 });
  add("form-mismatch", "A passkey key presenting a raw p256 signature.", genesis(C.web, { key: K.web, form: "p256" }), T0 + 60, { error: "bad_signature", seq: 1 });
  add("tampered-body", "The body changed after signing.",
    basic().add("add_approver", { approver: C.android }, { key: K.ios }, T0 + H, { tamper: (e) => ((e.body as { approver: { label: string } }).approver = { ...C.android, label: "Not what was signed" }) }),
    T0 + 2 * H, { error: "bad_signature", seq: 2 });
  add("key-reused", "A key enters a log once: re-adding a revoked approver.",
    basic().add("add_approver", { approver: C.android }, { key: K.ios }, T0 + H).add("revoke", { kid: K.android.kid }, { key: K.ios }, T0 + 2 * H)
      .add("add_approver", { approver: C.android }, { key: K.ios }, T0 + 3 * H), T0 + 4 * H, { error: "key_reused", seq: 4 });
  add("cancel-unknown-target", "cancel must name a recover or replace_root in this log.",
    (() => { const l = basic(); return l.add("cancel", { target: l.hash(1) }, { key: K.ios }, T0 + H); })(), T0 + 2 * H, { error: "bad_target", seq: 2 });
  add("revoke-root", "revoke names a current approver; the root passkey cannot be revoked.", basic().add("revoke", { kid: K.root.kid }, { key: K.ios }, T0 + H), T0 + 2 * H, { error: "bad_target", seq: 2 });
  add("first-seen-decreasing", "first_seen_at never decreases along the log.",
    (() => { const l = basic().add("add_approver", { approver: C.android }, { key: K.ios }, T0 + H); l.seen[1] = T0 - 1; return l; })(), T0 + 2 * H, { error: "bad_first_seen", seq: 2 });
  return v;
}

// ---------------------------------------------------------------- approval/2.0

function approvalVectors(): object {
  const owner = basic().add("add_approver", { approver: C.web }, { key: K.ios }, T0 + H);
  const single = genesis(null, { key: K.root });
  const closedLog = basic().add("add_approver", { approver: C.web }, { key: K.ios }, T0 + H).add("close", {}, { key: K.service }, T0 + 90 * 60);
  const logOf = (l: Log) => ({ did: l.did, log: l.lines, first_seen_at: l.seen });
  const revokedLog = basic().add("add_approver", { approver: C.web }, { key: K.ios }, T0 + H).add("revoke", { kid: K.ios.kid }, { key: K.web }, T0 + 90 * 60);
  const key_logs = { owner: logOf(owner), single: logOf(single), closed: logOf(closedLog), revoked: logOf(revokedLog) };
  const key_states = {
    owner: { did: owner.did, root: C.root, approvers: [C.ios, C.web], closed: false },
    single: { did: single.did, root: C.root, approvers: [C.root], closed: false },
    closed: { did: owner.did, root: C.root, approvers: [C.ios, C.web], closed: true },
    revoked: { did: owner.did, root: C.root, approvers: [C.web], closed: false },
  };
  const ASS = "did:web:api.agentsecretstore.com", DEN = "did:web:moltbotden.com", ACCOUNT = `did:web:${RP}`;
  const summary = { action: "secret.read", agent: AGENT, secret: "stripe/live", scope: "read", ttl_seconds: 300 };
  const payload = hex(sha(canonicalize(summary)));
  const NOW = T0 + 2 * H, EXP = NOW + 300;
  type Fields = { verifier_did: string; owner_did: string; request_id: string; payload_digest: string; decision: string; expires_at: number };
  const base: Fields = { verifier_did: ASS, owner_did: owner.did, request_id: "req_7Hk2:42", payload_digest: payload, decision: "approve", expires_at: EXP };
  const preimage = (f: Fields) => ["approval/2.0", f.verifier_did, f.owner_did, f.request_id, f.payload_digest, f.decision, String(f.expires_at)].join("|");
  const digest = (f: Fields) => sha(preimage(f));

  interface Make { key?: Key; deviceId?: string; form?: "p256" | "webauthn"; fields?: Partial<Fields>; signed?: Partial<Fields>; assert?: Assert; high?: boolean }
  function approval(m: Make = {}) {
    const k = m.key ?? K.ios;
    const fields = { ...base, ...m.fields };
    const d = digest({ ...fields, ...m.signed });
    const form = m.form ?? (k === K.web || k === K.root ? "webauthn" : "p256");
    const sig = form === "p256" ? { signature: b64url(rawSign(k, d, m.high)) } : assertion(k, d, m.assert);
    return { version: "approval/2.0", ...fields, device_id: m.deviceId ?? k.kid, form, ...sig };
  }
  const ctx = (o: Partial<{ verifier_did: string; owner_did: string; request_id: string; payload_digest: string; now: number; decisions: string[]; counter: number; key_state: string; allow_root: boolean; origins: string[] }> = {}) => ({
    verifier_did: ASS, owner_did: owner.did, request_id: base.request_id, payload_digest: payload, now: NOW, origins: ORIGINS, key_state: "owner", ...o,
  });
  const ok = (k: Key, counter = 0) => ({ ok: true, kid: k.kid, counter });
  const no = (error: string) => ({ ok: false, error });
  const c = (name: string, description: string, approval: object, context: object, expect: object) => ({ name, description, approval, context, expect });

  const v1Digest = sha(`${base.request_id}|${payload}|approve|${EXP}`);
  const v1 = { version: "approval/1.0", request_id: base.request_id, payload_digest: payload, decision: "approve", expires_at: EXP, device_id: K.ios.kid, form: "p256", signature: b64url(rawSign(K.ios, v1Digest)) };

  const cases = [
    c("p256-approve", "Secure Enclave key, raw r||s over the digest, approve.", approval(), ctx(), ok(K.ios)),
    c("p256-deny", "Secure Enclave key, deny.", approval({ fields: { decision: "deny" } }), ctx(), ok(K.ios)),
    c("p256-high-s", "Approvals accept the high-S twin (ADR 0004 forms); only key log entries require low S.", approval({ high: true }), ctx(), ok(K.ios)),
    c("webauthn-web-origin", "Web approver passkey, origin https://account.openentity.org.", approval({ key: K.web }), ctx(), ok(K.web)),
    c("webauthn-android-origin", "The same passkey through the Android app: origin android:apk-key-hash (example hash).", approval({ key: K.web, assert: { origin: ANDROID_ORIGIN } }), ctx(), ok(K.web)),
    c("webauthn-counter", "A nonzero signature counter above the stored one is accepted and returned.", approval({ key: K.web, assert: { counter: 7 } }), ctx({ counter: 6 }), ok(K.web, 7)),
    c("root-single-credential", "In a single-credential log the root passkey is the approver.",
      approval({ key: K.root, fields: { owner_did: single.did } }), ctx({ owner_did: single.did, key_state: "single" }), ok(K.root)),
    c("expiry-at-limit", "expires_at exactly 600 seconds after now.", approval({ fields: { expires_at: NOW + 600 } }), ctx(), ok(K.ios)),
    c("moltbotden-verifier", "Moltbot Den verifying an approval addressed to it.", approval({ fields: { verifier_did: DEN } }), ctx({ verifier_did: DEN }), ok(K.ios)),

    c("v1-from-keylog-key", "approval/1.0 (the old digest) signed by a key-log key is rejected.", v1, ctx(), no("bad_version")),
    c("wrong-verifier", "An approval addressed to Moltbot Den presented to Agent Secret Store.", approval({ fields: { verifier_did: DEN } }), ctx(), no("wrong_verifier")),
    c("agent-written", "An approval written through POST /v1/agent/approvals names the account service; no product accepts it.", approval({ fields: { verifier_did: ACCOUNT } }), ctx(), no("wrong_verifier")),
    c("wrong-owner", "The approval names another owner.", approval({ fields: { owner_did: single.did } }), ctx(), no("wrong_owner")),
    c("owner-closed", "The owner's key log is closed.", approval(), ctx({ key_state: "closed" }), no("owner_closed")),
    c("wrong-request", "The verifier's request id moved on (the action's state changed).", approval(), ctx({ request_id: "req_7Hk2:43" }), no("wrong_request")),
    c("wrong-payload", "The summary the verifier recomputes differs.", approval(), ctx({ payload_digest: hex(sha("another summary")) }), no("wrong_payload")),
    c("bad-decision", "This action accepts approve only.", approval({ fields: { decision: "deny" } }), ctx({ decisions: ["approve"] }), no("bad_decision")),
    c("expired", "now equals expires_at.", approval(), ctx({ now: EXP }), no("expired")),
    c("expiry-too-far", "expires_at 601 seconds after now.", approval({ fields: { expires_at: NOW + 601 } }), ctx(), no("expiry_too_far")),
    c("unknown-key", "Signed by a key that is not an approver in the owner's key log.", approval({ key: K.stranger }), ctx(), no("unknown_key")),
    c("root-not-approver", "allowRoot off (the default): the root passkey is not an approver once another approver exists.", approval({ key: K.root }), ctx(), no("unknown_key")),
    c("root-allow-root", "allowRoot on (account-service flows such as cancelling a deletion request): the root passkey's WebAuthn approval is accepted.",
      approval({ key: K.root }), ctx({ allow_root: true }), ok(K.root)),
    c("revoked-approver", "A revoked approver never signs an approval, even with allowRoot on (it may only sign the key log cancel op).",
      approval({ key: K.ios }), ctx({ key_state: "revoked", allow_root: true }), no("unknown_key")),
    c("tampered-decision", "Signed approve, presented as deny.", approval({ fields: { decision: "deny" }, signed: { decision: "approve" } }), ctx(), no("bad_signature")),
    c("form-mismatch", "A passkey key presenting a raw p256 signature.", approval({ key: K.web, form: "p256" }), ctx(), no("bad_signature")),
    c("webauthn-wrong-origin", "Origin https://evil.example.", approval({ key: K.web, assert: { origin: "https://evil.example" } }), ctx(), no("bad_webauthn")),
    c("webauthn-wrong-rp", "rpIdHash of evil.example.", approval({ key: K.web, assert: { rpId: "evil.example" } }), ctx(), no("bad_webauthn")),
    c("webauthn-no-uv", "User verification flag missing.", approval({ key: K.web, assert: { flags: 0x01 } }), ctx(), no("bad_webauthn")),
    c("webauthn-create-type", "clientDataJSON type webauthn.create.", approval({ key: K.web, assert: { type: "webauthn.create" } }), ctx(), no("bad_webauthn")),
    c("webauthn-wrong-challenge", "The challenge is the digest of another request.", approval({ key: K.web, assert: { challenge: digest({ ...base, request_id: "req_other" }) } }), ctx(), no("bad_webauthn")),
    c("webauthn-cross-origin", "crossOrigin true.", approval({ key: K.web, assert: { crossOrigin: true } }), ctx(), no("bad_webauthn")),
    c("webauthn-bom", "clientDataJSON starting with a UTF-8 byte order mark is not JSON.", approval({ key: K.web, assert: { bom: true } }), ctx(), no("bad_webauthn")),
    c("webauthn-lone-surrogate", "clientDataJSON with a lone surrogate in any string.", approval({ key: K.web, assert: { extra: { note: "\ud800" } } }), ctx(), no("bad_webauthn")),
    c("webauthn-no-origins", "An empty origins list accepts no origin.", approval({ key: K.web }), ctx({ origins: [] }), no("bad_webauthn")),
    c("webauthn-counter-replayed", "The signature counter did not increase.", approval({ key: K.web, assert: { counter: 6 } }), ctx({ counter: 6 }), no("counter_replayed")),
    c("request-id-with-separator", "request_id may not contain the | separator.", { ...approval(), request_id: "req|1" }, ctx({ request_id: "req|1" }), no("malformed")),
  ];

  const payloads = [
    summary,
    { network: "base-mainnet", contract: "ct_9f2", milestone: 2, amount_usdc_cents: 125000, to: "0x52908400098527886E0F7030069857D2E4169EE7", over_budget: false, note: null },
    { "z": "last", "a": "first", "é": "e acute sorts after z", "～": "fullwidth tilde", "😀": "emoji sorts before U+FF5E in UTF-16 order", nested: { b: [3, 1, 2], a: true } },
    { agent: "Zoë", note: "Café ☕ für Jürgen 🚀", lines: "one\ntwo\t\"quoted\" \\ back" },
  ].map((s) => ({ summary: s, canonical: canonicalize(s), digest: hex(sha(canonicalize(s))) }));

  return {
    description: "approval/2.0 vectors (ADR 0008). Throwaway keys from keys.json. digests: the preimage and its SHA-256 for both decisions. payloads: canonical JSON summaries and their digests; payloads_invalid must be refused. cases: verify `approval` with `context` against key_states[context.key_state]; `expect` is {ok, kid, counter} or {ok: false, error}. key_logs holds the key log behind each key state (keylog-1 rules, service key from keys.json, now = the cases' now).",
    warning: KEY_WARNING,
    digests: ["approve", "deny"].map((decision) => {
      const f = { ...base, decision };
      return { fields: f, preimage: preimage(f), digest: hex(digest(f)) };
    }),
    payloads,
    payloads_invalid: [
      { summary: { amount: 12.5 }, reason: "numbers must be integers: send amounts in minor units or as strings" },
      { summary: { amount: 9007199254740992 }, reason: "integers must be within 2^53 - 1" },
    ],
    key_states,
    key_logs,
    cases,
  };
}

// ---------------------------------------------------------------- pair-sas/1

function pairVectors(): Record<string, object> {
  const cases = [["OE-7K4M-Q2XP", AGENT], ["OE-0000-0000", AGENT], ["OE-7K4M-Q2XP", AGENT2], ["oe-7k4m-q2xp", AGENT]].map(([input, did]) => {
    const code = input.toUpperCase();
    const pre = `oe-pair-sas/1|${code}|${did}`;
    const h = sha(pre);
    return { code: input, agent_did: did, preimage: pre, sha256: hex(h), items: [...h.slice(0, 4)].map((b) => PAIR_SAS_WORDS[b]) };
  });
  return {
    "pair-sas-1/words.json": {
      description: "pair-sas/1 symbol list: 256 entries, index = byte value. Entry i is colors[i >> 4] + \" \" + nouns[i & 15].",
      colors: "red orange yellow green blue purple pink brown black white gray gold silver navy olive coral".split(" "),
      nouns: "fox kite bear boat star tree fish moon drum frog lamp owl wolf shell crown horse".split(" "),
      words: PAIR_SAS_WORDS,
    },
    "pair-sas-1/vectors.json": {
      description: "pair-sas/1: items = words[b] for the first 4 bytes b of SHA-256(UTF-8(\"oe-pair-sas/1|\" + CODE + \"|\" + agent_did)), CODE uppercased. The last case is typed in lowercase.",
      cases,
    },
  };
}

export function buildOwnerVectors(): Record<string, object> {
  const out: Record<string, object> = {};
  const keys = {
    warning: KEY_WARNING,
    derivation: "secret = SHA-256(UTF-8(\"openentity throwaway p256 \" + name)) as a big-endian P-256 scalar; kid = RFC 7638 thumbprint of the public JWK",
    keys: Object.fromEntries(Object.values(K).map((k) => [k.name, { secret: hex(k.secret), jwk: k.jwk, kid: k.kid }])),
    origins: { web: WEB_ORIGIN, android_example: ANDROID_ORIGIN },
  };
  out["approval-2.0/keys.json"] = keys;
  out["approval-2.0/vectors.json"] = approvalVectors();
  out["keylog-1/keys.json"] = keys;
  for (const [name, c] of Object.entries(keylogVectors())) out[`keylog-1/${name}.json`] = c;
  Object.assign(out, pairVectors());
  return out;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const dir = new URL("../../../test-vectors/", import.meta.url);
  for (const [path, v] of Object.entries(buildOwnerVectors())) {
    mkdirSync(new URL(path.split("/")[0] + "/", dir), { recursive: true });
    writeFileSync(new URL(path, dir), serialize(v));
  }
  console.log("wrote approval-2.0, keylog-1 and pair-sas-1 vectors to", dir.pathname);
}
