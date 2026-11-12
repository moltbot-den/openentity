// Device binding (PLAN 2.4): an app session's refresh tokens work only with the key its install proved at sign-in.
// iOS: an App Attest key, then an assertion over every refresh body. Android: a hardware-backed Keystore key (Key
// Attestation), then its signature over every refresh body, with a Play Integrity token bound to that body.
// Production refuses an app session without a binding; staging binds when the app sends an attestation.
import { createHash, createPublicKey, verify } from "node:crypto";
import type { Context } from "hono";
import type { Deps } from "./app.ts";
import { verifyAndroidKey, verifyAppAttest, verifyAppAttestAssertion } from "./attest.ts";
import { now } from "./db.ts";
import { HttpError, fail } from "./http.ts";
import { nonceHash } from "./idtoken.ts";
import type { Platform } from "./sessions.ts";
import { BUNDLE_ID } from "./wellknown.ts";

export type Binding =
  | { type: "app_attest"; key_id: string; public_key: string; counter: number }
  | { type: "android_key"; jwk: { kty: "EC"; crv: "P-256"; x: string; y: string }; key_storage: "tee" | "strongbox" };

/** A decoded Play Integrity verdict (standard request), from Google's decodeIntegrityToken. */
export interface IntegrityVerdict { requestHash: string; packageName: string; deviceIntegrity: string[]; appRecognition: string }

const sha256 = (b: Uint8Array | string) => createHash("sha256").update(b).digest();
const STATUS_URL = "https://android.googleapis.com/attestation/status";
let revocations: { at: number; serials: Set<string> } | undefined;

/** Google's revoked attestation certificates (serials, hex and decimal), cached an hour. */
export async function revokedSerials(d: Deps): Promise<Set<string>> {
  if (revocations && Date.now() - revocations.at < 3_600_000) return revocations.serials;
  try {
    const r = await (d.fetch ?? fetch)(STATUS_URL, { signal: AbortSignal.timeout(5000) });
    if (!r.ok) throw new Error(`status list answered ${r.status}`);
    const entries = (await r.json()).entries ?? {};
    revocations = { at: Date.now(), serials: new Set(Object.keys(entries).map((k) => k.toLowerCase())) };
    return revocations.serials;
  } catch (e) {
    if (d.stage === "production") fail(503, "unavailable", "the attestation revocation list cannot be read; try again");
    console.warn("attestation status list unavailable", e);
    return new Set();
  }
}

/**
 * Checks a Play Integrity token bound to `requestHash`: this app, and MEETS_DEVICE_INTEGRITY (production: also
 * recognized by Play). Without a decoder (no Google credentials in this environment) production refuses and staging
 * skips the check. Returns whether the device met integrity, and strong integrity.
 */
export async function integrity(d: Deps, token: unknown, requestHash: string, use: "refresh" | "sign-in" | "approver"): Promise<{ device: boolean; strong: boolean } | null> {
  if (!d.playIntegrity) {
    if (d.stage === "production" || use === "approver") fail(503, "unavailable", "Play Integrity is not configured in this environment");
    return null;
  }
  const [status, code] = use === "refresh" ? [401, "binding_invalid"] : [403, "attestation_invalid"];
  if (typeof token !== "string" || !token) fail(status, code, "a Play Integrity token is required");
  const v = await d.playIntegrity(token as string).catch(() => null);
  if (!v || v.requestHash !== requestHash || v.packageName !== BUNDLE_ID) fail(status, code, "the Play Integrity token is not for this request or app");
  if (d.stage === "production" && v!.appRecognition !== "PLAY_RECOGNIZED") fail(status, code, "the app is not the one Play installed");
  if (!v!.deviceIntegrity.includes("MEETS_DEVICE_INTEGRITY")) fail(status, use === "approver" ? "integrity_failed" : code, "the device does not meet Play device integrity");
  return { device: true, strong: v!.deviceIntegrity.includes("MEETS_STRONG_INTEGRITY") };
}

/** The proof a request carries for an install's key, over SHA-256 of its raw body (the refresh headers). */
export interface BodyProof { header: (name: string) => string | undefined; body: Uint8Array }

/** A proof by the bound key over this body: the App Attest assertion (counter rises) or the Keystore signature plus Play Integrity. */
async function proven(d: Deps, b: Binding, p: BodyProof, use: "refresh" | "sign-in"): Promise<Binding> {
  const [status, missing] = use === "refresh" ? [401, "binding_required"] : [403, "attestation_required"];
  if (b.type === "app_attest") {
    const h = p.header("x-oe-app-attest") ?? fail(status, missing, "send X-OE-App-Attest: an App Attest assertion over the request body");
    const counter = verifyAppAttestAssertion({ assertion: Buffer.from(h, "base64url"), publicKey: Buffer.from(b.public_key, "base64"), clientDataHash: sha256(p.body), counter: b.counter });
    return { ...b, counter };
  }
  const sig = p.header("x-oe-device-signature") ?? fail(status, missing, "send X-OE-Device-Signature: the Keystore key's signature over the request body");
  if (!verify("sha256", p.body, createPublicKey({ key: b.jwk, format: "jwk" }), Buffer.from(sig, "base64url"))) fail(401, "binding_invalid", "the device signature does not verify");
  await integrity(d, p.header("x-oe-play-integrity"), sha256(p.body).toString("hex"), use);
  return b;
}

/**
 * The binding for a session an app sign-in opens (sessions.ts openSession calls it). An install that attested before
 * proves the same key over this sign-in's body (X-OE-App-Attest, or X-OE-Device-Signature with X-OE-Play-Integrity),
 * with no nonce. An install's first sign-in, or one with a new key, sends `attestation` over a nonce issued to that
 * install: the sign-in's own `nonce` (Apple, Google), else its newest unused nonce, which this uses up (email,
 * passkey). Production refuses an app session without either (403 attestation_required).
 * Returns the JSON for sessions.binding, or null (web, or staging without a proof).
 */
export async function deviceBinding(d: Deps, o: { platform: Platform; installId: string | null; attestation: any; nonce?: string; proof?: BodyProof }): Promise<string | null> {
  if (o.platform === "web") return null;
  const production = d.stage === "production";
  if (!o.attestation) {
    const prior = o.installId ? await d.db.first<{ binding: string }>("SELECT binding FROM sessions WHERE install_id = $1 AND platform = $2 AND binding IS NOT NULL ORDER BY created_at DESC LIMIT 1", [o.installId, o.platform]) : null;
    if (prior && o.proof && (o.proof.header("x-oe-app-attest") || o.proof.header("x-oe-device-signature"))) {
      // A sign-in answers attestation_invalid where a refresh answers binding_invalid.
      const b = await proven(d, JSON.parse(prior.binding), o.proof, "sign-in").catch((e) => {
        throw e instanceof HttpError && e.code === "binding_invalid" ? new HttpError(403, "attestation_invalid", e.message) : e;
      });
      return JSON.stringify(b);
    }
    if (production) fail(403, "attestation_required", prior ? "prove this install's key over the request body (X-OE-App-Attest, or X-OE-Device-Signature with X-OE-Play-Integrity)" : "the first sign-in from an install sends its attestation; fetch a new nonce and retry");
    return null;
  }
  const hashes = o.nonce ? [nonceHash(o.nonce)] : (await d.db.all<{ hash: string }>(
    "SELECT hash FROM auth_nonces WHERE install_id = $1 AND platform = $2 AND used_at IS NULL AND expires_at > $3 ORDER BY created_at DESC LIMIT 5", [o.installId, o.platform, now()])).map((r) => r.hash);
  if (!hashes.length) fail(403, "attestation_invalid", "no nonce of this install matches; fetch one from POST /v1/auth/nonce");
  const spend = async (hash: string) => {
    if (o.nonce) return; // the sign-in already used it
    const used = await d.db.run("UPDATE auth_nonces SET used_at = $2 WHERE hash = $1 AND used_at IS NULL", [hash, now()]);
    if (!used.changes) fail(403, "attestation_invalid", "the nonce was already used");
  };
  const a = o.attestation;
  if (o.platform === "ios" && a.type === "app_attest" && typeof a.key_id === "string" && typeof a.attestation_object === "string") {
    let last: unknown;
    for (const h of hashes) {
      try {
        const { publicKey } = verifyAppAttest({ attestationObject: Buffer.from(a.attestation_object, "base64url"), keyId: a.key_id, clientDataHash: Buffer.from(h, "hex"), production, roots: d.attestRoots?.apple });
        await spend(h);
        return JSON.stringify({ type: "app_attest", key_id: a.key_id, public_key: publicKey.toString("base64"), counter: 0 } satisfies Binding);
      } catch (e) {
        if (!(e instanceof HttpError)) throw e;
        last = e;
      }
    }
    throw last;
  }
  if (o.platform === "android" && a.type === "android_key") {
    const k = verifyAndroidKey({ chain: a.certificate_chain, biometric: false, packageName: BUNDLE_ID, revoked: await revokedSerials(d), roots: d.attestRoots?.google });
    const h = sha256(k.challenge).toString("hex"); // attestationChallenge = UTF-8 of the raw nonce
    if (!hashes.includes(h)) fail(403, "attestation_invalid", "the attestation challenge is not this sign-in's nonce");
    await integrity(d, a.integrity_token, h, "sign-in");
    await spend(h);
    return JSON.stringify({ type: "android_key", jwk: k.jwk, key_storage: k.keyStorage } satisfies Binding);
  }
  return fail(403, "attestation_invalid", "the attestation does not fit this platform");
}

/**
 * The refresh check (POST /v1/token): the request proves the session's key over its raw body. iOS: X-OE-App-Attest,
 * whose counter must rise. Android: X-OE-Device-Signature and X-OE-Play-Integrity. 401 binding_required or
 * binding_invalid. Production refuses an app session that has no binding.
 */
export async function checkBinding(c: Context, d: Deps, session: { id: string; platform: string; binding: string | null }, body: Uint8Array): Promise<void> {
  if (session.platform === "web") return;
  if (!session.binding) {
    if (d.stage === "production") fail(401, "binding_required", "this session is not bound to a device key; sign in again");
    return;
  }
  const next = JSON.stringify(await proven(d, JSON.parse(session.binding), { header: (n) => c.req.header(n), body }, "refresh"));
  if (next === session.binding) return;
  const moved = await d.db.run("UPDATE sessions SET binding = $3 WHERE id = $1 AND binding = $2", [session.id, session.binding, next]);
  if (!moved.changes) fail(401, "binding_invalid", "another refresh moved the assertion counter; retry");
}
