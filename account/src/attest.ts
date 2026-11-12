// Device key attestation (POST /v1/keylog/attestations): the platform proves an approver key lives on a genuine device
// running the OpenEntity app, and the service answers with a receipt (KeyAttestationReceipt), a compact JWS by its
// Ed25519 key, that the key log credential carries. iOS: App Attest. Android Key Attestation lands next.
import { X509Certificate, createHash, createPublicKey, verify } from "node:crypto";
import { decodeAttestationObject } from "@simplewebauthn/server/helpers";
import type { Deps } from "./app.ts";
import { now } from "./db.ts";
import { fail } from "./http.ts";
import { APP_ID } from "./wellknown.ts";

/** Apple App Attestation Root CA (https://www.apple.com/certificateauthority/), SHA-256 fingerprint 1C:B9:82:3B:A2:8B:A6:AD:2D:33:A0:06:94:1D:E2:AE:4F:51:3E:F1:D4:E8:31:B9:F7:E0:FA:7B:62:42:C9:32. */
export const APPLE_APP_ATTEST_ROOT = `-----BEGIN CERTIFICATE-----
MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYw
JAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwK
QXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNa
Fw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlv
biBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9y
bmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdh
NbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9au
Yen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/
MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYw
CgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn
53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijV
oyFraWVIyd/dganmrduC1bmTBGwD
-----END CERTIFICATE-----`;
const NONCE_OID = Buffer.from("06092a864886f763640802", "hex"); // 1.2.840.113635.100.8.2
const AAGUID = { production: Buffer.from("appattest\0\0\0\0\0\0\0"), development: Buffer.from("appattestdevelop") };

const sha256 = (...parts: Uint8Array[]) => { const h = createHash("sha256"); for (const p of parts) h.update(p); return h.digest(); };
const bad = (why: string): never => fail(403, "attestation_invalid", why);

/** The chain leaf -> ... -> a pinned root, each signature and validity checked at `at`. */
function chainTo(ders: Uint8Array[], roots: X509Certificate[], at: Date): X509Certificate {
  const certs = ders.map((c) => { try { return new X509Certificate(Buffer.from(c)); } catch { return bad("a certificate in the chain does not parse"); } });
  const ok = (c: X509Certificate) => new Date(c.validFrom) <= at && at <= new Date(c.validTo);
  for (let i = 0; i < certs.length; i++) {
    const issuer = certs[i + 1] ?? roots.find((r) => certs[i].checkIssued(r) && certs[i].verify(r.publicKey)) ?? bad("the chain does not end at the pinned root");
    if (!certs[i].checkIssued(issuer) || !certs[i].verify(issuer.publicKey) || !ok(certs[i])) bad(`certificate ${i} is not issued by the next one or is not valid now`);
  }
  return certs[0];
}

/**
 * App Attest (Apple, "Validating apps that connect to your server"): the attestation of a new App Attest key whose
 * clientDataHash is SHA-256(UTF-8(nonce + "|" + kid)). Checks the x5c chain to the Apple root, the nonce extension,
 * that the key id is the SHA-256 of the attested public key, the RP ID hash of the app id, counter 0 and the AAGUID
 * of the environment. Throws 403 attestation_invalid naming the failed check.
 */
export function verifyAppAttest(o: { attestationObject: Uint8Array; keyId: string; clientDataHash: Uint8Array; production: boolean; roots?: X509Certificate[]; at?: Date; appId?: string }): { publicKey: Buffer } {
  let att: Map<string, any>;
  try { att = decodeAttestationObject(new Uint8Array(o.attestationObject)) as unknown as Map<string, any>; } catch { return bad("attestation_object is not CBOR"); }
  if (att.get("fmt") !== "apple-appattest") bad("fmt must be apple-appattest");
  const stmt = att.get("attStmt") as Map<string, any> | undefined, authData = att.get("authData") as Uint8Array | undefined;
  const x5c = stmt?.get("x5c") as Uint8Array[] | undefined;
  if (!Array.isArray(x5c) || x5c.length < 2 || !(authData instanceof Uint8Array) || authData.length < 55) bad("attestation_object misses x5c or authData");
  const leaf = chainTo(x5c!, o.roots ?? [new X509Certificate(APPLE_APP_ATTEST_ROOT)], o.at ?? new Date());
  const nonce = sha256(authData!, o.clientDataHash);
  const der = leaf.raw, at = der.indexOf(NONCE_OID);
  // The extension is SEQUENCE { OID, OCTET STRING { SEQUENCE { [1] { OCTET STRING nonce } } } }: the nonce's 04 20 header
  // starts 17 bytes after the OID; the chain check above already proved Apple signed these bytes.
  if (at < 0 || der.subarray(at, at + 64).indexOf(Buffer.concat([Buffer.from([0x04, 0x20]), nonce])) < 0) bad("the nonce extension does not match this request");
  const point = leaf.publicKey.export({ format: "der", type: "spki" }).subarray(-65);
  const keyId = Buffer.from(o.keyId, "base64");
  if (!sha256(point).equals(keyId)) bad("key_id is not the SHA-256 of the attested key");
  const a = Buffer.from(authData!);
  if (!a.subarray(0, 32).equals(sha256(Buffer.from(o.appId ?? APP_ID)))) bad("the RP ID hash is not this app's");
  if (a.readUInt32BE(33) !== 0) bad("the counter of a new key is 0");
  if (!a.subarray(37, 53).equals(o.production ? AAGUID.production : AAGUID.development)) bad(`the AAGUID is not App Attest ${o.production ? "production" : "development"}`);
  const len = a.readUInt16BE(53);
  if (!a.subarray(55, 55 + len).equals(keyId)) bad("the credential id is not key_id");
  return { publicKey: leaf.publicKey.export({ format: "der", type: "spki" }) };
}

/**
 * An App Attest assertion (every refresh, X-OE-App-Attest): CBOR {signature, authenticatorData} by the attested key
 * over SHA-256(authenticatorData || clientDataHash), this app's RP ID hash, and a counter above the last one seen.
 * Returns the new counter; throws 401 binding_invalid.
 */
export function verifyAppAttestAssertion(o: { assertion: Uint8Array; publicKey: Buffer; clientDataHash: Uint8Array; counter: number; appId?: string }): number {
  const invalid = (why: string): never => fail(401, "binding_invalid", why);
  let m: Map<string, any>;
  try { m = decodeAttestationObject(new Uint8Array(o.assertion)) as unknown as Map<string, any>; } catch { return invalid("X-OE-App-Attest is not CBOR"); }
  const sig = m.get("signature"), auth = m.get("authenticatorData");
  if (!(sig instanceof Uint8Array) || !(auth instanceof Uint8Array) || auth.length < 37) invalid("the assertion needs signature and authenticatorData");
  const a = Buffer.from(auth);
  if (!a.subarray(0, 32).equals(sha256(Buffer.from(o.appId ?? APP_ID)))) invalid("the RP ID hash is not this app's");
  const counter = a.readUInt32BE(33);
  if (counter <= o.counter) invalid("the assertion counter did not increase");
  const key = createPublicKey({ key: o.publicKey, format: "der", type: "spki" });
  if (!verify("sha256", sha256(a, o.clientDataHash), key, Buffer.from(sig))) invalid("the assertion signature does not verify");
  return counter;
}

/** The receipt: a compact JWS {alg EdDSA, kid <service DID>#<thumbprint>, typ oe-key-attestation+jwt} by the service key. */
export async function receipt(d: Deps, claims: Record<string, unknown>): Promise<string> {
  const b64 = (v: unknown) => Buffer.from(JSON.stringify(v)).toString("base64url");
  const input = `${b64({ alg: "EdDSA", kid: `did:web:${d.host}#${d.keys.did.kid}`, typ: "oe-key-attestation+jwt" })}.${b64(claims)}`;
  return `${input}.${Buffer.from(await d.keys.did.sign(new TextEncoder().encode(input))).toString("base64url")}`;
}

export const receiptClaims = (d: Deps, kid: string, platform: "ios" | "android", rest: { type: "app_attest" | "android_key"; key_storage: string; integrity: { device: boolean; strong: boolean } | null }) =>
  ({ iss: `did:web:${d.host}`, kid, platform, ...rest, verified: true, iat: now() });

// ---------------------------------------------------------------- Android Key Attestation

/** Google's hardware attestation roots (https://android.googleapis.com/attestation/root): the RSA root re-issued in 2022 and Key Attestation CA1 (2025). */
export const GOOGLE_ATTESTATION_ROOTS = [`-----BEGIN CERTIFICATE-----
MIIFHDCCAwSgAwIBAgIJAPHBcqaZ6vUdMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNV
BAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcNMjIwMzIwMTgwNzQ4WhcNNDIwMzE1MTgw
NzQ4WjAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0B
AQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdS
Sxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7
tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggj
nar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGq
C4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQ
oVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+O
JtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/Eg
sTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRi
igHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+M
RPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9E
aDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5Um
AGMCAwEAAaNjMGEwHQYDVR0OBBYEFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMB8GA1Ud
IwQYMBaAFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMA8GA1UdEwEB/wQFMAMBAf8wDgYD
VR0PAQH/BAQDAgIEMA0GCSqGSIb3DQEBCwUAA4ICAQB8cMqTllHc8U+qCrOlg3H7
174lmaCsbo/bJ0C17JEgMLb4kvrqsXZs01U3mB/qABg/1t5Pd5AORHARs1hhqGIC
W/nKMav574f9rZN4PC2ZlufGXb7sIdJpGiO9ctRhiLuYuly10JccUZGEHpHSYM2G
tkgYbZba6lsCPYAAP83cyDV+1aOkTf1RCp/lM0PKvmxYN10RYsK631jrleGdcdkx
oSK//mSQbgcWnmAEZrzHoF1/0gso1HZgIn0YLzVhLSA/iXCX4QT2h3J5z3znluKG
1nv8NQdxei2DIIhASWfu804CA96cQKTTlaae2fweqXjdN1/v2nqOhngNyz1361mF
mr4XmaKH/ItTwOe72NI9ZcwS1lVaCvsIkTDCEXdm9rCNPAY10iTunIHFXRh+7KPz
lHGewCq/8TOohBRn0/NNfh7uRslOSZ/xKbN9tMBtw37Z8d2vvnXq/YWdsm1+JLVw
n6yYD/yacNJBlwpddla8eaVMjsF6nBnIgQOf9zKSe06nSTqvgwUHosgOECZJZ1Eu
zbH4yswbt02tKtKEFhx+v+OTge/06V+jGsqTWLsfrOCNLuA8H++z+pUENmpqnnHo
vaI47gC+TNpkgYGkkBT6B/m/U01BuOBBTzhIlMEZq9qkDWuM2cA5kW5V3FJUcfHn
w1IdYIg2Wxg7yHcQZemFQg==
-----END CERTIFICATE-----`, `-----BEGIN CERTIFICATE-----
MIICIjCCAaigAwIBAgIRAISp0Cl7DrWK5/8OgN52BgUwCgYIKoZIzj0EAwMwUjEc
MBoGA1UEAwwTS2V5IEF0dGVzdGF0aW9uIENBMTEQMA4GA1UECwwHQW5kcm9pZDET
MBEGA1UECgwKR29vZ2xlIExMQzELMAkGA1UEBhMCVVMwHhcNMjUwNzE3MjIzMjE4
WhcNMzUwNzE1MjIzMjE4WjBSMRwwGgYDVQQDDBNLZXkgQXR0ZXN0YXRpb24gQ0Ex
MRAwDgYDVQQLDAdBbmRyb2lkMRMwEQYDVQQKDApHb29nbGUgTExDMQswCQYDVQQG
EwJVUzB2MBAGByqGSM49AgEGBSuBBAAiA2IABCPaI3FO3z5bBQo8cuiEas4HjqCt
G/mLFfRT0MsIssPBEEU5Cfbt6sH5yOAxqEi5QagpU1yX4HwnGb7OtBYpDTB57uH5
Eczm34A5FNijV3s0/f0UPl7zbJcTx6xwqMIRq6NCMEAwDwYDVR0TAQH/BAUwAwEB
/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFFIyuyz7RkOb3NaBqQ5lZuA0QepA
MAoGCCqGSM49BAMDA2gAMGUCMETfjPO/HwqReR2CS7p0ZWoD/LHs6hDi422opifH
EUaYLxwGlT9SLdjkVpz0UUOR5wIxAIoGyxGKRHVTpqpGRFiJtQEOOTp/+s1GcxeY
uR2zh/80lQyu9vAFCj6E4AXc+osmRg==
-----END CERTIFICATE-----`];
const KEY_DESCRIPTION_OID = Buffer.from("060a2b06010401d679020111", "hex"); // 1.3.6.1.4.1.11129.2.1.17

interface Tlv { tag: number; constructed: boolean; context: boolean; start: number; end: number }
/** One DER TLV at `i` (multi-byte tag numbers included), bounds-checked. */
function tlv(b: Buffer, i: number): Tlv {
  const first = b[i++];
  let tag = first & 0x1f;
  if (tag === 0x1f) { tag = 0; let x; do { x = b[i++]; tag = tag * 128 + (x & 0x7f); } while (x & 0x80); }
  let len = b[i++];
  if (len & 0x80) { const n = len & 0x7f; if (n > 3) throw new Error("length"); len = 0; for (let k = 0; k < n; k++) len = len * 256 + b[i++]; }
  if (first === undefined || i + len > b.length) throw new Error("truncated");
  return { tag, constructed: !!(first & 0x20), context: (first & 0xc0) === 0x80, start: i, end: i + len };
}
const kids = (b: Buffer, t: Tlv) => { const out: Tlv[] = []; for (let i = t.start; i < t.end;) { const x = tlv(b, i); out.push(x); i = x.end; } return out; };
const uint = (b: Buffer, t: Tlv) => Number(BigInt(`0x${b.subarray(t.start, t.end).toString("hex") || "0"}`));

export interface AndroidKey { jwk: { kty: "EC"; crv: "P-256"; x: string; y: string }; keyStorage: "tee" | "strongbox"; challenge: Buffer }

/**
 * Android Key Attestation of a hardware-backed P-256 key: the chain (leaf first) to a pinned Google root, no revoked
 * certificate, the KeyDescription challenge, security level TrustedEnvironment or StrongBox, a key generated in the
 * hardware, and this app's package. `biometric` (approver keys) also needs user authentication by a biometric on
 * every use. Throws 403 attestation_invalid naming the failed check.
 */
export function verifyAndroidKey(o: { chain: string[]; biometric: boolean; packageName: string; revoked?: Set<string>; roots?: X509Certificate[]; at?: Date }): AndroidKey {
  if (!Array.isArray(o.chain) || o.chain.length < 2 || o.chain.length > 10 || o.chain.some((c) => typeof c !== "string")) bad("certificate_chain is 2 to 10 base64 DER certificates");
  const ders = o.chain.map((c) => Buffer.from(c, "base64"));
  const leaf = chainTo(ders, o.roots ?? GOOGLE_ATTESTATION_ROOTS.map((p) => new X509Certificate(p)), o.at ?? new Date());
  for (const c of ders.map((x) => new X509Certificate(x))) {
    const serial = c.serialNumber.toLowerCase().replace(/^0+/, "");
    if (o.revoked?.has(serial) || o.revoked?.has(BigInt(`0x${serial || "0"}`).toString())) bad("a certificate in the chain is revoked");
  }
  const jwk = leaf.publicKey.export({ format: "jwk" }) as any;
  if (jwk.kty !== "EC" || jwk.crv !== "P-256") bad("the attested key is not P-256");
  const raw = leaf.raw, at = raw.indexOf(KEY_DESCRIPTION_OID);
  if (at < 0) bad("the leaf has no key description");
  let f: Tlv[], b = raw;
  try {
    let t = tlv(raw, at + KEY_DESCRIPTION_OID.length);
    if (!t.context && t.tag === 1) t = tlv(raw, t.end); // critical BOOLEAN
    b = raw.subarray(t.start, t.end); // the OCTET STRING's content: KeyDescription
    f = kids(b, tlv(b, 0));
  } catch { return bad("the key description does not parse"); }
  if (f!.length < 8) bad("the key description is short");
  const level = uint(b, f![1]);
  if (level !== 1 && level !== 2) bad("the key is not in a TrustedEnvironment or StrongBox");
  const list = (t: Tlv) => new Map(kids(b, t).map((x) => [x.tag, x] as const));
  const sw = list(f![6]), hw = list(f![7]);
  const inner = (x: Tlv | undefined) => (x ? tlv(b, x.start) : undefined);
  const origin = inner(hw.get(702));
  if (!origin || uint(b, origin) !== 0) bad("the key was not generated in the hardware");
  // attestationApplicationId: SEQUENCE { SET OF { packageName OCTET STRING, version INTEGER }, SET OF digests }.
  const app = inner(sw.get(709)) ?? inner(hw.get(709));
  let packages: string[] = [];
  try {
    const seq = tlv(b, app!.start);
    packages = kids(b, kids(b, seq)[0]).map((info) => { const name = kids(b, info)[0]; return b.subarray(name.start, name.end).toString("utf8"); });
  } catch { bad("the attestation application id does not parse"); }
  if (!packages.includes(o.packageName)) bad(`the key belongs to ${packages.join(", ") || "no package"}, not ${o.packageName}`);
  if (o.biometric) {
    const userAuth = inner(hw.get(504));
    if (hw.has(503) || !userAuth || !(uint(b, userAuth) & 2) || hw.has(505)) bad("an approver key needs a biometric on every use");
  }
  return { jwk: { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y }, keyStorage: level === 2 ? "strongbox" : "tee", challenge: Buffer.from(b.subarray(f![4].start, f![4].end)) };
}
