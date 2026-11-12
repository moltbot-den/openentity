// Signing keys. Both private keys live in AWS KMS and never leave it:
//   token key: ECC_NIST_P256, ES256 access tokens (PLAN 2.4), published in /.well-known/jwks.json;
//   DID key:   ECC_NIST_EDWARDS25519, RFC 9421 signatures on calls to products, published in /.well-known/did.json.
import { GetPublicKeyCommand, KMSClient, SignCommand } from "@aws-sdk/client-kms";
import { createHash, createPublicKey } from "node:crypto";
import { calculateJwkThumbprint, type JWK } from "jose";

/** Signs bytes and returns the signature in JOSE form (ES256: r || s; Ed25519: the 64-byte signature). */
export type Signer = (data: Uint8Array) => Promise<Uint8Array>;
export interface SigningKey { jwk: JWK; kid: string; sign: Signer }

const malformed = (): never => { throw new Error("malformed DER ECDSA signature"); };

/**
 * DER ECDSA-Sig-Value (SEQUENCE { r INTEGER, s INTEGER }, what KMS returns) to the JOSE form JWTs need:
 * r || s, each left-padded to `size` bytes (RFC 7518 section 3.4). Rejects anything that is not minimal DER.
 */
export function derToJose(der: Uint8Array, size = 32): Uint8Array {
  let i = 0;
  if (der[i++] !== 0x30) malformed();
  let len = der[i++];
  if (len === 0x81) len = der[i++]; // long form, one length byte (only curves above P-384 need it)
  else if (len & 0x80) malformed();
  if (len !== der.length - i) malformed();
  const int = (): Uint8Array => {
    if (der[i++] !== 0x02) malformed();
    const n = der[i++];
    if (!n || n > size + 1 || i + n > der.length) malformed();
    let v = der.subarray(i, i + n);
    i += n;
    if (v[0] & 0x80) malformed(); // negative
    if (v[0] === 0 && n > 1) {
      if (!(v[1] & 0x80)) malformed(); // a zero pad is allowed only before a high bit
      v = v.subarray(1);
    }
    if (v.length > size) malformed();
    const out = new Uint8Array(size);
    out.set(v, size - v.length);
    return out;
  };
  const r = int(), s = int();
  if (i !== der.length) malformed();
  const out = new Uint8Array(size * 2);
  out.set(r);
  out.set(s, size);
  return out;
}

const b64u = (b: Uint8Array | string) => Buffer.from(b).toString("base64url");

/** A compact JWS: base64url(header) "." base64url(claims) "." base64url(signature). */
export async function signJwt(key: SigningKey, header: Record<string, unknown>, claims: Record<string, unknown>): Promise<string> {
  const input = `${b64u(JSON.stringify({ alg: "ES256", kid: key.kid, ...header }))}.${b64u(JSON.stringify(claims))}`;
  return `${input}.${b64u(await key.sign(new TextEncoder().encode(input)))}`;
}

/** ES256 through KMS: hash locally (no 4096-byte message limit), sign the digest, convert DER to r || s. */
export const kmsEs256 = (kms: KMSClient, keyId: string): Signer => async (data) => {
  const digest = createHash("sha256").update(data).digest();
  const r = await kms.send(new SignCommand({ KeyId: keyId, Message: digest, MessageType: "DIGEST", SigningAlgorithm: "ECDSA_SHA_256" }));
  return derToJose(r.Signature!);
};

/** Pure Ed25519 through KMS (ED25519_SHA_512 takes the raw message, at most 4096 bytes; an RFC 9421 base is far smaller). */
export const kmsEd25519 = (kms: KMSClient, keyId: string): Signer => async (data) => {
  const r = await kms.send(new SignCommand({ KeyId: keyId, Message: data, MessageType: "RAW", SigningAlgorithm: "ED25519_SHA_512" }));
  const sig = r.Signature!;
  if (sig.length !== 64) throw new Error(`KMS returned a ${sig.length}-byte Ed25519 signature`);
  return sig;
};

/** The public half of a KMS key as a JWK, with its RFC 7638 thumbprint as kid (the same id names it in did.json). */
export async function kmsKey(kms: KMSClient, keyId: string, sign: (kms: KMSClient, id: string) => Signer): Promise<SigningKey> {
  const { PublicKey } = await kms.send(new GetPublicKeyCommand({ KeyId: keyId }));
  return publicKey(createPublicKey({ key: Buffer.from(PublicKey!), format: "der", type: "spki" }).export({ format: "jwk" }) as JWK, sign(kms, keyId));
}

export async function publicKey(jwk: JWK, sign: Signer): Promise<SigningKey> {
  const pub: JWK = jwk.kty === "OKP" ? { kty: "OKP", crv: jwk.crv, x: jwk.x } : { kty: "EC", crv: jwk.crv, x: jwk.x, y: jwk.y };
  return { jwk: pub, kid: await calculateJwkThumbprint(pub, "sha256"), sign };
}
