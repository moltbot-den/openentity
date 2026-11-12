// Data the service encrypts itself (Apple refresh tokens and the like): AES-256-GCM under one data key from SSM
// (/openentity/account/data_key_<stage>, 32 random bytes, base64url). Each purpose is bound in as additional data,
// the way a KMS encryption context would be, so a value sealed for one purpose never opens as another.
// ponytail: an SSM-held data key keeps KMS at three signing keys per stage (the $6 budget); a KMS data key is the upgrade.
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

export type Purpose = "data" | "apple-refresh";
const aad = (purpose: Purpose) => Buffer.from(`purpose=${purpose}`);

/** base64url(iv 12 bytes || ciphertext || tag 16 bytes) */
export function seal(key: Buffer, purpose: Purpose, plaintext: string): string {
  const iv = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", key, iv).setAAD(aad(purpose));
  const body = Buffer.concat([c.update(plaintext, "utf8"), c.final()]);
  return Buffer.concat([iv, body, c.getAuthTag()]).toString("base64url");
}

/** Throws when the value was sealed under another key or purpose, or was altered. */
export function open(key: Buffer, purpose: Purpose, sealed: string): string {
  const b = Buffer.from(sealed, "base64url");
  if (b.length < 28) throw new Error("sealed value too short");
  const d = createDecipheriv("aes-256-gcm", key, b.subarray(0, 12)).setAAD(aad(purpose));
  d.setAuthTag(b.subarray(b.length - 16));
  return Buffer.concat([d.update(b.subarray(12, b.length - 16)), d.final()]).toString("utf8");
}

export function dataKey(b64url: string | undefined): Buffer {
  const k = Buffer.from(b64url ?? "", "base64url");
  if (k.length !== 32) throw new Error("data_key must be 32 bytes, base64url");
  return k;
}
