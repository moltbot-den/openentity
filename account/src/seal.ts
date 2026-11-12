// Data the service encrypts itself (Apple refresh tokens and the like): AWS KMS Encrypt and Decrypt under the data key,
// which never leaves KMS; every decrypt is logged in CloudTrail. The purpose is the encryption context, so a value
// sealed for one purpose fails to open as another. Values are small (KMS encrypts up to 4 KB directly).
import { DecryptCommand, EncryptCommand, type KMSClient } from "@aws-sdk/client-kms";

export type Purpose = "data" | "apple-refresh";
type Kms = Pick<KMSClient, "send">;

/** base64url of the KMS ciphertext blob. */
export async function seal(kms: Kms, keyId: string, purpose: Purpose, plaintext: string): Promise<string> {
  const r = await kms.send(new EncryptCommand({ KeyId: keyId, Plaintext: new TextEncoder().encode(plaintext), EncryptionContext: { purpose } }));
  return Buffer.from(r.CiphertextBlob!).toString("base64url");
}

/** Throws (InvalidCiphertextException) when the value was sealed for another purpose or under another key. */
export async function open(kms: Kms, keyId: string, purpose: Purpose, sealed: string): Promise<string> {
  const r = await kms.send(new DecryptCommand({ KeyId: keyId, CiphertextBlob: Buffer.from(sealed, "base64url"), EncryptionContext: { purpose } }));
  return new TextDecoder().decode(r.Plaintext!);
}
