import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { DecryptCommand, EncryptCommand } from "@aws-sdk/client-kms";
import { expect, test } from "vitest";
import { open, seal } from "../src/seal.ts";

// A stand-in for KMS with its encryption-context rule: the context is authenticated, and Decrypt fails unless it is the
// same. The live check against the real key is account/test/kms-live.ts.
const key = randomBytes(32);
const sent: unknown[] = [];
const kms = {
  async send(cmd: EncryptCommand | DecryptCommand) {
    const i = cmd.input as any;
    sent.push(i);
    const aad = Buffer.from(JSON.stringify(i.EncryptionContext ?? {}));
    if (cmd instanceof EncryptCommand) {
      const iv = randomBytes(12), c = createCipheriv("aes-256-gcm", key, iv).setAAD(aad);
      const body = Buffer.concat([c.update(i.Plaintext), c.final()]);
      return { CiphertextBlob: Buffer.concat([iv, body, c.getAuthTag()]) };
    }
    const b = Buffer.from(i.CiphertextBlob), d = createDecipheriv("aes-256-gcm", key, b.subarray(0, 12)).setAAD(aad);
    d.setAuthTag(b.subarray(b.length - 16));
    try { return { Plaintext: Buffer.concat([d.update(b.subarray(12, b.length - 16)), d.final()]) }; } catch { throw Object.assign(new Error("InvalidCiphertextException"), { name: "InvalidCiphertextException" }); }
  },
} as any;

test("seal and open send the purpose as the KMS encryption context and round-trip", async () => {
  const s = await seal(kms, "arn:data", "apple-refresh", "r.apple-refresh-token");
  expect(await open(kms, "arn:data", "apple-refresh", s)).toBe("r.apple-refresh-token");
  expect(sent.map((x: any) => x.EncryptionContext)).toEqual([{ purpose: "apple-refresh" }, { purpose: "apple-refresh" }]);
  expect(sent.every((x: any) => x.KeyId === "arn:data")).toBe(true);
});

test("a value sealed for one purpose fails to open as the other, either way", async () => {
  await expect(open(kms, "arn:data", "data", await seal(kms, "arn:data", "apple-refresh", "secret"))).rejects.toThrow("InvalidCiphertextException");
  await expect(open(kms, "arn:data", "apple-refresh", await seal(kms, "arn:data", "data", "secret"))).rejects.toThrow("InvalidCiphertextException");
});
