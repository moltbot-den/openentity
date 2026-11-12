import { createHash } from "node:crypto";
import { expect, test } from "vitest";
import { authenticationOptions, registrationOptions, rpFor, verifyAuthentication, verifyRegistration } from "../src/passkey.ts";
import { authenticator } from "./helpers.ts";

const RP = rpFor("account.openentity.org");
const sha = (b: Uint8Array | string) => new Uint8Array(createHash("sha256").update(b).digest());
const b64u = (b: Uint8Array) => Buffer.from(b).toString("base64url");
const err = async (p: Promise<unknown>) => p.then(() => "ok", (e) => e.code);

test("options: RP ID account.openentity.org, user verification required, ES256 only, discoverable credentials", async () => {
  const reg = await registrationOptions(RP, { accountId: "acct_x", userName: "ada@example.com" });
  expect(reg.rp).toEqual({ name: "OpenEntity", id: "account.openentity.org" });
  expect(reg.pubKeyCredParams).toEqual([{ alg: -7, type: "public-key" }]);
  expect(reg.authenticatorSelection).toMatchObject({ residentKey: "required", userVerification: "required" });
  const auth = await authenticationOptions(RP);
  expect(auth).toMatchObject({ rpId: "account.openentity.org", userVerification: "required" });
  expect(auth.allowCredentials ?? []).toEqual([]);
});

test("register then sign in: the passkey's P-256 key comes back as a JWK with its RFC 7638 thumbprint", async () => {
  const a = authenticator();
  const reg = await registrationOptions(RP, { accountId: "acct_x", userName: "ada@example.com" });
  const r = await verifyRegistration(RP, a.register(reg.challenge), reg.challenge);
  expect(r.jwk).toEqual({ kty: "EC", crv: "P-256", x: a.jwk.x, y: a.jwk.y });
  expect(r.keyId).toMatch(/^[A-Za-z0-9_-]{43}$/);
  const auth = await authenticationOptions(RP);
  expect(await verifyAuthentication(RP, a.assert(auth.challenge), auth.challenge, r.credential)).toBe(1);
});

test("guards: another challenge, origin, RP ID, missing user verification or a replayed counter are passkey_invalid", async () => {
  const a = authenticator();
  const reg = await registrationOptions(RP, { accountId: "acct_x", userName: "u" });
  expect(await err(verifyRegistration(RP, a.register(reg.challenge, "https://evil.example"), reg.challenge))).toBe("passkey_invalid");
  expect(await err(verifyRegistration(RP, a.register(reg.challenge, undefined, 0x41), reg.challenge))).toBe("passkey_invalid"); // UP without UV
  expect(await err(verifyRegistration(RP, authenticator("staging.account.openentity.org").register(reg.challenge, "https://account.openentity.org"), reg.challenge))).toBe("passkey_invalid");
  const { credential } = await verifyRegistration(RP, a.register(reg.challenge), reg.challenge);
  const auth = await authenticationOptions(RP);
  expect(await err(verifyAuthentication(RP, a.assert("another-challenge"), auth.challenge, credential))).toBe("passkey_invalid");
  expect(await err(verifyAuthentication(RP, a.assert(auth.challenge, { origin: "https://staging.account.openentity.org" }), auth.challenge, credential))).toBe("passkey_invalid");
  expect(await err(verifyAuthentication(RP, a.assert(auth.challenge, { flags: 0x01 }), auth.challenge, credential))).toBe("passkey_invalid");
  expect(await verifyAuthentication(RP, a.assert(auth.challenge, { count: 7 }), auth.challenge, credential)).toBe(7);
  expect(await err(verifyAuthentication(RP, a.assert(auth.challenge, { count: 5 }), auth.challenge, { ...credential, counter: 7 }))).toBe("passkey_invalid");
  // A different passkey's assertion for this credential id.
  expect(await err(verifyAuthentication(RP, authenticator().assert(auth.challenge), auth.challenge, credential))).toBe("passkey_invalid");
});

test("the Android app origin is accepted only once configured", async () => {
  const origin = "android:apk-key-hash:" + b64u(sha("signing-cert"));
  const a = authenticator();
  const reg = await registrationOptions(RP, { accountId: "acct_x", userName: "u" });
  expect(await err(verifyRegistration(RP, a.register(reg.challenge, origin), reg.challenge))).toBe("passkey_invalid");
  expect(await err(verifyRegistration(rpFor(RP.id, [origin]), a.register(reg.challenge, origin), reg.challenge))).toBe("ok");
});
