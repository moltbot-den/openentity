import { createHash, generateKeyPairSync, randomBytes, sign as nodeSign } from "node:crypto";
import { isoCBOR } from "@simplewebauthn/server/helpers";
import { expect, test } from "vitest";
import { authenticationOptions, registrationOptions, rpFor, verifyAuthentication, verifyRegistration } from "../src/passkey.ts";

const RP = rpFor("account.openentity.org");
const sha = (b: Uint8Array | string) => new Uint8Array(createHash("sha256").update(b).digest());
const b64u = (b: Uint8Array) => Buffer.from(b).toString("base64url");
const u32 = (n: number) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n); return b; };
const cat = (...p: Uint8Array[]) => { const o = new Uint8Array(p.reduce((n, x) => n + x.length, 0)); let i = 0; for (const x of p) { o.set(x, i); i += x.length; } return o; };

/** A software platform authenticator: P-256, user verification, fmt "none". Fresh throwaway keys per run. */
function authenticator(rpId = RP.id) {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = publicKey.export({ format: "jwk" });
  const credId = new Uint8Array(randomBytes(32));
  let counter = 0;
  const client = (type: string, challenge: string, origin: string) => new TextEncoder().encode(JSON.stringify({ type, challenge, origin, crossOrigin: false }));
  return {
    jwk,
    register(challenge: string, origin = `https://${rpId}`, flags = 0x45) {
      const coseKey = isoCBOR.encode(new Map<number, number | Uint8Array>([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x!, "base64url")], [-3, Buffer.from(jwk.y!, "base64url")]]));
      const authData = cat(sha(rpId), Uint8Array.of(flags), u32(0), new Uint8Array(16), Uint8Array.of(0, credId.length), credId, coseKey);
      const attestationObject = isoCBOR.encode(new Map<string, unknown>([["fmt", "none"], ["attStmt", new Map()], ["authData", authData]]) as never);
      return { id: b64u(credId), rawId: b64u(credId), type: "public-key" as const, clientExtensionResults: {}, authenticatorAttachment: "platform" as const,
        response: { clientDataJSON: b64u(client("webauthn.create", challenge, origin)), attestationObject: b64u(attestationObject), transports: ["internal" as const] } };
    },
    assert(challenge: string, o: { origin?: string; flags?: number; count?: number } = {}) {
      const c = client("webauthn.get", challenge, o.origin ?? `https://${rpId}`);
      const authData = cat(sha(rpId), Uint8Array.of(o.flags ?? 0x05), u32(o.count ?? ++counter));
      const signature = nodeSign("sha256", cat(authData, sha(c)), privateKey);
      return { id: b64u(credId), rawId: b64u(credId), type: "public-key" as const, clientExtensionResults: {},
        response: { clientDataJSON: b64u(c), authenticatorData: b64u(authData), signature: b64u(signature), userHandle: b64u(new TextEncoder().encode("acct_x")) } };
    },
  };
}
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
