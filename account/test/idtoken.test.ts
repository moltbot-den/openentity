import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT, type JWTPayload } from "jose";
import { expect, test } from "vitest";
import { nonceHash, verifyApple, verifyGoogle } from "../src/idtoken.ts";

// Throwaway keys generated per run stand in for Apple's and Google's published JWKS. Nothing here is a real key.
const provider = await generateKeyPair("RS256");
const impostor = await generateKeyPair("RS256"); // e.g. the staging test identity provider
const jwk = { ...(await exportJWK(provider.publicKey)), kid: "k1", alg: "RS256" };
const keys = createLocalJWKSet({ keys: [jwk] });

const NATIVE = "org.openentity.app", WEB = "org.openentity.app.web", NONCE = "n-0123456789abcdefghijklmnopqrstuvwxyzABCDEFG";
const now = () => Math.floor(Date.now() / 1000);
const sign = (claims: JWTPayload, key = provider.privateKey) =>
  new SignJWT({ iat: now(), exp: now() + 600, ...claims }).setProtectedHeader({ alg: "RS256", kid: "k1" }).sign(key);
const apple = (over: JWTPayload = {}) => sign({ iss: "https://appleid.apple.com", aud: NATIVE, sub: "001234.abcd", nonce: nonceHash(NONCE), email: "Ada@Example.com", email_verified: "true", is_private_email: "false", ...over });
const google = (over: JWTPayload = {}) => sign({ iss: "https://accounts.google.com", aud: WEB, azp: "android-client", sub: "1170000", nonce: nonceHash(NONCE), email: "ada@example.com", email_verified: true, ...over });

const code = async (p: Promise<unknown>) => p.then(() => "ok", (e) => e.code);

test("Apple native: iss, aud = bundle ID and the hashed nonce pass; the verified email comes back lowercased", async () => {
  const id = await verifyApple(await apple(), { audience: [NATIVE], nonce: NONCE, keys });
  expect(id).toEqual({ provider: "apple", sub: "001234.abcd", email: "ada@example.com", emailPrivate: false, aud: NATIVE });
});

test("Apple web and Android: aud = the Services ID passes only where the Services ID is the expected audience", async () => {
  const t = await apple({ aud: WEB });
  expect((await verifyApple(t, { audience: [WEB], nonce: NONCE, keys })).aud).toBe(WEB);
  expect(await code(verifyApple(t, { audience: [NATIVE], nonce: NONCE, keys }))).toBe("id_token_invalid");
});

test("Apple: a private relay address is flagged, and an unverified email is dropped", async () => {
  expect((await verifyApple(await apple({ email: "x@privaterelay.appleid.com", is_private_email: true }), { audience: [NATIVE], nonce: NONCE, keys })).emailPrivate).toBe(true);
  expect((await verifyApple(await apple({ email_verified: false }), { audience: [NATIVE], nonce: NONCE, keys })).email).toBeNull();
});

test("wrong issuer, wrong audience, several audiences, expiry and a foreign signing key are all id_token_invalid", async () => {
  const o = { audience: [NATIVE], nonce: NONCE, keys };
  expect(await code(verifyApple(await apple({ iss: "https://accounts.google.com" }), o))).toBe("id_token_invalid");
  expect(await code(verifyApple(await apple({ aud: "com.example.other" }), o))).toBe("id_token_invalid");
  expect(await code(verifyApple(await apple({ aud: [NATIVE, "com.example.other"] }), o))).toBe("id_token_invalid");
  expect(await code(verifyApple(await apple({ exp: now() - 120 }), o))).toBe("id_token_invalid");
  // An Apple-shaped token signed by any key Apple did not publish (the staging test identity provider included).
  expect(await code(verifyApple(await sign({ iss: "https://appleid.apple.com", aud: NATIVE, sub: "x", nonce: nonceHash(NONCE) }, impostor.privateKey), o))).toBe("id_token_invalid");
});

test("the nonce must be the SHA-256 of the raw nonce: the raw value, another nonce, or none fail", async () => {
  const o = { audience: [NATIVE], nonce: NONCE, keys };
  expect(await code(verifyApple(await apple({ nonce: NONCE }), o))).toBe("nonce_invalid");
  expect(await code(verifyApple(await apple({ nonce: nonceHash("another") }), o))).toBe("nonce_invalid");
  expect(await code(verifyApple(await apple({ nonce: undefined }), o))).toBe("nonce_invalid");
});

test("Google: both issuer spellings, iOS and web audiences; email only when email_verified is true", async () => {
  const o = { audience: ["ios-client", WEB], nonce: NONCE, keys };
  expect((await verifyGoogle(await google(), o)).email).toBe("ada@example.com");
  expect((await verifyGoogle(await google({ iss: "accounts.google.com", aud: "ios-client" }), o)).aud).toBe("ios-client");
  expect((await verifyGoogle(await google({ email_verified: false }), o)).email).toBeNull();
  expect(await code(verifyGoogle(await google({ iss: "https://appleid.apple.com" }), o))).toBe("id_token_invalid");
  expect(await code(verifyGoogle(await google({ aud: "android-client" }), o))).toBe("id_token_invalid");
  expect(await code(verifyGoogle(await google({ nonce: "x" }), o))).toBe("nonce_invalid");
});

test("an unconfigured provider answers unavailable instead of accepting any audience", async () => {
  expect(await code(verifyGoogle(await google(), { audience: [], nonce: NONCE, keys }))).toBe("unavailable");
});
