import { createPrivateKey, createPublicKey, sign as nodeSign, verify as nodeVerify, type KeyObject } from "node:crypto";
import { decodeProtectedHeader, importJWK, jwtVerify, type JWK } from "jose";
import { expect, test } from "vitest";
import { derToJose, publicKey, signJwt } from "../src/keys.ts";

const hex = (s: string) => Uint8Array.from(Buffer.from(s.replace(/\s+/g, ""), "hex"));

// RFC 6979 appendix A.2.5: P-256, SHA-256, message "sample". A published test key, not a secret.
const D = "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721";
const UX = "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6";
const UY = "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299";
const R = "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716";
const S = "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8";
const jwkOf = (h: string) => Buffer.from(h, "hex").toString("base64url");
const privJwk = { kty: "EC", crv: "P-256", d: jwkOf(D), x: jwkOf(UX), y: jwkOf(UY) };
const priv: KeyObject = createPrivateKey({ key: privJwk, format: "jwk" });
const pub: KeyObject = createPublicKey({ key: { kty: "EC", crv: "P-256", x: privJwk.x, y: privJwk.y }, format: "jwk" });

test("RFC 6979 vector: both integers carry a 0x00 pad in DER and convert to the 64-byte r || s", () => {
  const der = hex(`3046 0221 00${R} 0221 00${S}`);
  const raw = derToJose(der);
  expect(Buffer.from(raw).toString("hex").toUpperCase()).toBe(R + S);
  expect(nodeVerify("sha256", Buffer.from("sample"), { key: pub, dsaEncoding: "ieee-p1363" }, raw)).toBe(true);
});

test("short integers are left-padded to 32 bytes", () => {
  // r = 1 (one byte), s = 0x7f followed by 30 bytes (31 bytes, no pad needed)
  const s31 = "7f" + "11".repeat(30);
  const der = hex(`3024 0201 01 021f ${s31}`);
  expect(Buffer.from(derToJose(der)).toString("hex")).toBe("00".repeat(31) + "01" + "00" + s31);
});

test("malformed DER is rejected: negative, non-minimal pad, trailing bytes, wrong tags, overlong", () => {
  const ok = `0221 00${R} 0221 00${S}`;
  for (const bad of [
    `3044 0220 ${R} 0220 ${S}`, // high bit without pad: a negative integer
    `3047 0222 0000${R} 0221 00${S}`, // two pad bytes
    `3046 0221 0011${R.slice(2)} 0221 00${S}`, // a pad before a low bit is not minimal
    `3048 ${ok} 0000`, // length covers trailing garbage
    `3146 ${ok}`, // not a SEQUENCE
    `3046 0321 00${R} 0221 00${S}`, // not an INTEGER
    `3046 0221 7F${"AA".repeat(32)} 0221 00${S}`, // r longer than the curve
    `3046 0221 00${R} 0221 00${S}`.slice(0, -2), // truncated
  ]) expect(() => derToJose(hex(bad)), bad).toThrow(/malformed/);
});

test("500 random signatures in DER all convert to signatures node verifies in raw form", () => {
  let padded = 0, short = 0;
  for (let i = 0; i < 500; i++) {
    const msg = Buffer.from(`message ${i}`);
    const der = new Uint8Array(nodeSign("sha256", msg, { key: priv, dsaEncoding: "der" }));
    if (der[3] === 33) padded++;
    if (der[3] < 32) short++;
    expect(nodeVerify("sha256", msg, { key: pub, dsaEncoding: "ieee-p1363" }, derToJose(der))).toBe(true);
  }
  expect(padded).toBeGreaterThan(100); // about half of all r values have the high bit set
  expect(short + padded).toBeGreaterThan(0);
});

test("a JWT signed through a KMS-shaped signer (DER out) verifies with jose as ES256", async () => {
  // Same contract as kmsEs256: the signer returns DER, signJwt's key converts it.
  const key = await publicKey({ kty: "EC", crv: "P-256", x: privJwk.x, y: privJwk.y } as JWK, async (data) =>
    derToJose(new Uint8Array(nodeSign("sha256", data, { key: priv, dsaEncoding: "der" }))));
  expect(key.kid).toMatch(/^[A-Za-z0-9_-]{43}$/);
  const token = await signJwt(key, { typ: "at+jwt" }, { iss: "https://account.openentity.org", aud: "did:web:moltbotden.com", sub: "did:web:account.openentity.org:o:x", exp: Math.floor(Date.now() / 1000) + 60 });
  expect(decodeProtectedHeader(token)).toEqual({ alg: "ES256", kid: key.kid, typ: "at+jwt" });
  const { payload } = await jwtVerify(token, await importJWK({ ...key.jwk, alg: "ES256" }), { algorithms: ["ES256"], audience: "did:web:moltbotden.com", typ: "at+jwt" });
  expect(payload.sub).toBe("did:web:account.openentity.org:o:x");
});
