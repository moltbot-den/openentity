import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519.js";
import * as oe from "../src/index.ts";

const VEC = JSON.parse(readFileSync(new URL("../../../test-vectors/http-signature.json", import.meta.url), "utf8"));
const SEED = Uint8Array.from({ length: 32 }, (_, i) => i + 1); // published throwaway seed, test-vectors/keys.json
const enc = new TextEncoder();
const URL_ = "https://gw.example.com/v1/x", NOW = 1_800_000_000, BODY = enc.encode('{"a":1}'), NONCE = "AAECAwQFBgcICQoLDA0ODw";
const kp = await oe.keyPairFromSeed(SEED);
const req = (o = {}) => oe.signRequest({ method: "POST", url: URL_, body: BODY, privateKey: SEED, did: kp.did, created: NOW, nonce: NONCE, ...o });
const check = async (headers: Record<string, string>, code: string, o: Record<string, unknown> = {}) => {
  const e = await oe.verifyRequest({ method: "POST", url: URL_, headers, body: BODY, now: NOW, ...o }).catch((x) => x);
  expect(e).toBeInstanceOf(oe.HttpSigError);
  expect(e.code).toBe(code);
};
/** A correctly signed request with arbitrary Signature-Input parameters. */
const forge = (params: string, comps = ["@method", "@target-uri", "content-digest"], key = SEED) => {
  const h: Record<string, string> = { "Content-Digest": `sha-256=:${createHash("sha256").update(BODY).digest("base64")}:` };
  const sig = ed25519.sign(oe.httpSigBase("POST", URL_, comps, h["Content-Digest"], params), key);
  return { ...h, "Signature-Input": `sig1=${params}`, Signature: `sig1=:${Buffer.from(sig).toString("base64")}:` };
};
const params = (o: { created?: number; expires?: number; nonce?: string | null; keyid?: string; alg?: string; comps?: string } = {}) => {
  const { created = NOW, expires = NOW + 60, nonce = NONCE, keyid = kp.did, alg = "ed25519", comps = '"@method" "@target-uri" "content-digest"' } = o;
  return `(${comps});created=${created};expires=${expires}${nonce ? `;nonce="${nonce}"` : ""};keyid="${keyid}";alg="${alg}"`;
};

describe("http message signatures", () => {
  it.each(VEC.valid as { name: string }[])("vector $name signs byte-identically and verifies", async (c: any) => {
    const h = await oe.signRequest({ method: c.method, url: c.url, body: enc.encode(c.body), privateKey: SEED, did: VEC.did, created: c.created, expiresIn: c.expires_in, nonce: c.nonce });
    expect(h).toEqual(c.headers);
    expect(await oe.verifyRequest({ method: c.method, url: c.url, headers: c.headers, body: enc.encode(c.body), now: VEC.now })).toEqual({
      did: VEC.did, keyid: VEC.did, created: c.created, expires: c.created + 60, nonce: c.nonce,
    });
  });
  it.each(VEC.invalid as { name: string; code: string }[])("vector $name rejects with $code", async (c: any) => {
    await check(c.headers, c.code, { method: c.method, url: c.url, body: enc.encode(c.body), now: c.now ?? VEC.now });
  });
  it("round trips, accepts a KeyPair, omits the digest for an empty body, ignores header case", async () => {
    expect((await oe.verifyRequest({ method: "post", url: URL_, headers: await req(), body: BODY, now: NOW })).did).toBe(kp.did);
    expect(await req({ privateKey: kp })).toEqual(await req());
    const h = await oe.signRequest({ method: "GET", url: URL_, privateKey: SEED, did: kp.did });
    expect(h["Content-Digest"]).toBeUndefined();
    expect(h["Signature-Input"]).not.toContain("content-digest");
    expect((await oe.verifyRequest({ method: "GET", url: URL_, headers: h })).did).toBe(kp.did);
    const lower = Object.fromEntries(Object.entries(await req()).map(([k, v]) => [k.toLowerCase(), v]));
    expect(await oe.verifyRequest({ method: "POST", url: URL_, headers: lower, body: BODY, now: NOW })).toBeTruthy();
  });
  it("missing_headers", async () => {
    await check({}, "missing_headers");
    const { Signature: _s, ...noSig } = await req();
    await check(noSig, "missing_headers");
    await check({ ...(await req()), Signature: "garbage" }, "missing_headers");
  });
  it("unknown_alg", () => check(forge(params({ alg: "rsa-pss-sha512" })), "unknown_alg"));
  it("bad_keyid", async () => {
    await check(forge(params({ keyid: "did:web:example.com" })), "bad_keyid");
    await check(forge(params({ keyid: "did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme" })), "bad_keyid"); // secp256k1
  });
  it("digest_mismatch", async () => {
    await check(await req(), "digest_mismatch", { body: enc.encode("other") });
    const { "Content-Digest": _d, ...noDigest } = await req();
    await check(noDigest, "digest_mismatch");
    await check(forge(params({ comps: '"@method" "@target-uri"' }), ["@method", "@target-uri"]), "digest_mismatch");
  });
  it("created_in_future allows 5 s of skew", async () => {
    await check(await req(), "created_in_future", { now: NOW - 6 });
    expect(await oe.verifyRequest({ method: "POST", url: URL_, headers: await req(), body: BODY, now: NOW - 5 })).toBeTruthy();
  });
  it("created_too_old", async () => {
    await check(forge(params({ created: NOW - 400, expires: NOW + 10 })), "created_too_old");
    await check(await req(), "created_too_old", { now: NOW + 301, maxAge: 300 });
  });
  it("expired", async () => check(await req(), "expired", { now: NOW + 61 }));
  it("lifetime_too_long", async () => {
    await check(forge(params({ expires: NOW + 301 })), "lifetime_too_long");
    await check(await req({ expiresIn: 200 }), "lifetime_too_long", { maxAge: 100 });
  });
  it("missing_nonce", async () => {
    await check(forge(params({ nonce: null })), "missing_nonce");
    await check(forge(params({ nonce: "short" })), "missing_nonce");
  });
  it("bad_signature", async () => {
    await check(await req(), "bad_signature", { url: URL_ + "?y=1" });
    await check(await req(), "bad_signature", { method: "GET" });
    await check(forge(params(), undefined, new Uint8Array(32).fill(7)), "bad_signature");
  });
});
