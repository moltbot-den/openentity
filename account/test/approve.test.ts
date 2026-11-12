import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { Script } from "node:vm";
import { didKeyFromPublicKey, payloadDigest, verifyApproval, type Credential } from "@openentity/sdk";
import { calculateJwkThumbprint } from "jose";
import { expect, test } from "vitest";
import { approvePage, assertionKeys, checkEnvelope, ENVELOPE_TYP, PRODUCT_SITES } from "../src/approve.ts";
import { PRODUCT_DIDS } from "../src/app.ts";
import { HttpError } from "../src/http.ts";

// Throwaway keys per run, none real: an Ed25519 product key, a P-256 passkey standing in for a browser authenticator.
const HOST = "staging.account.openentity.org", SERVICE = `did:web:${HOST}`;
const PRODUCT = "did:web:api.agentsecretstore.com", KID = `${PRODUCT}#key-1`;
const OWNER = `${SERVICE}:o:${"a".repeat(52)}`;
const product = generateKeyPairSync("ed25519");
const multibase = didKeyFromPublicKey(Buffer.from((product.publicKey.export({ format: "jwk" }) as any).x, "base64url")).slice("did:key:".length);
const productDoc = (rel = "assertionMethod") => ({
  id: PRODUCT, verificationMethod: [{ id: KID, type: "Multikey", controller: PRODUCT, publicKeyMultibase: multibase }], [rel]: [KID],
});
const passkey = generateKeyPairSync("ec", { namedCurve: "P-256" });
const pjwk = passkey.publicKey.export({ format: "jwk" }) as any;
const approver: Credential = {
  kid: await calculateJwkThumbprint({ kty: "EC", crv: "P-256", x: pjwk.x, y: pjwk.y }, "sha256"),
  type: "webauthn", jwk: { kty: "EC", crv: "P-256", x: pjwk.x, y: pjwk.y }, credential_id: "Y3JlZC0x", rp_id: HOST,
};
const device: Credential = { ...approver, kid: "device-kid", type: "p256", credential_id: undefined, rp_id: undefined };
const now = Math.floor(Date.now() / 1000);
const payload = { action: "vault.read", path: "prod/stripe/key", agent: "did:key:z6Mkexample" };

function envelope(claims: Record<string, unknown> = {}, header: Record<string, unknown> = {}, key = product.privateKey) {
  const h = Buffer.from(JSON.stringify({ alg: "EdDSA", kid: KID, typ: ENVELOPE_TYP, ...header })).toString("base64url");
  const c = Buffer.from(JSON.stringify({
    iss: PRODUCT, aud: SERVICE, iat: now, exp: now + 600, request_id: "req_123", owner_did: OWNER, payload,
    payload_digest: payloadDigest(payload), return_url: "https://agentsecretstore.com/dashboard/approve/return", state: "s1", ...claims,
  })).toString("base64url");
  return `${h}.${c}.${sign(null, Buffer.from(`${h}.${c}`), key).toString("base64url")}`;
}
const doc: object = productDoc();
const ctx = (o: Partial<Parameters<typeof checkEnvelope>[1]> = {}) => ({
  serviceDid: SERVICE, rpId: HOST, now, fetchJson: async () => doc,
  keyLog: async (did: string) => (did === OWNER ? { approvers: [approver, device], closed: false } : null), ...o,
});
async function rejects(p: Promise<unknown>, status: number, code: string) {
  const e = await p.then(() => null, (x) => x);
  expect(e, code).toBeInstanceOf(HttpError);
  expect([e.status, e.code]).toEqual([status, code]);
}

test("the four product signers are the service's product DIDs", () => {
  expect(Object.keys(PRODUCT_SITES).sort()).toEqual([...PRODUCT_DIDS].sort());
});

test("a valid envelope returns the request, the passkey approvers with their kids, and both approval/2.0 challenges", async () => {
  const v = await checkEnvelope(envelope(), ctx());
  expect(v).toMatchObject({
    verifier_did: PRODUCT, owner_did: OWNER, request_id: "req_123", payload, payload_digest: payloadDigest(payload), expires_at: now + 600,
    return_url: "https://agentsecretstore.com/dashboard/approve/return", state: "s1", rp_id: HOST,
    allow_credentials: ["Y3JlZC0x"], kids: { Y3JlZC0x: approver.kid },
  });
  expect(v.challenges.approve).not.toBe(v.challenges.deny);
});

test("what the page builds from the check verifies at the product with verifyApproval (software authenticator)", async () => {
  const v = await checkEnvelope(envelope(), ctx());
  for (const decision of ["approve", "deny"] as const) {
    // The browser: clientDataJSON with the challenge and this origin; authenticatorData with UP and UV and a counter.
    const clientData = Buffer.from(JSON.stringify({ type: "webauthn.get", challenge: v.challenges[decision], origin: `https://${HOST}`, crossOrigin: false }));
    const authData = Buffer.concat([createHash("sha256").update(HOST).digest(), Buffer.from([0x05, 0, 0, 0, 7])]);
    const signature = sign("sha256", Buffer.concat([authData, createHash("sha256").update(clientData).digest()]), passkey.privateKey);
    const approval = {
      version: "approval/2.0", verifier_did: v.verifier_did, owner_did: v.owner_did, request_id: v.request_id, payload_digest: v.payload_digest,
      decision, expires_at: v.expires_at, device_id: v.kids[v.allow_credentials[0]], form: "webauthn",
      signature: signature.toString("base64url"), authenticator_data: authData.toString("base64url"), client_data_json: clientData.toString("base64url"),
    };
    // The product's own check: its DID, the request it issued, the digest of the payload it built.
    const r = verifyApproval(approval, {
      keyLog: { did: OWNER, root: approver, approvers: [approver], closed: false }, verifierDid: PRODUCT, ownerDid: OWNER,
      requestId: "req_123", payloadDigest: payloadDigest(payload), now, rpId: HOST, origins: [`https://${HOST}`],
    });
    expect(r, decision).toMatchObject({ ok: true, kid: approver.kid, counter: 7 });
  }
});

test("guard: only the four product DIDs may ask, and only with an Ed25519 assertionMethod key", async () => {
  await rejects(checkEnvelope(envelope({ iss: "did:web:evil.example" }, { kid: "did:web:evil.example#key-1" }), ctx()), 403, "unknown_verifier");
  // A key listed for request signatures only (another product DID, so the cached document of the first one is not reused).
  const den = "did:web:moltbotden.com";
  const authOnly = { id: den, verificationMethod: [{ id: `${den}#key-1`, type: "Multikey", controller: den, publicKeyMultibase: multibase }], authentication: [`${den}#key-1`] };
  await rejects(checkEnvelope(envelope({ iss: den, return_url: "https://moltbotden.com/x" }, { kid: `${den}#key-1` }), ctx({ fetchJson: async () => authOnly })), 400, "envelope_invalid");
  await rejects(checkEnvelope(envelope({}, {}, generateKeyPairSync("ed25519").privateKey), ctx()), 400, "envelope_invalid"); // another key
});

test("guard: header, claims and payload digest are checked", async () => {
  const bad: [Record<string, unknown>, Record<string, unknown>][] = [
    [{}, { typ: "JWT" }], [{}, { alg: "ES256" }], [{}, { crit: ["b64"] }],
    [{ iss: "did:web:moltbotden.com" }, {}], [{ aud: "did:web:account.openentity.org" }, {}],
    [{ exp: now + 601 }, {}], [{ iat: now + 60, exp: now + 120 }, {}], [{ request_id: "a b" }, {}],
    [{ owner_did: `did:web:account.openentity.org:o:${"a".repeat(52)}` }, {}], [{ payload: [1] }, {}],
    [{ payload_digest: "0".repeat(64) }, {}], [{ payload: { amount: 1.5 }, payload_digest: "0".repeat(64) }, {}], [{ state: "x".repeat(257) }, {}],
  ];
  for (const [claims, header] of bad) await rejects(checkEnvelope(envelope(claims, header), ctx()), 400, "envelope_invalid");
  await rejects(checkEnvelope("a.b", ctx()), 400, "envelope_invalid");
  const [h, c, s] = envelope().split(".");
  const tampered = Buffer.from(JSON.stringify({ ...JSON.parse(Buffer.from(c, "base64url").toString()), request_id: "req_other" })).toString("base64url");
  await rejects(checkEnvelope(`${h}.${tampered}.${s}`, ctx()), 400, "envelope_invalid");
});

test("guard: an expired envelope is 410; return_url must be https on the verifier's own site", async () => {
  await rejects(checkEnvelope(envelope({ iat: now - 700, exp: now - 100 }), ctx()), 410, "envelope_expired");
  for (const url of ["https://evil.example/x", "http://agentsecretstore.com/x", "https://agentsecretstore.com.evil.example/x", "https://user@agentsecretstore.com/x",
    "https://agentsecretstore.com:8443/x", "https://clawgrc.com/x", "javascript:alert(1)"]) {
    await rejects(checkEnvelope(envelope({ return_url: url }), ctx()), 400, "envelope_invalid");
  }
  const sub = await checkEnvelope(envelope({ return_url: "https://app.agentsecretstore.com/approve/done?x=1" }), ctx());
  expect(sub.return_url).toBe("https://app.agentsecretstore.com/approve/done?x=1");
});

test("guard: an unknown or deleted owner is 404 owner_unknown", async () => {
  const other = `${SERVICE}:o:${"b".repeat(52)}`;
  await rejects(checkEnvelope(envelope({ owner_did: other }), ctx()), 404, "owner_unknown");
  await rejects(checkEnvelope(envelope(), ctx({ keyLog: async () => ({ approvers: [approver], closed: true }) })), 404, "owner_unknown");
});

test("assertionKeys reads Multikey and Ed25519 JsonWebKey methods, relative ids and embedded methods, nothing else", () => {
  const x = (product.publicKey.export({ format: "jwk" }) as any).x;
  const keys = assertionKeys(PRODUCT, {
    id: PRODUCT,
    verificationMethod: [
      { id: "#a", type: "Multikey", publicKeyMultibase: multibase },
      { id: `${PRODUCT}#b`, type: "JsonWebKey", publicKeyJwk: { kty: "OKP", crv: "Ed25519", x } },
      { id: `${PRODUCT}#c`, type: "JsonWebKey", publicKeyJwk: { kty: "EC", crv: "P-256", x: pjwk.x, y: pjwk.y } },
      { id: `${PRODUCT}#d`, type: "Multikey", publicKeyMultibase: multibase },
    ],
    assertionMethod: ["#a", `${PRODUCT}#b`, `${PRODUCT}#c`, { id: "#e", type: "JsonWebKey", publicKeyJwk: { kty: "OKP", crv: "Ed25519", x } }],
  });
  expect([...keys.keys()].sort()).toEqual([`${PRODUCT}#a`, `${PRODUCT}#b`, `${PRODUCT}#e`]);
  expect(() => assertionKeys(PRODUCT, { id: "did:web:other" })).toThrow();
});

test("the /approve page: script and style allowed only by hash, forms only to the four product sites, client code self-contained", async () => {
  const res = approvePage();
  const csp = res.headers.get("content-security-policy")!;
  const html = await res.text();
  const script = /<script>([\s\S]*)<\/script><\/body>/.exec(html)![1];
  expect(csp).toContain(`script-src 'sha256-${createHash("sha256").update(script).digest("base64")}'`);
  expect(csp).toMatch(/default-src 'none'.*frame-ancestors 'none'/);
  expect(csp).toContain("form-action 'self' https://moltbotden.com https://*.moltbotden.com https://securemyagent.ai");
  expect(csp).not.toMatch(/unsafe-inline|unsafe-eval/);
  expect(res.headers.get("cache-control")).toBe("no-store");
  expect(() => new Script(script)).not.toThrow(); // parses as plain JavaScript (types stripped)
  expect(script).not.toMatch(/__name|__async|require\(/); // no bundler helpers from outside the function
});
