import { generateKeyPairSync, sign } from "node:crypto";
import { didKeyFromPublicKey, payloadDigest, signRequest } from "@openentity/sdk";
import { expect, test } from "vitest";
import { ENVELOPE_TYP } from "../src/approve.ts";
import { HOST, ORIGIN, call, owner, webApp } from "./owner.ts";

// Secure My Agent's live did.json (2026-11-12) has two keys: a secp256k1 issuer key under assertionMethod only, and
// its Ed25519 `#service-key` (Multikey) under authentication and assertionMethod. Same shape here, with a throwaway
// Ed25519 key in place of the real one: both the envelope check and the push hub use the Ed25519 key, never the other.
const SMA = "did:web:securemyagent.ai", KID = `${SMA}#service-key`;
const k = generateKeyPairSync("ed25519");
const x = (k.publicKey.export({ format: "jwk" }) as { x: string }).x;
const smaDoc = {
  "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/secp256k1recovery-2020/v2", "https://w3id.org/security/multikey/v1"],
  id: SMA, alsoKnownAs: ["did:pkh:eip155:8453:0x62fef02E2859726EC1c0B534853Ad2cdd5FdDE1a"],
  verificationMethod: [
    { id: `${SMA}#issuer-key`, type: "EcdsaSecp256k1RecoveryMethod2020", controller: SMA, blockchainAccountId: "eip155:8453:0x62fef02E2859726EC1c0B534853Ad2cdd5FdDE1a" },
    { id: KID, type: "Multikey", controller: SMA, publicKeyMultibase: didKeyFromPublicKey(Buffer.from(x, "base64url")).slice("did:key:".length) },
  ],
  authentication: [KID], assertionMethod: [`${SMA}#issuer-key`, KID],
};
const pushes: string[] = [];
const { d, app } = await webApp({
  web: { apns: async (_t, m) => { pushes.push(m.id); return null; } },
  answer: (url) => (url === "https://securemyagent.ai/.well-known/did.json" ? Response.json(smaDoc) : undefined),
});
const now = () => Math.floor(Date.now() / 1000);

test("Secure My Agent's Ed25519 #service-key signs an ApproveEnvelope that /v1/approve/check accepts", async () => {
  const o = await owner(d, { rootOnly: true }), payload = { action: "agent.fix", agent: "did:key:z6Mkexample" };
  const seg = (v: object) => Buffer.from(JSON.stringify(v)).toString("base64url");
  const input = `${seg({ alg: "EdDSA", kid: KID, typ: ENVELOPE_TYP })}.${seg({ iss: SMA, aud: `did:web:${HOST}`, iat: now(), exp: now() + 600, request_id: "sma_1", owner_did: o.ownerDid, payload, payload_digest: payloadDigest(payload), return_url: "https://securemyagent.ai/approve/return" })}`;
  const r = await call(app, "POST", "/v1/approve/check", { request: `${input}.${sign(null, Buffer.from(input), k.privateKey).toString("base64url")}` });
  expect([r.status, r.body.verifier_did, r.body.allow_credentials.length]).toEqual([200, SMA, 1]);
  // The secp256k1 issuer key is no Ed25519 key: an envelope naming it is refused.
  const bad = `${seg({ alg: "EdDSA", kid: `${SMA}#issuer-key`, typ: ENVELOPE_TYP })}.${input.split(".")[1]}`;
  expect((await call(app, "POST", "/v1/approve/check", { request: `${bad}.${sign(null, Buffer.from(bad), k.privateKey).toString("base64url")}` })).body.error).toBe("envelope_invalid");
});

test("Secure My Agent's Ed25519 #service-key signs a /v1/notify call the push hub accepts", async () => {
  const o = await owner(d);
  await d.db.run("INSERT INTO push_tokens (install_id, account_id, provider, token, environment, created_at, updated_at) VALUES ($1, $2, 'apns', 'tok-sma', 'production', 1, 1)", [o.install, o.accountId]);
  const body = new TextEncoder().encode(JSON.stringify({ owner_did: o.ownerDid, type: "alert", id: "sma_alert_1" }));
  const seed = Buffer.from((k.privateKey.export({ format: "jwk" }) as { d: string }).d, "base64url");
  const h = await signRequest({ method: "POST", url: `${ORIGIN}/v1/notify`, body, privateKey: seed, did: KID });
  const r = await app.request(`${ORIGIN}/v1/notify`, { method: "POST", body, headers: { "content-type": "application/json", ...h } });
  expect(r.status).toBe(202);
  expect(pushes).toContain("sma_alert_1");
});
