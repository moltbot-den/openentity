import { buildPresentation, canonicalize, didKeyFromPublicKey, generateKeyPair, sha256Hex, signAttestation, signRequest } from "@openentity/sdk";
import { expect, test } from "vitest";
import { createApp } from "../src/app.ts";
import { HOST, SERVICE_DID, caller, entry, ownerId, p256Key, registerRoot, signIn, testDeps } from "./helpers.ts";

// A stand-in registry serving one Secure My Agent posture attestation, signed by a throwaway key published as
// did:web:securemyagent.ai in a fake did.json. Nothing here is a real key.
const sma = await generateKeyPair(), agent = await generateKeyPair();
const att = await signAttestation(sma, { issuer: "did:web:securemyagent.ai", keyId: "key-1", subject: agent.did, claimType: "custom:securemyagent:security_posture", claim: { score_band: "low_risk", checks_passed: [], scanner_version: "1", evidence_hash: "0".repeat(64) }, ttlSeconds: 86_400 });
const smaDoc = { id: "did:web:securemyagent.ai", verificationMethod: [{ id: "did:web:securemyagent.ai#key-1", type: "Multikey", controller: "did:web:securemyagent.ai", publicKeyMultibase: didKeyFromPublicKey(sma.publicKey).slice(8) }], assertionMethod: ["did:web:securemyagent.ai#key-1"], authentication: ["did:web:securemyagent.ai#key-1"] };
const fakeFetch = (async (input: RequestInfo | URL) => {
  const url = String(input);
  if (url === `https://openentity.org/v1/entities/${agent.did}`) return Response.json({ eid: agent.did, level: "L1", withdrawn: false });
  if (url === `https://openentity.org/v1/entities/${agent.did}/attestations`) return Response.json({ attestations: [{ sha256: await sha256Hex(canonicalize(att)), attestation: att, inherited_from: null, revocation: null, revoked_at: null }] });
  if (url === "https://securemyagent.ai/.well-known/did.json") return Response.json(smaDoc);
  return new Response(null, { status: 404 });
}) as typeof fetch;
const d = await testDeps({ fetch: fakeFetch, products: {} });
const call = caller(createApp(d));

test("the owner sees the agent's Secure My Agent verdict from the registry, verified locally", async () => {
  const me = await signIn(call, d);
  const root = p256Key({ type: "webauthn" }), approver = p256Key();
  await registerRoot(d.db, me.accountId, root);
  const genesis = entry(approver, { seq: 1, prev: null, op: "genesis", body: { root: root.credential, approver: approver.credential } });
  await call("POST", `/o/${ownerId(genesis)}/log`, { line: genesis }, me.auth);
  const p = (await call("POST", "/v1/pairings", undefined, me.auth)).body;
  const body = JSON.stringify({ code: p.code, presentation: await buildPresentation(agent, { audience: SERVICE_DID, nonce: `pair:${p.code}` }), framework: "x", sdk: "x", sdk_version: "1" });
  expect((await call("POST", "/v1/pair", body, await signRequest({ method: "POST", url: `https://${HOST}/v1/pair`, body: new TextEncoder().encode(body), privateKey: agent, did: agent.did }))).status).toBe(201);
  const detail = (await call("GET", `/v1/pairings/${p.id}`, undefined, me.auth)).body;
  expect(detail.agent.safety).toEqual({ verdict: "low_risk", checked_at: expect.any(Number) });
});
