import { describe, it, expect } from "vitest";
import * as oe from "../src/index.ts";

const kp = await oe.keyPairFromSeed(Uint8Array.from({ length: 32 }, (_, i) => i + 1)); // published throwaway seed
const subject = (await oe.keyPairFromSeed(Uint8Array.from({ length: 32 }, (_, i) => i + 33))).did;
const DID = "did:web:issuer.example";
const now = new Date("2026-10-27T12:00:00Z");
const doc = oe.buildDidDocument(DID, kp.publicKey);
const resolver: oe.Resolver = async (did) => {
  expect(did).toBe(DID);
  return { ed25519: [oe.publicKeyFromDidKey("did:key:" + doc.verificationMethod[0].publicKeyMultibase)] };
};

describe("issuer helpers", () => {
  it("a did:web attestation verifies against the published did.json and fits the schema", async () => {
    const a = await oe.signAttestation(kp, { issuer: DID, subject, claimType: "trust_tier", claim: { tier: 2, platform: "x" }, ttlSeconds: 30 * 86400, now });
    expect([a.issuer, a.created, a.expires]).toEqual([DID, "2026-10-27T12:00:00Z", "2026-11-26T12:00:00Z"]);
    expect(a.proof.verificationMethod).toBe(`${DID}#key-1`);
    expect(oe.validate("Attestation", a)).toEqual({ ok: true, errors: [] });
    expect((await oe.verifyObject(a, resolver)).ok).toBe(true);
    expect((await oe.verifyObject({ ...a, claim: { tier: 4, platform: "x" } } as typeof a, resolver)).ok).toBe(false);
  });
  it("a did:key issuer needs no key id, and ttl is capped at one year", async () => {
    const a = await oe.signAttestation(kp, { subject, claimType: "stage", claim: { stage: "agent", profile: "p" }, now });
    expect(a.issuer).toBe(kp.did);
    expect((await oe.verifyObject(a)).ok).toBe(true);
    for (const ttlSeconds of [0, 366 * 86400]) await expect(oe.signAttestation(kp, { subject, claimType: "x", claim: {}, ttlSeconds })).rejects.toThrow();
  });
  it("a revocation names the attestation hash", async () => {
    const a = await oe.signAttestation(kp, { issuer: DID, subject, claimType: "custom:x:y", claim: {}, now });
    const r = await oe.signRevocation(kp, a, { issuer: DID, reason: "superseded", now });
    expect(r.attestation_sha256).toBe(await oe.sha256Hex(oe.canonicalize(a)));
    expect((await oe.signRevocation(kp, r.attestation_sha256, { issuer: DID, now })).attestation_sha256).toBe(r.attestation_sha256);
    expect(oe.validate("Revocation", r).ok).toBe(true);
    expect((await oe.verifyObject(r, resolver)).ok).toBe(true);
  });
  it("did.json and openentity.json agree on the key", () => {
    const o = oe.buildOpenEntityJson(DID, kp.publicKey, { name: "Issuer", description: "An issuer.", extensions: { "openentity:observer": {} } });
    expect(doc.id).toBe(o.eid);
    expect(doc.verificationMethod[0].publicKeyMultibase).toBe(o.keys[0].publicKeyMultibase);
    expect(doc.assertionMethod).toEqual([o.keys[0].id]);
  });
});
