import { describe, expect, it } from "vitest";
import { buildPresentation, generateKeyPair, keyPairFromJwk, nowSeconds, randomNonce, signObject, signProof, type KeyPair } from "../src/sdk.ts";
import { E, adopted, call, signed, write } from "./helpers.ts";

const AUDIENCE = "https://openentity.org";
const nonce = () => randomNonce() + randomNonce();

async function custodial(): Promise<KeyPair> {
  const r = await write("POST", "/adopt", "did:web:openentity.org", { custodial: true, name: "Kept", keep_copy: true });
  expect(r.status).toBe(201);
  return keyPairFromJwk(r.body.custodial.private_key_jwk);
}
const exportKey = (kp: KeyPair, body: unknown) => write("POST", `/entities/${kp.did}/custody/export`, kp.did, body);
const kept = async (eid: string) => !!(await E.db.first("SELECT 1 FROM custodial_keys WHERE eid = $1", [eid]));

describe("custodial key export (spec 10.6)", () => {
  it("returns the kept key once, after a Presentation to the registry, and deletes the copy", async () => {
    const kp = await custodial();
    const r = await exportKey(kp, await buildPresentation(kp, { audience: AUDIENCE, nonce: nonce() }));
    expect(r.status).toBe(200);
    expect((await keyPairFromJwk(r.body.private_key_jwk)).did).toBe(kp.did);
    expect(await kept(kp.did)).toBe(false);
    const again = await exportKey(kp, await buildPresentation(kp, { audience: AUDIENCE, nonce: nonce() }));
    expect([again.status, again.body.error]).toEqual([404, "no_custodial_copy"]);
  });

  it("refuses a Presentation by another key, for another audience, stale, or replayed", async () => {
    const kp = await custodial(), other = await generateKeyPair();
    const forged = await signObject({ spec: "openentity/1.0", type: "Presentation", eid: kp.did, audience: AUDIENCE, nonce: nonce(), created: nowSeconds() }, other);
    expect((await exportKey(kp, forged)).body.error).toBe("presentation_invalid");
    expect((await exportKey(kp, await buildPresentation(kp, { audience: "https://elsewhere.example", nonce: nonce() }))).body.error).toBe("presentation_invalid");
    const old = new Date(Date.now() - 10 * 60_000).toISOString().replace(/\.\d+Z$/, "Z");
    const stale = await signObject({ spec: "openentity/1.0", type: "Presentation", eid: kp.did, audience: AUDIENCE, nonce: nonce(), created: old }, kp, old);
    expect((await exportKey(kp, stale)).body.error).toBe("presentation_invalid");
    const other2 = await adopted();
    const p = await buildPresentation(other2.kp, { audience: AUDIENCE, nonce: nonce() });
    expect((await exportKey(other2.kp, p)).body.error).toBe("no_custodial_copy");
    expect((await exportKey(other2.kp, p)).body.error).toBe("nonce_reused");
    expect(await kept(kp.did)).toBe(true);
  });

  it("a rotation away from a custodial key drops the registry's copy of the old key", async () => {
    const kp = await custodial(), succ = await generateKeyPair();
    const { document } = await signed(succ, "Kept");
    const unsigned = { spec: "openentity/1.0", type: "ContinuityLink", previous: kp.did, successor: succ.did, basis: "rotation", created: nowSeconds(), nonce: randomNonce() };
    const link = { ...unsigned, proofs: [await signProof(unsigned, kp), await signProof(unsigned, succ)] };
    expect((await write("POST", "/continuity", succ.did, { link, document })).status).toBe(201);
    expect(await kept(kp.did)).toBe(false);
    expect((await call("GET", `/entities/${succ.did}`)).body.lineage.previous).toBe(kp.did);
  });
});
