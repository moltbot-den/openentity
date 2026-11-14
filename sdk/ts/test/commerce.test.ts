import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import * as oe from "../src/index.ts";
import { buildCommerceVectors } from "../scripts/gen-commerce-vectors.ts";
import { serialize } from "../scripts/gen-vectors.ts";

const dir = new URL("../../../test-vectors/", import.meta.url);
const json = (p: string) => JSON.parse(readFileSync(new URL(p, dir), "utf8"));
const A = json("approval-2.0/vectors.json");
const keyState = (n: string) => A.key_states[n];
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

describe("commerce vectors", () => {
  it("committed files equal a fresh deterministic generation", async () => {
    const fresh = await buildCommerceVectors();
    for (const sub of ["mandate-1", "cart-1", "receipt-1", "checkout-1"])
      expect(readdirSync(new URL(`${sub}/`, dir)).filter((f) => f.endsWith(".json")).map((f) => `${sub}/${f}`)).toEqual(Object.keys(fresh).filter((k) => k.startsWith(sub)));
    for (const [path, v] of Object.entries(fresh)) expect(readFileSync(new URL(path, dir), "utf8"), path).toBe(serialize(v));
  });
});

describe("mandate/1", () => {
  const V = json("mandate-1/vectors.json");
  for (const c of V.cases)
    it(c.name, () => {
      const x = c.context;
      const r = oe.verifyMandate(c.mandate, { keyLog: keyState(x.key_state), agentDid: x.agent_did, now: x.now, status: x.status });
      const got = r.ok ? { ok: true, mandate_id: r.mandate_id, limits: r.limits, scope: r.scope, step_up_over: r.step_up_over, ...(r.ok && "kid" in c.expect ? { kid: r.kid } : {}), ...(x.status?.period_spent !== undefined ? { period_spent: r.period_spent, total_spent: r.total_spent } : {}) } : { ok: false, error: r.error };
      expect(got, r.ok ? "" : r.message).toEqual(c.expect);
    });
  it("digest preimages", () => {
    for (const d of V.digests) {
      const m = [...Object.values(json("cart-1/vectors.json").mandates)].find((x) => (x as { mandate_id: string }).mandate_id === d.mandate_id) ?? V.cases.find((c: { mandate: { mandate_id: string } }) => c.mandate.mandate_id === d.mandate_id).mandate;
      expect(hex(oe.mandateDigest(m))).toBe(d.digest);
    }
  });
  it("a mandate signature does not verify as an approval", () => {
    const r = V.replay.mandate_signature_as_approval, c = r.context;
    expect(oe.verifyApproval(r.approval, { keyLog: keyState(c.key_state), verifierDid: c.verifier_did, ownerDid: c.owner_did, requestId: c.request_id, payloadDigest: c.payload_digest, now: c.now })).toMatchObject(r.expect);
  });
});

describe("cart/1", () => {
  const V = json("cart-1/vectors.json");
  it("digests are SHA-256 of the RFC 8785 form", () => {
    for (const c of V.carts) {
      expect(oe.canonicalize(c.cart)).toBe(c.canonical);
      expect(oe.cartDigest(c.cart)).toBe(c.digest);
    }
    for (const c of V.invalid) expect(() => oe.cartDigest(c.cart), c.reason).toThrow(oe.OpenEntityError);
  });
  for (const c of V.covers)
    it(`covers: ${c.name}`, () => {
      const r = oe.mandateCovers(V.mandates[c.mandate], c.cart, { spent: c.spent });
      expect({ ok: r.ok, step_up_required: r.step_up_required, ...(r.reason ? { reason: r.reason } : {}) }).toEqual(c.expect);
    });
});

describe("receipt/1", () => {
  const V = json("receipt-1/vectors.json");
  for (const c of V.cases)
    it(c.name, async () => {
      const r = await oe.verifyReceipt(c.receipt, { require: c.require });
      expect(r.ok ? { ok: true, signed_by: r.signed_by } : { ok: false, error: r.error }, r.ok ? "" : r.message).toEqual(c.expect);
    });
  it("signReceipt refuses a signer that is not the named party and a second proof by the same party", async () => {
    const k = await oe.keyPairFromSeed(Uint8Array.from({ length: 32 }, (_, i) => i + 77));
    const base = V.cases[0].receipt;
    const { proofs: _p, ...bare } = base;
    await expect(oe.signReceipt(bare, k, "merchant")).rejects.toThrow(oe.OpenEntityError); // k is the agent
    const agent = await oe.keyPairFromSeed(Uint8Array.from({ length: 32 }, (_, i) => i + 1)); // the vectors' agent
    await expect(oe.signReceipt(base, agent, "agent")).rejects.toThrow(/already signed/);
  });
});

describe("verifyAgentForCheckout", () => {
  const V = json("checkout-1/vectors.json");
  for (const c of V.cases)
    it(c.name, async () => {
      const i = c.input;
      const r = await oe.verifyAgentForCheckout({
        agentDid: i.agent_did, cart: i.cart, merchantPolicy: i.merchant_policy, agent: i.agent, mandate: i.mandate, keyLog: keyState(i.key_state), status: i.status, now: i.now,
        approval: i.approval && { approval: i.approval.approval, verifierDid: i.approval.verifier_did, requestId: i.approval.request_id },
      });
      expect({ decision: r.decision, reasons: r.reasons, ...(r.evidence.approval_error ? { approval_error: r.evidence.approval_error } : {}) }).toEqual(c.expect);
    });
  it("verifies the agent's own signed request", async () => {
    const seed = Uint8Array.from({ length: 32 }, (_, i) => i + 77);
    const k = await oe.keyPairFromSeed(seed);
    const c = V.cases[0].input, cart = { ...c.cart, agent_did: k.did, mandate_id: null };
    const url = "https://shop.example/checkout", now = 1_800_000_000;
    const headers = await oe.signRequest({ method: "POST", url, privateKey: k, did: k.did, created: now });
    const base = { cart, merchantPolicy: {}, now };
    const ok = await oe.verifyAgentForCheckout({ ...base, request: { method: "POST", url, headers } });
    expect(ok).toMatchObject({ decision: "step_up", reasons: ["no_mandate"], evidence: { request: "verified", agent_did: k.did } });
    expect((await oe.verifyAgentForCheckout({ ...base, request: { method: "POST", url: "https://evil.example/", headers } })).reasons).toEqual(["request_unverified"]);
    expect((await oe.verifyAgentForCheckout({ ...base, cart: { ...cart, agent_did: c.agent_did }, request: { method: "POST", url, headers } })).reasons).toEqual(["agent_mismatch"]);
  });
});
