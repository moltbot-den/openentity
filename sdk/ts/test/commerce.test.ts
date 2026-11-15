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
    for (const sub of ["mandate-1", "cart-1", "receipt-1", "checkout-1", "quorum-1"])
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

describe("receipt/1 with a did:pkh party (EIP-712)", () => {
  const V = json("receipt-1/pkh.json"), S = V.signing;
  for (const c of V.cases)
    it(c.name, async () => {
      const r = await oe.verifyReceipt(c.receipt, { require: c.require });
      expect(r.ok ? { ok: true, signed_by: r.signed_by } : { ok: false, error: r.error }, r.ok ? "" : r.message).toEqual(c.expect);
    });
  it("the wallet signs the same digest before and after the merchant's proof", () => {
    for (const r of [S.unsigned, S.merchant_signed]) expect(`0x${hex(oe.receiptEip712Digest(r, S.created))}`).toBe(S.digest);
  });
  it("addReceiptEip712Proof attaches the wallet's signature and refuses another wallet, a repeat and an Ed25519 party", () => {
    expect(oe.addReceiptEip712Proof(S.merchant_signed, "agent", S.signature, S.created)).toEqual(S.countersigned);
    const other = V.cases.find((c: { name: string }) => c.name === "other-wallet").receipt.proofs.at(-1).proofValue;
    expect(() => oe.addReceiptEip712Proof(S.merchant_signed, "agent", other, S.created)).toThrow(/not by agent_did/);
    expect(() => oe.addReceiptEip712Proof(S.countersigned, "agent", S.signature, S.created)).toThrow(/already signed/);
    expect(() => oe.addReceiptEip712Proof(S.unsigned, "merchant", S.signature, S.created)).toThrow(/not a did:pkh/);
    expect(() => oe.addReceiptEip712Proof(S.merchant_signed, "agent", "0x1234", S.created)).toThrow(/not by agent_did/);
  });
});

describe("verifyAgentForCheckout", () => {
  const V = json("checkout-1/vectors.json");
  for (const c of V.cases)
    it(c.name, async () => {
      const i = c.input;
      const r = await oe.verifyAgentForCheckout({
        agentDid: i.agent_did, cart: i.cart, merchantPolicy: i.merchant_policy, agent: i.agent, mandate: i.mandate, keyLog: keyState(i.key_state), status: i.status, now: i.now,
        approval: i.approval && { approval: i.approval.approval, verifierDid: i.approval.verifier_did, requestId: i.approval.request_id, counter: i.approval.counter },
      });
      expect({ decision: r.decision, reasons: r.reasons, ...(r.evidence.approval_error ? { approval_error: r.evidence.approval_error } : {}), ...(c.expect.approval_counter !== undefined ? { approval_counter: r.evidence.approval_counter } : {}) }).toEqual(c.expect);
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

describe("adversarial review fixes", () => {
  const CV = json("cart-1/vectors.json"), M = CV.mandates.M, cart = CV.covers[0].cart;
  const at = (merchant: string) => oe.mandateCovers(M, { ...cart, merchant });
  it("a wildcard merchant matches only a plain hostname", () => {
    expect(at("did:web:shop.moltbotden.com").ok).toBe(true);
    expect(at("did:web:shop.moltbotden.com%3A8443").ok).toBe(true);
    for (const evil of ["did:web:evil.com%2F.moltbotden.com", "did:web:evil.com%23.moltbotden.com", "did:web:evil.com%3F.moltbotden.com", "did:web:evil.com%40.moltbotden.com", "did:web:%zz.moltbotden.com"])
      expect(at(evil), evil).toMatchObject({ ok: false, reason: "out_of_scope" });
  });
  it("spent that is not an unsigned integer never fits", () => {
    for (const bad of [NaN, "abc", -1000, 1.5])
      expect(oe.mandateCovers(M, cart, { spent: { period_spent: bad as number } }), String(bad)).toMatchObject({ ok: false, reason: "over_limit" });
  });
  it("a malformed or foreign status answer is no answer", () => {
    const c = json("mandate-1/vectors.json").cases[0], x = c.context;
    const run = (status: unknown) => oe.verifyMandate(c.mandate, { keyLog: keyState(x.key_state), agentDid: x.agent_did, now: x.now, status: status as never });
    for (const bad of [{}, { status: "bogus" }, { status: "active", mandate_id: "md_aaaaaaaaaaaaaaaaaaaaaaaaaa" }, { status: "active", total_spent: "abc" }, { status: "active", period_spent: -1 }, "active", null])
      expect(run(bad), JSON.stringify(bad)).toMatchObject({ ok: false, error: "status_required" });
    expect(run({ status: "active", mandate_id: c.mandate.mandate_id }).ok).toBe(true);
  });
  it("a receipt cannot name one DID as merchant and agent, and refunds stay inside the purchase", () => {
    const p = json("receipt-1/vectors.json").cases[0].receipt;
    expect(oe.receiptError({ ...p, merchant_did: p.agent_did })).toMatch(/differ/);
    const refund = (id: string, total: number, extra = {}) => ({ ...p, kind: "refund", receipt_id: id, refers_to: p.receipt_id, total, proofs: undefined, ...extra });
    const r1 = refund("rc_aaaaaaaaaaaaaaaaaaaaaaaaaa", 600), r2 = refund("rc_bbbbbbbbbbbbbbbbbbbbbbbbbb", 400);
    expect(oe.verifyReceiptChain(p, [r1, r2])).toEqual({ ok: true, refunded: 1000 });
    expect(oe.verifyReceiptChain(p, [r1, { ...r2, total: 401 }])).toMatchObject({ ok: false, error: "over_refund" });
    expect(oe.verifyReceiptChain(p, [r1, r1])).toMatchObject({ ok: false, error: "mismatch" });
    expect(oe.verifyReceiptChain(p, [{ ...r1, currency: "EUR" }])).toMatchObject({ ok: false, error: "mismatch" });
    expect(oe.verifyReceiptChain(p, [{ ...r1, refers_to: "rc_cccccccccccccccccccccccccc" }])).toMatchObject({ ok: false, error: "mismatch" });
    expect(oe.verifyReceiptChain(r1, [])).toMatchObject({ ok: false, error: "not_purchase" });
  });
  it("an allow by approval hands back the key and counter to store", async () => {
    const c = V_CHECKOUT.cases.find((k: { name: string }) => k.name === "allow-step-up-approved"), i = c.input;
    const r = await oe.verifyAgentForCheckout({ agentDid: i.agent_did, cart: i.cart, merchantPolicy: i.merchant_policy, agent: i.agent, mandate: i.mandate, keyLog: keyState(i.key_state), status: i.status, now: i.now,
      approval: { approval: i.approval.approval, verifierDid: i.approval.verifier_did, requestId: i.approval.request_id, counter: 0 } });
    expect(r.evidence).toMatchObject({ approval_kid: i.approval.approval.device_id, approval_counter: 0 });
  });
});
const V_CHECKOUT = json("checkout-1/vectors.json");

describe("quorum approvals", () => {
  const V = json("quorum-1/vectors.json");
  for (const c of V.cases)
    it(c.name, () => {
      const x = c.context;
      const r = oe.verifyQuorum(c.approvals, { keyLog: keyState(x.key_state), verifierDid: x.verifier_did, ownerDid: x.owner_did, requestId: x.request_id, payloadDigest: x.payload_digest, now: x.now, m: x.m, of: x.of });
      expect(r.ok ? { ok: true, kids: r.kids } : { ok: false, error: r.error }, r.ok ? "" : r.message).toEqual(c.expect);
    });
  it("returns the counters to store, by kid", () => {
    const x = V.cases[0].context, opts = { keyLog: keyState(x.key_state), verifierDid: x.verifier_did, ownerDid: x.owner_did, requestId: x.request_id, payloadDigest: x.payload_digest, now: x.now, m: x.m, of: x.of };
    expect(oe.verifyQuorum(V.cases[0].approvals, opts)).toMatchObject({ ok: true, counters: { [x.of[0]]: 0 } });
  });
});

describe("verifyAgentForCheckout with an organisation's quorum", async () => {
  const { p256 } = await import("@noble/curves/nist.js");
  const V = json("checkout-1/vectors.json"), c = V.cases.find((x: { name: string }) => x.name === "step-up-over-threshold").input;
  const dev = (n: number) => {
    const secret = Uint8Array.from({ length: 32 }, (_, i) => i + n + 1), pub = p256.getPublicKey(secret, false);
    return { secret, cred: { kid: `org-device-${n}`, type: "p256" as const, jwk: { kty: "EC" as const, crv: "P-256" as const, x: Buffer.from(pub.slice(1, 33)).toString("base64url"), y: Buffer.from(pub.slice(33)).toString("base64url") } } };
  };
  const [d1, d2] = [dev(1), dev(2)], base = keyState(c.key_state), keyLog = { ...base, approvers: [...base.approvers, d1.cred, d2.cred] };
  const signed = (d: ReturnType<typeof dev>, o: Record<string, unknown> = {}) => {
    const a = { version: "approval/2.0", verifier_did: "did:web:shop.example", owner_did: base.did, request_id: "req_q1", payload_digest: oe.cartDigest(c.cart), decision: "approve", expires_at: c.now + 300, ...o };
    return { ...a, device_id: d.cred.kid, form: "p256", signature: Buffer.from(p256.sign(oe.approvalDigest(a as never), d.secret, { prehash: false, lowS: true })).toString("base64url") };
  };
  const run = (quorum: object | undefined) => oe.verifyAgentForCheckout({ agentDid: c.agent_did, cart: c.cart, merchantPolicy: c.merchant_policy, agent: c.agent, mandate: c.mandate, keyLog, status: c.status, now: c.now, quorum: quorum as never });
  const q = (approvals: unknown, o: object = {}) => ({ approvals, m: 2, of: [d1.cred.kid, d2.cred.kid], verifierDid: "did:web:shop.example", requestId: "req_q1", ...o });
  it("allows with m approvals of this cart, and reports the devices and counters to store", async () => {
    const r = await run(q([signed(d1), signed(d2)]));
    expect(r).toMatchObject({ decision: "allow", reasons: ["owner_approved_cart", "step_up_over"], evidence: { approval_kids: [d1.cred.kid, d2.cred.kid], approval_counters: { [d1.cred.kid]: 0 } } });
  });
  it("steps up when the bundle is short, padded with one device, for another cart, or for another request", async () => {
    for (const [name, bundle, over] of [["short", [signed(d1)], {}], ["same device twice", [signed(d1), signed(d1)], {}], ["other cart", [signed(d1), signed(d2, { payload_digest: "0".repeat(64) })], {}], ["other request", [signed(d1), signed(d2)], { requestId: "req_other" }]] as const) {
      const r = await run(q(bundle, over));
      expect(r.decision, name).toBe("step_up");
      expect(r.evidence.approval_error, name).toBeTruthy();
    }
  });
});
