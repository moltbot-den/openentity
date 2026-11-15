// Generates test-vectors/{mandate-1,cart-1,receipt-1,checkout-1}/ from the PUBLISHED THROWAWAY keys of approval-2.0 (P-256 owner devices)
// and test-vectors/keys.json (Ed25519 merchant and agent). Never use these keys for anything real. Run: pnpm --filter @openentity/sdk gen:vectors
// Signing lives here only. Expected results are written by hand below, not computed by the verifiers they test.
import { p256 } from "@noble/curves/nist.js";
import { sha256 as nobleSha256 } from "@noble/hashes/sha2.js";
import { readFileSync } from "node:fs";
import { canonicalize, keyPairFromSeed, approvalDigest, payloadDigest, mandateDigest, signReceipt, signProof, cartDigest } from "../src/index.ts";
import { hashTypedData } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { buildOwnerVectors, webPasskey } from "./gen-owner-vectors.ts";

const sha = (d: string | Uint8Array) => nobleSha256(typeof d === "string" ? new TextEncoder().encode(d) : d);
const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const b64url = (b: Uint8Array) => Buffer.from(b).toString("base64url");
const unhex = (h: string) => Uint8Array.from(h.match(/../g)!.map((x) => parseInt(x, 16)));
const base32 = (b: Uint8Array) => {
  const A = "abcdefghijklmnopqrstuvwxyz234567";
  return (([...b].map((x) => x.toString(2).padStart(8, "0")).join("").match(/.{1,5}/g) ?? []).map((g) => A[parseInt(g.padEnd(5, "0"), 2)]).join(""));
};
const id = (prefix: string, name: string) => `${prefix}_${base32(sha(`${prefix} vector ${name}`)).slice(0, 26)}`;

const owner = buildOwnerVectors();
const web = webPasskey();
const AK = (owner["approval-2.0/keys.json"] as { keys: Record<string, { secret: string; kid: string }> }).keys;
const AV = owner["approval-2.0/vectors.json"] as { key_states: Record<string, { did: string }>; cases: { approval: Record<string, unknown> }[] };
const OWNER_DID = AV.key_states.owner.did;
const OEIS = JSON.parse(readFileSync(new URL("../../../test-vectors/keys.json", import.meta.url), "utf8"));
const seed = (hexSeed: string) => unhex(hexSeed);
const KEY_WARNING = "PUBLISHED THROWAWAY KEYS FOR TEST VECTORS ONLY. Every secret is published (test-vectors/approval-2.0/keys.json and test-vectors/keys.json). Anyone can sign with them. Never use them for anything real.";

const T0 = 1794009600; // 2026-11-07T00:00:00Z
const DAY = 86_400;
const NOW = T0 + 1000;
const WARNING = KEY_WARNING;
export const COMMERCE_DIRS = ["mandate-1", "cart-1", "receipt-1", "checkout-1", "quorum-1"];

const p256Sign = (keyName: string, digest: Uint8Array) => ({
  device_id: AK[keyName].kid,
  form: "p256" as const,
  signature: b64url(p256.sign(digest, unhex(AK[keyName].secret), { prehash: false, lowS: true })),
});

export async function buildCommerceVectors(): Promise<Record<string, object>> {
  const agent = await keyPairFromSeed(seed(OEIS.entity.seed));
  const agent2 = await keyPairFromSeed(seed(OEIS.second.seed));
  const merchant = agent2; // the OEIS "second" key plays the merchant; the agent is "entity"
  const stranger = await keyPairFromSeed(sha("openentity commerce vector stranger"));
  const AGENT = agent.did, MERCHANT = merchant.did, OTHER_AGENT = stranger.did;

  // ---------------------------------------------------------------- mandates
  const limits = { currency: "USD", per_tx_max: 5000, period: "P1D", period_max: 20000, total_max: 100000 };
  const body = (name: string, o: Record<string, unknown> = {}) => ({
    version: "mandate/1",
    mandate_id: id("md", name),
    issuer_did: OWNER_DID,
    agent_did: AGENT,
    issued_at: T0,
    expires_at: T0 + 30 * DAY,
    limits,
    scope: { merchants: [MERCHANT, "*.moltbotden.com"], categories: ["software", "data"], rails: ["card", "x402", "mpp", "credits", "usdc"] },
    step_up_over: 2500,
    status: `https://account.openentity.org/v1/mandates/${id("md", name)}/status`,
    ...o,
  });
  type Md = { mandate_id: string; limits: unknown; scope: unknown; step_up_over: number; signature: { device_id: string; form: string; signature: string } };
  const sign = (b: Record<string, unknown>, key = "ios") => ({ ...b, signature: p256Sign(key, mandateDigest(b)) }) as unknown as Md;
  const M = {
    long: sign(body("long")),
    short: sign(body("short", { expires_at: T0 + DAY })),
    narrow: sign(body("narrow", { scope: { merchants: ["shop.example"], categories: ["software"], rails: ["card", "x402"] } })),
    ap2: sign(body("ap2", { ap2: { checkout_mandate_hash: "a".repeat(43) } })),
  };
  const ctx = (o: Record<string, unknown> = {}) => ({ key_state: "owner", agent_did: AGENT, now: NOW, ...o });
  const active = { status: "active", period_spent: 4000, total_spent: 9000 };
  const okm = (m: { mandate_id: string; limits: unknown; scope: unknown; step_up_over: number }, extra: object = {}) =>
    ({ ok: true, mandate_id: m.mandate_id, limits: m.limits, scope: m.scope, step_up_over: m.step_up_over, ...extra });
  const bad = (error: string) => ({ ok: false, error });
  const longTampered = { ...M.long, limits: { ...limits, per_tx_max: 5001 } };
  const approvalWithMandateSig = {
    version: "approval/2.0",
    verifier_did: "did:web:api.agentsecretstore.com",
    owner_did: OWNER_DID,
    request_id: "req_replay:1",
    payload_digest: payloadDigest({ replay: "mandate signature as approval" }),
    decision: "approve",
    expires_at: NOW + 300,
    device_id: M.long.signature.device_id,
    form: "p256",
    signature: M.long.signature.signature,
  };
  const ap = AV.cases[0].approval as { device_id: string; form: string; signature: string };
  const approvalOnMandate = { ...M.long, signature: { device_id: ap.device_id, form: ap.form, signature: ap.signature } };

  const mandateCases = [
    { name: "valid-with-status", description: "Thirty-day mandate, active status answer.", mandate: M.long, context: ctx({ status: active }), expect: okm(M.long, { kid: AK.ios.kid, period_spent: 4000, total_spent: 9000 }) },
    { name: "valid-offline", description: "A mandate with a day or less left needs no status answer (the offline mode).", mandate: M.short, context: ctx(), expect: okm(M.short, { kid: AK.ios.kid }) },
    { name: "valid-with-ap2-binding", description: "The optional ap2 binding is part of the signed body.", mandate: M.ap2, context: ctx({ status: active }), expect: okm(M.ap2, { kid: AK.ios.kid, period_spent: 4000, total_spent: 9000 }) },
    { name: "status-required", description: "More than a day left and no status answer: refused.", mandate: M.long, context: ctx(), expect: bad("status_required") },
    { name: "expired", description: "now equals expires_at.", mandate: M.short, context: ctx({ now: T0 + DAY }), expect: bad("expired") },
    { name: "not-yet-valid", description: "now before issued_at.", mandate: M.long, context: ctx({ now: T0 - 1, status: active }), expect: bad("not_yet_valid") },
    { name: "revoked", description: "The status endpoint says revoked (the owner paused the agent or revoked the mandate).", mandate: M.long, context: ctx({ status: { status: "revoked" } }), expect: bad("revoked") },
    { name: "exhausted", description: "The status endpoint says exhausted.", mandate: M.long, context: ctx({ status: { status: "exhausted", period_spent: 20000 } }), expect: bad("exhausted") },
    { name: "wrong-agent", description: "Another agent presents the mandate.", mandate: M.long, context: ctx({ agent_did: OTHER_AGENT, status: active }), expect: bad("wrong_agent") },
    { name: "wrong-owner", description: "Checked against another owner's key log.", mandate: M.long, context: ctx({ key_state: "single", status: active }), expect: bad("wrong_owner") },
    { name: "owner-closed", description: "The owner's key log is closed.", mandate: M.long, context: ctx({ key_state: "closed", status: active }), expect: bad("owner_closed") },
    { name: "revoked-device-key", description: "Signed by an approver that has since been revoked.", mandate: M.long, context: ctx({ key_state: "revoked", status: active }), expect: bad("unknown_key") },
    { name: "key-outside-log", description: "Signed by a key that is not in the owner's key log.", mandate: sign(body("thief"), "thief"), context: ctx({ status: active }), expect: bad("unknown_key") },
    { name: "tampered-limits", description: "per_tx_max raised after signing.", mandate: longTampered, context: ctx({ status: active }), expect: bad("bad_signature") },
    { name: "approval-signature-as-mandate", description: "The signature of an approval/2.0 (a different digest prefix) pasted into a mandate.", mandate: approvalOnMandate, context: ctx({ status: active }), expect: bad("bad_signature") },
    { name: "bad-version", description: "version is not mandate/1.", mandate: { ...M.long, version: "mandate/2" }, context: ctx({ status: active }), expect: bad("bad_version") },
    { name: "ttl-over-90-days", description: "expires_at is more than 90 days after issued_at.", mandate: sign(body("ttl", { expires_at: T0 + 91 * DAY })), context: ctx({ status: active }), expect: bad("malformed") },
    { name: "unknown-field", description: "A top-level field outside the profile.", mandate: sign(body("extra", { note: "x" })), context: ctx({ status: active }), expect: bad("malformed") },
    { name: "float-limit", description: "A fractional amount (limits are integers in minor units).", mandate: sign(body("float", { limits: { ...limits, per_tx_max: 50.5 } })), context: ctx({ status: active }), expect: bad("malformed") },
    { name: "empty-rails", description: "scope.rails is empty.", mandate: sign(body("rails", { scope: { merchants: [], rails: [] } })), context: ctx({ status: active }), expect: bad("malformed") },
  ];
  const mandateDigestCase = (m: Record<string, unknown>) => {
    const { signature: _s, ...b } = m;
    const pre = "mandate/1|*|" + canonicalize(b);
    return { preimage: pre, digest: hex(sha(pre)) };
  };

  // ---------------------------------------------------------------- carts
  const cart = (o: Record<string, unknown> = {}) => ({
    profile: "cart/1", merchant: MERCHANT, agent_did: AGENT,
    lines: [{ sku: "lst_123", title: "Dataset", qty: 1, unit: 1000, category: "data" }],
    total: 1000, currency: "USD", rail: "credits", mandate_id: M.long.mandate_id, ...o,
  });
  const line = (sku: string, unit: number, category = "software") => ({ sku, title: sku, qty: 1, unit, category });
  const CP = { M: M.long, N: M.narrow };
  const cov = (name: string, description: string, mandate: "M" | "N", c: unknown, expect: object, spent?: object) => ({ name, description, mandate, cart: c, ...(spent ? { spent } : {}), expect });
  const stepUp = (n: number) => cart({ lines: [line("sku_big", n)], total: n });
  const coversCases = [
    cov("small-cart", "Under step_up_over.", "M", cart(), { ok: true, step_up_required: false }),
    cov("step-up", "Over step_up_over (2500) and under per_tx_max: the owner must approve this cart.", "M", stepUp(3000), { ok: true, step_up_required: true }),
    cov("at-step-up-edge", "Exactly step_up_over needs no step up.", "M", stepUp(2500), { ok: true, step_up_required: false }),
    cov("at-per-tx-edge", "Exactly per_tx_max fits.", "M", stepUp(5000), { ok: true, step_up_required: true }),
    cov("over-per-tx", "One unit over per_tx_max.", "M", stepUp(5001), { ok: false, step_up_required: false, reason: "over_limit" }),
    cov("over-period", "period_spent 19000 plus 1500 passes period_max 20000.", "M", cart({ lines: [line("a", 1500)], total: 1500 }), { ok: false, step_up_required: false, reason: "over_limit" }, { period_spent: 19000 }),
    cov("at-period-edge", "period_spent 19000 plus 1000 reaches period_max exactly.", "M", cart(), { ok: true, step_up_required: false }, { period_spent: 19000 }),
    cov("over-total", "total_spent 99500 plus 1000 passes total_max 100000.", "M", cart(), { ok: false, step_up_required: false, reason: "over_limit" }, { total_spent: 99500 }),
    cov("merchant-pattern", "did:web:api.moltbotden.com matches *.moltbotden.com.", "M", cart({ merchant: "did:web:api.moltbotden.com" }), { ok: true, step_up_required: false }),
    cov("merchant-pattern-apex", "The apex moltbotden.com is not matched by *.moltbotden.com.", "M", cart({ merchant: "did:web:moltbotden.com" }), { ok: false, step_up_required: false, reason: "out_of_scope" }),
    cov("merchant-pattern-lookalike", "evilmoltbotden.com is not a subdomain.", "M", cart({ merchant: "did:web:evilmoltbotden.com" }), { ok: false, step_up_required: false, reason: "out_of_scope" }),
    cov("merchant-pattern-port", "A did:web with an encoded port matches its host.", "M", cart({ merchant: "did:web:api.moltbotden.com%3A8443" }), { ok: true, step_up_required: false }),
    cov("merchant-domain-exact", "A bare domain pattern equals the host of a did:web merchant.", "N", cart({ merchant: "did:web:shop.example", mandate_id: M.narrow.mandate_id, rail: "card", lines: [line("a", 100)], total: 100 }), { ok: true, step_up_required: false }),
    cov("merchant-not-listed", "A merchant outside the list.", "N", cart({ merchant: "did:web:other.example", mandate_id: null, rail: "card", lines: [line("a", 100)], total: 100 }), { ok: false, step_up_required: false, reason: "out_of_scope" }),
    cov("rail-not-in-scope", "credits is not in the narrow mandate's rails.", "N", cart({ merchant: "did:web:shop.example", mandate_id: null, rail: "credits", lines: [line("a", 100)], total: 100 }), { ok: false, step_up_required: false, reason: "out_of_scope" }),
    cov("category-not-in-scope", "A hardware line under a software-only mandate.", "N", cart({ merchant: "did:web:shop.example", mandate_id: null, rail: "card", lines: [line("a", 100, "hardware")], total: 100 }), { ok: false, step_up_required: false, reason: "out_of_scope" }),
    cov("line-without-category", "A line with no category under a mandate that lists categories.", "N", cart({ merchant: "did:web:shop.example", mandate_id: null, rail: "card", lines: [{ sku: "a", title: "a", qty: 1, unit: 100 }], total: 100 }), { ok: false, step_up_required: false, reason: "out_of_scope" }),
    cov("wrong-agent", "The cart names another agent.", "M", cart({ agent_did: OTHER_AGENT }), { ok: false, step_up_required: false, reason: "wrong_agent" }),
    cov("wrong-mandate", "The cart names another mandate.", "M", cart({ mandate_id: M.short.mandate_id }), { ok: false, step_up_required: false, reason: "wrong_mandate" }),
    cov("null-mandate-id", "A cart that names no mandate may be checked against one.", "M", cart({ mandate_id: null }), { ok: true, step_up_required: false }),
    cov("wrong-currency", "EUR cart, USD mandate.", "M", cart({ currency: "EUR" }), { ok: false, step_up_required: false, reason: "wrong_currency" }),
    cov("bad-cart", "total does not equal the lines.", "M", cart({ total: 999 }), { ok: false, step_up_required: false, reason: "bad_cart" }),
  ];
  const carts = [cart(), cart({ lines: [{ sku: "a", title: "Café ☕", qty: 2, unit: 450 }, { sku: "b", title: "B", qty: 1, unit: 100, category: "data" }], total: 1000, rail: "x402", mandate_id: null })].map((c) => ({
    cart: c, canonical: canonicalize(c), digest: cartDigest(c),
  }));
  const cartsInvalid = [
    { cart: cart({ total: 999 }), reason: "total is not the sum of qty * unit" },
    { cart: cart({ lines: [] , total: 0 }), reason: "no lines" },
    { cart: cart({ lines: [{ sku: "a", title: "a", qty: 0, unit: 10 }], total: 0 }), reason: "qty must be positive" },
    { cart: cart({ lines: [{ sku: "a", title: "a", qty: 1, unit: 10.5 }], total: 10.5 }), reason: "fractional amount" },
    { cart: cart({ rail: "paypal" }), reason: "rail not in the profile" },
    { cart: cart({ currency: "usd" }), reason: "currency is three uppercase letters" },
    { cart: cart({ profile: "cart/2" }), reason: "profile must be cart/1" },
    { cart: { ...cart(), note: "x" }, reason: "unknown field" },
    { cart: cart({ merchant: "shop.example" }), reason: "merchant must be a DID" },
    { cart: cart({ mandate_id: "md_short" }), reason: "mandate_id form" },
  ];

  // ---------------------------------------------------------------- receipts
  const cartPurchase = cart();
  const purchase = {
    version: "receipt/1", receipt_id: id("rc", "purchase"), kind: "purchase", refers_to: null, merchant_did: MERCHANT, agent_did: AGENT,
    mandate_id: M.long.mandate_id, mandate_hash: hex(mandateDigest(M.long)), cart_digest: cartDigest(cartPurchase), approval_request_id: null,
    total: 1000, currency: "USD", rail: "x402", settlement_ref: "0x" + "ab".repeat(32), created_at: T0 + 100,
  };
  const refund = { ...purchase, receipt_id: id("rc", "refund"), kind: "refund", refers_to: purchase.receipt_id, total: 400, settlement_ref: "re_vector_1", created_at: T0 + 200 };
  const chargeback = { ...purchase, receipt_id: id("rc", "chargeback"), kind: "chargeback", refers_to: purchase.receipt_id, settlement_ref: "dp_vector_1", created_at: T0 + 300 };
  const CREATED = "2026-11-07T00:02:00Z";
  const byM = (r: object) => signReceipt(r, merchant, "merchant", CREATED);
  const both = async (r: object) => signReceipt(await byM(r), agent, "agent", CREATED);
  const pBoth = await both(purchase), pM = await byM(purchase);
  const rcase = (name: string, description: string, receipt: unknown, expect: object, require?: string[]) => ({ name, description, receipt, ...(require ? { require } : {}), expect });
  const receiptCases = [
    rcase("purchase-both-proofs", "Merchant and buyer agent both signed.", pBoth, { ok: true, signed_by: ["merchant", "agent"] }, ["merchant", "agent"]),
    rcase("purchase-merchant-only", "Merchant proof alone satisfies the default requirement.", pM, { ok: true, signed_by: ["merchant"] }),
    rcase("agent-countersign-missing", "Both proofs required, the agent has not countersigned.", pM, { ok: false, error: "missing_proof" }, ["merchant", "agent"]),
    rcase("unsigned", "No proofs.", purchase, { ok: false, error: "missing_proof" }),
    rcase("agent-signed-first", "The agent may sign before the merchant; order is not significant.", { ...pBoth, proofs: [pBoth.proofs![1], pBoth.proofs![0]] }, { ok: true, signed_by: ["agent", "merchant"] }, ["merchant", "agent"]),
    rcase("refund", "A refund is a new receipt that refers to the purchase.", await both(refund), { ok: true, signed_by: ["merchant", "agent"] }, ["merchant", "agent"]),
    rcase("chargeback", "A chargeback is a new receipt that refers to the purchase.", await byM(chargeback), { ok: true, signed_by: ["merchant"] }),
    rcase("tampered-total", "total changed after signing.", { ...pBoth, total: 1 }, { ok: false, error: "bad_proof" }),
    rcase("tampered-mandate-hash", "mandate_hash changed after signing.", { ...pM, mandate_hash: "0".repeat(64) }, { ok: false, error: "bad_proof" }),
    rcase("proof-mislabelled", "The agent's proof presented as the merchant's.", { ...pBoth, proofs: [{ ...pBoth.proofs![1], by: "merchant" }] }, { ok: false, error: "wrong_signer" }),
    rcase("signed-by-stranger", "A proof by a key that is neither party, labelled merchant.", { ...purchase, proofs: [{ by: "merchant", ...(await signProof(purchase, stranger, CREATED)) }] }, { ok: false, error: "wrong_signer" }),
    rcase("duplicate-by", "Two merchant proofs.", { ...pM, proofs: [pM.proofs![0], pM.proofs![0]] }, { ok: false, error: "malformed" }),
    rcase("refund-without-refers-to", "A refund with refers_to null.", { ...refund, refers_to: null }, { ok: false, error: "malformed" }),
    rcase("purchase-with-refers-to", "A purchase that refers to another receipt.", { ...purchase, refers_to: refund.receipt_id }, { ok: false, error: "malformed" }),
    rcase("mandate-id-without-hash", "mandate_id and mandate_hash go together.", { ...purchase, mandate_hash: null }, { ok: false, error: "malformed" }),
    rcase("no-mandate", "A purchase approved per cart: no mandate, an approval request id.", await byM({ ...purchase, mandate_id: null, mandate_hash: null, approval_request_id: "req_cart:7" }), { ok: true, signed_by: ["merchant"] }),
    rcase("unknown-kind", "kind outside the profile.", { ...purchase, kind: "void" }, { ok: false, error: "malformed" }),
  ];
  // ---------------------------------------------------------------- receipts with a did:pkh party (EIP-712, signed by the wallet through viem, independent of the SDK digest)
  const wallet = privateKeyToAccount(`0x${hex(sha("openentity commerce vector wallet"))}`);
  const PKH = `did:pkh:eip155:8453:${wallet.address}`;
  const wallet2 = privateKeyToAccount(`0x${hex(sha("openentity commerce vector other wallet"))}`);
  const pkhPurchase = { ...purchase, agent_did: PKH };
  const typed = (obj: object, objectType = "receipt/1", created = CREATED) => ({
    domain: { name: "Open Entity", version: "1" },
    types: { OpenEntityObject: [{ name: "objectType", type: "string" }, { name: "canonicalHash", type: "bytes32" }, { name: "created", type: "string" }] },
    primaryType: "OpenEntityObject" as const,
    message: { objectType, canonicalHash: `0x${hex(sha(canonicalize(obj)))}` as `0x${string}`, created },
  });
  const eipProof = async (obj: object, who = wallet, objectType = "receipt/1") =>
    ({ by: "agent", type: "EthereumEip712Signature2021", created: CREATED, verificationMethod: `${PKH}#blockchainAccountId`, proofPurpose: "assertionMethod", proofValue: await who.signTypedData(typed(obj, objectType)) });
  const pkhByM = await signReceipt(pkhPurchase, merchant, "merchant", CREATED);
  const walletProof = await eipProof(pkhPurchase);
  const pkhBoth = { ...pkhByM, proofs: [...pkhByM.proofs!, walletProof] };
  const pkhCase = (name: string, description: string, receipt: unknown, expect: object, require = ["merchant", "agent"]) => ({ name, description, receipt, require, expect });
  const pkhCases = [
    pkhCase("merchant-then-wallet", "The merchant signed with Ed25519, then the buyer's wallet countersigned: the typed data hashes the receipt without `proofs`, so the merchant's proof does not change what the wallet signs.", pkhBoth, { ok: true, signed_by: ["merchant", "agent"] }),
    pkhCase("wallet-then-merchant", "The wallet signed first and the merchant after: order does not matter.", { ...pkhPurchase, proofs: [walletProof, pkhByM.proofs![0]] }, { ok: true, signed_by: ["agent", "merchant"] }),
    pkhCase("wallet-only", "Only the wallet signed; the merchant's proof is required too.", { ...pkhPurchase, proofs: [walletProof] }, { ok: false, error: "missing_proof" }),
    pkhCase("wallet-only-agent-required", "Only the wallet signed and only the agent's proof is required.", { ...pkhPurchase, proofs: [walletProof] }, { ok: true, signed_by: ["agent"] }, ["agent"]),
    pkhCase("tampered-total", "total changed after the wallet signed.", { ...pkhBoth, total: 1 }, { ok: false, error: "bad_proof" }),
    pkhCase("other-wallet", "Another wallet's signature under the agent's DID.", { ...pkhByM, proofs: [...pkhByM.proofs!, await eipProof(pkhPurchase, wallet2)] }, { ok: false, error: "bad_proof" }),
    pkhCase("hash-covers-proofs", "A signature over the receipt WITH the merchant's proof inside (hashing minus `proof` only): the buyer could not have signed it before the merchant, and it is refused.", { ...pkhByM, proofs: [...pkhByM.proofs!, await eipProof(pkhByM)] }, { ok: false, error: "bad_proof" }),
    pkhCase("object-type-entity-document", "Signed with objectType EntityDocument instead of receipt/1: another domain, refused.", { ...pkhByM, proofs: [...pkhByM.proofs!, await eipProof(pkhPurchase, wallet, "EntityDocument")] }, { ok: false, error: "bad_proof" }),
    pkhCase("proof-mislabelled-merchant", "The wallet's proof presented as the merchant's.", { ...pkhPurchase, proofs: [{ ...walletProof, by: "merchant" }] }, { ok: false, error: "wrong_signer" }),
  ];
  const pkhSigning = {
    wallet_address: wallet.address,
    agent_did: PKH,
    created: CREATED,
    unsigned: pkhPurchase,
    merchant_signed: pkhByM,
    digest: hashTypedData(typed(pkhPurchase)),
    signature: walletProof.proofValue,
    countersigned: pkhBoth,
  };
  // ---------------------------------------------------------------- checkout decisions
  const VERIFIER = MERCHANT;
  const approve = (c: unknown, name: string, o: Record<string, unknown> = {}) => {
    const f = { verifier_did: VERIFIER, owner_did: OWNER_DID, request_id: `req_${name}`, payload_digest: cartDigest(c), decision: "approve", expires_at: NOW + 300, ...o };
    return { approval: { version: "approval/2.0", ...f, ...p256Sign("ios", approvalDigest(f as never)) }, verifier_did: f.verifier_did, request_id: f.request_id };
  };
  // A WebAuthn approval (the owner's web passkey) carries a signature counter; `counter` in the input is the one the merchant stored for that key.
  const approveWeb = (c: unknown, name: string, signed: number, stored: number) => {
    const f = { verifier_did: VERIFIER, owner_did: OWNER_DID, request_id: `req_${name}`, payload_digest: cartDigest(c), decision: "approve", expires_at: NOW + 300 };
    return { approval: { version: "approval/2.0", ...f, device_id: web.kid, form: "webauthn", ...web.assert(approvalDigest(f as never), { counter: signed }) }, verifier_did: f.verifier_did, request_id: f.request_id, counter: stored };
  };
  const big = stepUp(3000), over = stepUp(5001);
  const policy = { min_level: 1, require_owner: true, require_mandate: true, min_security_band: "good", accept_issuers: ["did:web:securemyagent.ai"] };
  const facts = { level: 2, owner_did: OWNER_DID, security_band: "strong", security_issuer: "did:web:securemyagent.ai" };
  const base = { agent_did: AGENT, cart: cart(), merchant_policy: policy, agent: facts, mandate: M.long, key_state: "owner", status: active, now: NOW };
  const k = (name: string, description: string, input: Record<string, unknown>, expect: { decision: string; reasons: string[]; approval_error?: string; approval_counter?: number }) => ({ name, description, input: { ...base, ...input }, expect });
  const checkoutCases = [
    k("allow-mandate-covers", "Mandate covers a small cart and the policy is met.", {}, { decision: "allow", reasons: ["mandate_covers_cart"] }),
    k("step-up-over-threshold", "Over step_up_over and no approval.", { cart: big }, { decision: "step_up", reasons: ["step_up_over"] }),
    k("allow-step-up-approved", "Over step_up_over with the owner's approval of this exact cart.", { cart: big, approval: approve(big, "big") }, { decision: "allow", reasons: ["owner_approved_cart", "step_up_over"] }),
    k("step-up-approval-for-other-cart", "An approval of a different cart does not carry over.", { cart: big, approval: approve(cart(), "other") }, { decision: "step_up", reasons: ["step_up_over"], approval_error: "wrong_payload" }),
    k("step-up-approval-expired", "An expired approval.", { cart: big, approval: approve(big, "old", { expires_at: NOW - 1 }) }, { decision: "step_up", reasons: ["step_up_over"], approval_error: "expired" }),
    k("step-up-approval-deny", "The owner denied this cart.", { cart: big, approval: approve(big, "no", { decision: "deny" }) }, { decision: "step_up", reasons: ["step_up_over"], approval_error: "bad_decision" }),
    k("step-up-mandate-signature-as-approval", "The mandate's signature pasted into an approval/2.0: a different digest prefix, so it cannot verify.", { cart: big, approval: { approval: { ...approve(big, "replay").approval, device_id: M.long.signature.device_id, signature: M.long.signature.signature }, verifier_did: VERIFIER, request_id: "req_replay" } }, { decision: "step_up", reasons: ["step_up_over"], approval_error: "bad_signature" }),
    k("allow-webauthn-counter-advances", "A web passkey approval whose signature counter (7) is above the stored one (6): allowed, and evidence returns 7 to store.", { cart: big, approval: approveWeb(big, "web7", 7, 6) }, { decision: "allow", reasons: ["owner_approved_cart", "step_up_over"], approval_counter: 7 }),
    k("allow-webauthn-no-counter", "An authenticator that keeps no counter signs 0 and 0 is stored: allowed.", { cart: big, approval: approveWeb(big, "web0", 0, 0) }, { decision: "allow", reasons: ["owner_approved_cart", "step_up_over"], approval_counter: 0 }),
    k("step-up-webauthn-counter-replayed", "The same approval offered again after its counter (7) was stored: the counter did not increase, so it is a replay.", { cart: big, approval: approveWeb(big, "web7", 7, 7) }, { decision: "step_up", reasons: ["step_up_over"], approval_error: "counter_replayed" }),
    k("step-up-webauthn-counter-regressed", "A cloned authenticator signs counter 5 below the stored 6.", { cart: big, approval: approveWeb(big, "web5", 5, 6) }, { decision: "step_up", reasons: ["step_up_over"], approval_error: "counter_replayed" }),
    k("step-up-over-limit", "Over per_tx_max: only this cart's approval can allow it.", { cart: over }, { decision: "step_up", reasons: ["mandate_over_limit"] }),
    k("allow-over-limit-approved", "Over per_tx_max with the owner's approval of this exact cart.", { cart: over, approval: approve(over, "over") }, { decision: "allow", reasons: ["owner_approved_cart", "mandate_over_limit"] }),
    k("step-up-out-of-scope", "A merchant outside the mandate's scope.", { cart: cart({ merchant: "did:web:other.example" }) }, { decision: "step_up", reasons: ["mandate_out_of_scope"] }),
    k("deny-mandate-expired", "The mandate expired.", { mandate: M.short, cart: cart({ mandate_id: M.short.mandate_id }), now: T0 + DAY }, { decision: "deny", reasons: ["mandate_expired"] }),
    k("deny-mandate-revoked", "The status endpoint says revoked.", { status: { status: "revoked" } }, { decision: "deny", reasons: ["mandate_revoked"] }),
    k("deny-mandate-status-required", "A long mandate with no status answer.", { status: undefined }, { decision: "deny", reasons: ["mandate_status_required"] }),
    k("deny-mandate-wrong-agent", "Another agent presents the mandate.", { agent_did: OTHER_AGENT, cart: cart({ agent_did: OTHER_AGENT }) }, { decision: "deny", reasons: ["mandate_wrong_agent"] }),
    k("deny-mandate-tampered", "The mandate's limits were changed after signing.", { mandate: longTampered }, { decision: "deny", reasons: ["mandate_bad_signature"] }),
    k("deny-cart-for-other-agent", "The request is signed by one agent and the cart names another.", { cart: cart({ agent_did: OTHER_AGENT }) }, { decision: "deny", reasons: ["agent_mismatch"] }),
    k("deny-no-agent", "No verified agent.", { agent_did: undefined }, { decision: "deny", reasons: ["request_unverified"] }),
    k("deny-bad-cart", "The cart is not a cart/1.", { cart: cart({ total: 1 }) }, { decision: "deny", reasons: ["bad_cart"] }),
    k("deny-level-too-low", "min_level 1, agent level 0.", { agent: { ...facts, level: 0 } }, { decision: "deny", reasons: ["level_too_low"] }),
    k("deny-security-band", "min_security_band good, agent poor.", { agent: { ...facts, security_band: "poor" } }, { decision: "deny", reasons: ["security_band_too_low"] }),
    k("deny-security-band-unknown", "A band the profile does not rank.", { agent: { ...facts, security_band: "platinum" } }, { decision: "deny", reasons: ["security_band_too_low"] }),
    k("deny-issuer-not-accepted", "The posture is vouched by an issuer the merchant does not accept.", { agent: { ...facts, security_issuer: "did:web:scanner.example" } }, { decision: "deny", reasons: ["issuer_not_accepted"] }),
    k("deny-mandate-required", "The merchant requires a mandate.", { mandate: undefined, status: undefined }, { decision: "deny", reasons: ["mandate_required"] }),
    k("step-up-no-mandate", "No mandate and the policy does not require one: the owner can approve this cart.", { mandate: undefined, status: undefined, merchant_policy: { min_level: 1 } }, { decision: "step_up", reasons: ["no_mandate"] }),
    k("allow-approval-without-mandate", "No mandate, the owner's approval of this cart, owner known from the registry.", { mandate: undefined, status: undefined, merchant_policy: { require_owner: true }, approval: approve(cart(), "solo") }, { decision: "allow", reasons: ["owner_approved_cart", "no_mandate"] }),
    k("deny-owner-unknown", "require_owner and no owner known.", { mandate: undefined, status: undefined, merchant_policy: { require_owner: true }, agent: { ...facts, owner_did: undefined } }, { decision: "deny", reasons: ["owner_unknown"] }),
    k("deny-two-policy-failures", "Every failed policy check is listed.", { agent: { level: 0, security_band: "poor" } }, { decision: "deny", reasons: ["level_too_low", "security_band_too_low"] }),
  ];

  // ---------------------------------------------------------------- quorum (approvals[] of an organisation-owned action)
  // The approvals are the approval-2.0 cases' own (same verifier, request and payload), so no new signature is made here.
  const pick = (name: string) => (AV.cases as unknown as { name: string; approval: Record<string, unknown>; context: Record<string, unknown> }[]).find((c) => c.name === name)!;
  const IOS = pick("p256-approve").approval, WEB = pick("webauthn-web-origin").approval, DENY = pick("p256-deny").approval, STRANGER = pick("unknown-key").approval;
  const qbase = pick("p256-approve").context as { verifier_did: string; owner_did: string; request_id: string; payload_digest: string; now: number };
  const OF = [AK.ios.kid, AK.web.kid];
  const qctx = (o: Record<string, unknown> = {}) => ({ key_state: "owner", verifier_did: qbase.verifier_did, owner_did: qbase.owner_did, request_id: qbase.request_id, payload_digest: qbase.payload_digest, now: qbase.now, m: 2, of: OF, ...o });
  const q = (name: string, description: string, approvals: unknown, context: object, expect: object) => ({ name, description, approvals, context, expect });
  const quorumCases = [
    q("two-of-two", "Both devices approve the same request: an iOS device key (p256) and a web passkey (webauthn).", [IOS, WEB], qctx(), { ok: true, kids: [AK.ios.kid, AK.web.kid] }),
    q("one-of-two", "m is 1: one approval is enough.", [WEB], qctx({ m: 1 }), { ok: true, kids: [AK.web.kid] }),
    q("not-met", "m is 2 and one device approved.", [IOS], qctx(), { ok: false, error: "quorum_not_met" }),
    q("same-device-twice", "One device sent its approval twice: it counts once, and the bundle is refused.", [IOS, IOS], qctx(), { ok: false, error: "duplicate_device" }),
    q("device-outside-of", "web is an approver in the key log but not in the quorum's list.", [IOS, WEB], qctx({ of: [AK.ios.kid, AK.android.kid] }), { ok: false, error: "not_in_quorum" }),
    q("device-outside-log", "A key the quorum lists but the key log does not hold.", [IOS, STRANGER], qctx({ of: [AK.ios.kid, AK.stranger.kid] }), { ok: false, error: "unknown_key" }),
    q("another-payload", "The verifier recomputed another payload digest than the approvals signed.", [IOS, WEB], qctx({ payload_digest: payloadDigest({ other: 1 }) }), { ok: false, error: "wrong_payload" }),
    q("another-request", "The verifier issued another request id than the approvals answer.", [IOS, WEB], qctx({ request_id: "req_other:1" }), { ok: false, error: "wrong_request" }),
    q("one-deny", "A deny is not an approval.", [DENY, WEB], qctx(), { ok: false, error: "bad_decision" }),
    q("expired", "now is at the approvals' expires_at.", [IOS, WEB], qctx({ now: IOS.expires_at }), { ok: false, error: "expired" }),
    q("padded-bundle", "More approvals than devices in the quorum.", [IOS, WEB, IOS], qctx(), { ok: false, error: "malformed" }),
    q("m-zero", "m below 1.", [IOS], qctx({ m: 0 }), { ok: false, error: "bad_quorum" }),
    q("m-over-of", "m above the number of devices.", [IOS, WEB], qctx({ m: 3 }), { ok: false, error: "bad_quorum" }),
    q("not-a-list", "approvals is one object, not a list.", IOS, qctx({ m: 1 }), { ok: false, error: "malformed" }),
    q("owner-closed", "The organisation's key log is closed.", [IOS, WEB], qctx({ key_state: "closed" }), { ok: false, error: "owner_closed" }),
  ];

  const w = (description: string, o: object) => ({ description, warning: WARNING, ...o });
  return {
    "mandate-1/vectors.json": w("mandate/1 vectors. Owner DID, key states and device keys are those of approval-2.0 (published throwaway keys). cases: verify `mandate` with `context` (key_state names an entry of approval-2.0/vectors.json key_states; agent_did, now and the status answer); `expect` is {ok: true, kid, mandate_id, limits, scope, step_up_over, period_spent?, total_spent?} or {ok: false, error}. digests: the signing preimage and its SHA-256. replay: an approval/2.0 carrying a mandate's signature must fail bad_signature.", {
      verifier_scope: "*",
      digests: [M.long, M.ap2].map((m) => ({ mandate_id: m.mandate_id, ...mandateDigestCase(m) })),
      cases: mandateCases,
      replay: { mandate_signature_as_approval: { approval: approvalWithMandateSig, context: { verifier_did: "did:web:api.agentsecretstore.com", owner_did: OWNER_DID, request_id: "req_replay:1", payload_digest: approvalWithMandateSig.payload_digest, now: NOW, key_state: "owner" }, expect: { ok: false, error: "bad_signature" } } },
    }),
    "cart-1/vectors.json": w("cart/1 vectors. carts: valid summaries with their canonical form and payload digest (the payload_digest of the approval/2.0 that approves the purchase). invalid: cartDigest must refuse. mandates: signed mandate/1 objects the covers cases refer to by name. covers: mandateCovers(mandates[mandate], cart, {spent}) must equal `expect`.", {
      carts, invalid: cartsInvalid, mandates: CP, covers: coversCases,
    }),
    "receipt-1/pkh.json": w("receipt/1 vectors for a buyer whose DID is a did:pkh wallet (spec/commerce-profile.md section 4). The wallet signs EIP-712 typed data {objectType: \"receipt/1\", canonicalHash: SHA-256 of JCS(receipt without `proof` and `proofs`), created} under domain {name: \"Open Entity\", version: \"1\"}; the merchant signs eddsa-jcs-2022 as in vectors.json. cases: verifyReceipt(receipt, {require}) must equal `expect`. signing: receiptEip712Digest(unsigned, created) and (merchant_signed, created) both equal `digest` (the merchant's proof is outside the hash), addReceiptEip712Proof(merchant_signed, \"agent\", signature, created) equals `countersigned`, and it refuses a signature by another wallet. The wallet key is the SHA-256 of the string `openentity commerce vector wallet`: a published throwaway.", {
      merchant_did: MERCHANT, agent_did: PKH, cases: pkhCases, signing: pkhSigning,
    }),
    "receipt-1/vectors.json": w("receipt/1 vectors. Merchant key is the OEIS `second` key, agent the `entity` key (test-vectors/keys.json). cases: verifyReceipt(receipt, {require}) must equal `expect`; `require` defaults to [merchant]. Proofs are eddsa-jcs-2022 over the receipt without `proofs`; `by` is outside the signed proof configuration.", {
      merchant_did: MERCHANT, agent_did: AGENT, cases: receiptCases,
    }),
    "quorum-1/vectors.json": w("quorum vectors: verifyQuorum(approvals, {keyLog: key_states[context.key_state], verifierDid: context.verifier_did, ownerDid: context.owner_did, requestId, payloadDigest, now, m, of}) must equal `expect`: {ok: true, kids} (the kids in bundle order) or {ok: false, error}. The owner key state plays the organisation's key log; `of` is the policy list of quorum devices. approvals are those of approval-2.0.", {
      cases: quorumCases,
    }),
    "checkout-1/vectors.json": w("verifyAgentForCheckout vectors. input: agent_did (already verified from the request signature), cart, merchant_policy, agent (registry facts), mandate, key_state (approval-2.0 key_states), status, approval {approval, verifier_did, request_id}, now. expect: decision, reasons (in order) and, where an approval was offered and refused, the approval error in evidence.approval_error. Security bands rank poor < fair < good < strong.", {
      cases: checkoutCases,
    }),
  };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const { mkdirSync, writeFileSync } = await import("node:fs");
  const { serialize } = await import("./gen-vectors.ts");
  const dir = new URL("../../../test-vectors/", import.meta.url);
  for (const [path, v] of Object.entries(await buildCommerceVectors())) {
    mkdirSync(new URL(path.split("/")[0] + "/", dir), { recursive: true });
    writeFileSync(new URL(path, dir), serialize(v));
  }
  console.log("wrote mandate-1, cart-1, receipt-1 (and pkh), checkout-1 and quorum-1 vectors to", dir.pathname);
}
