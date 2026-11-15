// OEIS Commerce Profile (spec/commerce-profile.md): mandate/1, cart/1, receipt/1 and the one-call checkout check.
// Verify and sign only: owners sign mandates on their devices, products verify. test/commerce.test.ts runs
// test-vectors/{mandate-1,cart-1,receipt-1,checkout-1}; sdk/python runs the same files.
import { OpenEntityError } from "./errors.ts";
import { canonicalize, sha256Sync, toHex, signProof, verifyProof, verificationMethodId, eip712Digest, eip712ObjectType, recoverEip712, unsecured, type KeyPair, type Resolver, type Proof } from "./core.ts";
import { verifyRequest } from "./httpsig.ts";
import { verifyApproval, verifyQuorum, payloadDigest, type KeyLogState, type ApprovalError } from "./owner.ts";
import { Fail, fail, isObj, exactKeys, isUint, plainJson, checkSignature, signedShape, DID, HEX64, RP_ID, DAY } from "./owner.ts";

const MAX_TTL = 90 * DAY;
const MD_ID = /^md_[a-z2-7]{26}$/;
const RC_ID = /^rc_[a-z2-7]{26}$/;
const CCY = /^[A-Z]{3}$/;
export const RAILS = ["card", "x402", "mpp", "credits", "usdc"] as const;
const PERIODS = ["P1D", "P7D", "P1M"];
const BANDS = ["poor", "fair", "good", "strong"];

type Obj = Record<string, unknown>;
const strs = (v: unknown): v is string[] => Array.isArray(v) && v.every((x) => typeof x === "string" && x.length > 0 && x.length <= 253);

export interface Limits { currency: string; per_tx_max: number; period: string; period_max: number; total_max: number }
export interface Scope { merchants: string[]; categories?: string[]; rails: string[] }
export interface Mandate {
  version: "mandate/1"; mandate_id: string; issuer_did: string; agent_did: string; issued_at: number; expires_at: number;
  limits: Limits; scope: Scope; step_up_over: number; status: string; ap2?: { checkout_mandate_hash: string | null };
  signature: { device_id: string; form: "p256" | "webauthn"; signature: string; authenticator_data?: string; client_data_json?: string };
}
export interface CartLine { sku: string; title: string; qty: number; unit: number; category?: string }
export interface Cart {
  profile: "cart/1"; merchant: string; agent_did: string; lines: CartLine[]; total: number; currency: string; rail: string; mandate_id: string | null;
}
export type MandateError = "malformed" | "bad_version" | "wrong_owner" | "owner_closed" | "wrong_agent" | "not_yet_valid" | "expired" | "unknown_key" | "bad_signature" | "bad_webauthn" | "revoked" | "exhausted" | "status_required";
export type MandateStatus = { status: "active" | "revoked" | "exhausted"; mandate_id?: string; period_spent?: number; total_spent?: number };
export type MandateResult =
  | { ok: true; kid: string; mandate_id: string; limits: Limits; scope: Scope; step_up_over: number; period_spent?: number; total_spent?: number }
  | { ok: false; error: MandateError; message: string };

// ---------------------------------------------------------------- cart/1

const CART_KEYS = ["profile", "merchant", "agent_did", "lines", "total", "currency", "rail", "mandate_id"];
const LINE_KEYS = ["sku", "title", "qty", "unit"];

/** null when `c` is a well-formed cart/1 summary, else why not. */
export function cartError(c: unknown): string | null {
  if (!isObj(c) || !exactKeys(c, CART_KEYS)) return `cart/1 has exactly: ${CART_KEYS.join(", ")}`;
  if (c.profile !== "cart/1") return "profile must be cart/1";
  if (typeof c.merchant !== "string" || !DID.test(c.merchant)) return "merchant must be a DID";
  if (typeof c.agent_did !== "string" || !DID.test(c.agent_did)) return "agent_did must be a DID";
  if (typeof c.currency !== "string" || !CCY.test(c.currency)) return "currency must be 3 uppercase letters";
  if (!(RAILS as readonly unknown[]).includes(c.rail)) return `rail must be one of ${RAILS.join(", ")}`;
  if (c.mandate_id !== null && !(typeof c.mandate_id === "string" && MD_ID.test(c.mandate_id))) return "mandate_id must be md_<26 base32> or null";
  if (!Array.isArray(c.lines) || !c.lines.length || c.lines.length > 100) return "lines must hold 1 to 100 lines";
  let sum = 0;
  for (const l of c.lines as unknown[]) {
    if (!isObj(l)) return "a line must be an object";
    const keys = Object.hasOwn(l, "category") ? [...LINE_KEYS, "category"] : LINE_KEYS;
    if (!exactKeys(l, keys)) return `a line has exactly: ${keys.join(", ")}`;
    if (typeof l.sku !== "string" || !l.sku || typeof l.title !== "string" || (Object.hasOwn(l, "category") && typeof l.category !== "string")) return "sku, title and category must be strings";
    if (!isUint(l.qty) || !l.qty || !isUint(l.unit)) return "qty must be a positive integer and unit an integer in minor units";
    sum += (l.qty as number) * (l.unit as number);
  }
  if (!isUint(c.total) || c.total !== sum) return "total must equal the sum of qty * unit";
  return plainJson(c);
}

/** Lowercase hex payload digest of a cart/1 summary: the `payload_digest` of the approval/2.0 that approves this purchase. */
export function cartDigest(cart: unknown): string {
  const e = cartError(cart);
  if (e) throw new OpenEntityError("invalid_input", e);
  return payloadDigest(cart);
}

// ---------------------------------------------------------------- mandate/1

const MANDATE_KEYS = ["version", "mandate_id", "issuer_did", "agent_did", "issued_at", "expires_at", "limits", "scope", "step_up_over", "status", "signature"];

function mandateFieldsError(m: Obj): string | null {
  const keys = Object.keys(m);
  if (keys.some((k) => !MANDATE_KEYS.includes(k) && k !== "ap2") || MANDATE_KEYS.some((k) => !Object.hasOwn(m, k))) return `mandate/1 has ${MANDATE_KEYS.join(", ")} and optionally ap2`;
  if (typeof m.mandate_id !== "string" || !MD_ID.test(m.mandate_id)) return "mandate_id must be md_<26 base32>";
  if (typeof m.issuer_did !== "string" || !DID.test(m.issuer_did)) return "issuer_did must be a DID";
  if (typeof m.agent_did !== "string" || !DID.test(m.agent_did)) return "agent_did must be a DID";
  if (!isUint(m.issued_at) || !isUint(m.expires_at) || m.expires_at <= m.issued_at) return "issued_at and expires_at must be unix seconds, expires after issued";
  if (m.expires_at - m.issued_at > MAX_TTL) return "a mandate lasts at most 90 days";
  const l = m.limits;
  if (!isObj(l) || !exactKeys(l, ["currency", "per_tx_max", "period", "period_max", "total_max"])) return "limits must be {currency, per_tx_max, period, period_max, total_max}";
  if (typeof l.currency !== "string" || !CCY.test(l.currency) || !PERIODS.includes(l.period as string)) return `limits.currency must be 3 uppercase letters and period one of ${PERIODS.join(", ")}`;
  if (!isUint(l.per_tx_max) || !isUint(l.period_max) || !isUint(l.total_max)) return "limits amounts must be integers in minor units";
  const s = m.scope;
  if (!isObj(s) || Object.keys(s).some((k) => !["merchants", "categories", "rails"].includes(k)) || !Object.hasOwn(s, "merchants") || !Object.hasOwn(s, "rails")) return "scope must be {merchants, categories?, rails}";
  if (!strs(s.merchants) || (Object.hasOwn(s, "categories") && !strs(s.categories))) return "scope.merchants and scope.categories must be arrays of strings";
  if (!Array.isArray(s.rails) || !s.rails.length || s.rails.some((r) => !(RAILS as readonly unknown[]).includes(r))) return `scope.rails must be a non-empty subset of ${RAILS.join(", ")}`;
  if (!isUint(m.step_up_over)) return "step_up_over must be an integer in minor units";
  if (typeof m.status !== "string" || !/^https:\/\/[^\s]+$/.test(m.status)) return "status must be an https URL";
  if (Object.hasOwn(m, "ap2") && !(isObj(m.ap2) && exactKeys(m.ap2, ["checkout_mandate_hash"]) && (m.ap2.checkout_mandate_hash === null || typeof m.ap2.checkout_mandate_hash === "string"))) return "ap2 must be {checkout_mandate_hash: string | null}";
  const sig = m.signature;
  if (!isObj(sig) || typeof sig.device_id !== "string") return "signature must hold device_id, form, signature";
  const keys2 = sig.form === "webauthn" ? ["device_id", "form", "signature", "authenticator_data", "client_data_json"] : ["device_id", "form", "signature"];
  return signedShape(sig) ?? (exactKeys(sig, keys2) ? plainJson(m) : `signature must have exactly ${keys2.join(", ")}`);
}

/** SHA-256 of `mandate/1|*|` + the RFC 8785 form of the mandate without its signature. The `*` is the verifier scope: any merchant may rely on it. */
export function mandateDigest(m: unknown): Uint8Array {
  if (!isObj(m)) throw new OpenEntityError("invalid_input", "mandate must be an object");
  const { signature: _s, ...body } = m;
  return sha256Sync("mandate/1|*|" + canonicalize(body));
}

export interface MandateOptions {
  /** The issuer's verified key log (verifyKeyLog's state). */
  keyLog: Pick<KeyLogState, "did" | "approvers" | "closed">;
  /** The agent presenting the mandate (from the verified request signature). Omit only to inspect a mandate. */
  agentDid?: string;
  /** Unix seconds; defaults to the clock. */
  now?: number;
  /** The answer of the mandate's status URL, fetched by the caller (max-age 60 or less). Without it a mandate is accepted only if it expires within a day. */
  status?: MandateStatus;
  origins?: string[];
  rpId?: string;
}

/** Verifies a mandate/1 against the issuer's key log. Revocation is `status`; spend accounting stays with the enforcing product. */
export function verifyMandate(mandate: unknown, o: MandateOptions): MandateResult {
  try {
    if (!isObj(mandate)) fail("malformed", "mandate must be an object");
    const m = mandate as Obj;
    if (m.version !== "mandate/1") fail("bad_version", `version ${String(m.version)} is not mandate/1`);
    const bad = mandateFieldsError(m);
    if (bad) fail("malformed", bad);
    const md = m as unknown as Mandate;
    const now = o.now ?? Math.floor(Date.now() / 1000);
    if (md.issuer_did !== o.keyLog.did) fail("wrong_owner", "the mandate names another owner");
    if (o.keyLog.closed) fail("owner_closed", "the owner's key log is closed");
    if (o.agentDid !== undefined && md.agent_did !== o.agentDid) fail("wrong_agent", "the mandate is for another agent");
    if (now < md.issued_at) fail("not_yet_valid", "the mandate is issued in the future");
    if (now >= md.expires_at) fail("expired", "the mandate expired");
    const cred = o.keyLog.approvers.find((c) => c.kid === md.signature.device_id);
    if (!cred) fail("unknown_key", "device_id is not a current approver in the owner's key log");
    const rpId = o.rpId ?? RP_ID;
    checkSignature(cred!, md.signature, mandateDigest(md), { origins: o.origins ?? [`https://${rpId}`], rpId, lowS: false });
    if (o.status !== undefined) {
      const st = o.status as Obj;
      // A status answer that is not exactly what section 2.2 says is no answer: it never lets a mandate through.
      if (!isObj(st) || !["active", "revoked", "exhausted"].includes(st.status as string) || (st.mandate_id !== undefined && st.mandate_id !== md.mandate_id)
        || (st.period_spent !== undefined && !isUint(st.period_spent)) || (st.total_spent !== undefined && !isUint(st.total_spent))) fail("status_required", "the status answer is malformed or for another mandate");
      if (st.status === "revoked") fail("revoked", "the owner revoked the mandate");
      if (st.status === "exhausted") fail("exhausted", "the mandate is spent");
    } else if (md.expires_at - now > DAY) fail("status_required", "a mandate with more than a day left needs a fresh status answer");
    return { ok: true, kid: cred!.kid, mandate_id: md.mandate_id, limits: md.limits, scope: md.scope, step_up_over: md.step_up_over, period_spent: o.status?.period_spent, total_spent: o.status?.total_spent };
  } catch (x) {
    if (x instanceof Fail) return { ok: false, error: x.code as MandateError, message: x.message };
    throw x;
  }
}

const HOST = /^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:\d+)?$/;
/** The host of a did:web DID, lowercase, without port; null for other methods and for anything that is not a plain hostname (%2F, %23, %3F, a bad escape). */
function didHost(did: string): string | null {
  if (!did.startsWith("did:web:")) return null;
  let d: string;
  try { d = decodeURIComponent(did.slice(8).split(":")[0]).toLowerCase(); } catch { return null; }
  return HOST.test(d) ? d.split(":")[0] : null;
}
function merchantAllowed(patterns: string[], merchant: string): boolean {
  if (!patterns.length) return true;
  const host = didHost(merchant);
  return patterns.some((p) => {
    if (p === merchant) return true;
    if (p.startsWith("did:") || !host) return false;
    const d = p.toLowerCase();
    return d.startsWith("*.") ? host.endsWith(d.slice(1)) : host === d;
  });
}

export type CoverReason = "bad_cart" | "wrong_agent" | "wrong_mandate" | "wrong_currency" | "out_of_scope" | "over_limit";
export interface CoverOptions { spent?: { period_spent?: number; total_spent?: number } }
/** Whether a verified mandate allows this cart. `step_up_required` means the cart fits but is above `step_up_over`: the owner must approve this exact cart (approval/2.0 over `cartDigest`). */
export function mandateCovers(mandate: Pick<Mandate, "mandate_id" | "agent_did" | "limits" | "scope" | "step_up_over">, cart: unknown, o: CoverOptions = {}): { ok: boolean; step_up_required: boolean; reason?: CoverReason; detail?: string } {
  const no = (reason: CoverReason, detail: string) => ({ ok: false, step_up_required: false, reason, detail });
  const bad = cartError(cart);
  if (bad) return no("bad_cart", bad);
  const c = cart as Cart, { limits: l, scope: s } = mandate;
  if (c.agent_did !== mandate.agent_did) return no("wrong_agent", "the cart is for another agent");
  if (c.mandate_id !== null && c.mandate_id !== mandate.mandate_id) return no("wrong_mandate", "the cart names another mandate");
  if (c.currency !== l.currency) return no("wrong_currency", `the mandate is in ${l.currency}`);
  if (!s.rails.includes(c.rail)) return no("out_of_scope", `rail ${c.rail} is not in scope`);
  if (!merchantAllowed(s.merchants, c.merchant)) return no("out_of_scope", `merchant ${c.merchant} is not in scope`);
  if (s.categories?.length && c.lines.some((x) => !x.category || !s.categories!.includes(x.category))) return no("out_of_scope", "a line is outside the categories");
  const sp = o.spent ?? {};
  if ((sp.period_spent !== undefined && !isUint(sp.period_spent)) || (sp.total_spent !== undefined && !isUint(sp.total_spent))) return no("over_limit", "spent must be unsigned integers");
  if (c.total > l.per_tx_max) return no("over_limit", "per_tx_max");
  if ((sp.period_spent ?? 0) + c.total > l.period_max) return no("over_limit", "period_max");
  if ((sp.total_spent ?? 0) + c.total > l.total_max) return no("over_limit", "total_max");
  return { ok: true, step_up_required: c.total > mandate.step_up_over };
}

// ---------------------------------------------------------------- receipt/1

export type Party = "merchant" | "agent";
export interface Receipt {
  version: "receipt/1"; receipt_id: string; kind: "purchase" | "refund" | "chargeback"; refers_to: string | null; merchant_did: string; agent_did: string;
  mandate_id: string | null; mandate_hash: string | null; cart_digest: string; approval_request_id: string | null;
  total: number; currency: string; rail: string; settlement_ref: string; created_at: number; proofs?: (Proof & { by: Party })[];
}
const RECEIPT_KEYS = ["version", "receipt_id", "kind", "refers_to", "merchant_did", "agent_did", "mandate_id", "mandate_hash", "cart_digest", "approval_request_id", "total", "currency", "rail", "settlement_ref", "created_at"];

/** null when `r` is a well-formed receipt/1 (proofs aside), else why not. */
export function receiptError(r: unknown): string | null {
  if (!isObj(r)) return "receipt must be an object";
  const extra = Object.keys(r).filter((k) => !RECEIPT_KEYS.includes(k) && k !== "proofs");
  if (extra.length || RECEIPT_KEYS.some((k) => !Object.hasOwn(r, k))) return `receipt/1 has exactly: ${RECEIPT_KEYS.join(", ")}, proofs`;
  if (r.version !== "receipt/1") return "version must be receipt/1";
  if (typeof r.receipt_id !== "string" || !RC_ID.test(r.receipt_id)) return "receipt_id must be rc_<26 base32>";
  if (!["purchase", "refund", "chargeback"].includes(r.kind as string)) return "kind must be purchase, refund or chargeback";
  if (r.kind === "purchase" ? r.refers_to !== null : typeof r.refers_to !== "string" || !RC_ID.test(r.refers_to)) return "refers_to is null for a purchase and the purchase's receipt_id for a refund or chargeback";
  if (typeof r.merchant_did !== "string" || !DID.test(r.merchant_did) || typeof r.agent_did !== "string" || !DID.test(r.agent_did)) return "merchant_did and agent_did must be DIDs";
  if (r.merchant_did === r.agent_did) return "merchant_did and agent_did must differ";
  if (r.mandate_id !== null && !(typeof r.mandate_id === "string" && MD_ID.test(r.mandate_id))) return "mandate_id must be md_<26 base32> or null";
  if (r.mandate_hash !== null && !(typeof r.mandate_hash === "string" && HEX64.test(r.mandate_hash))) return "mandate_hash must be 64 lowercase hex or null";
  if ((r.mandate_id === null) !== (r.mandate_hash === null)) return "mandate_id and mandate_hash go together";
  if (typeof r.cart_digest !== "string" || !HEX64.test(r.cart_digest)) return "cart_digest must be 64 lowercase hex";
  if (r.approval_request_id !== null && !(typeof r.approval_request_id === "string" && /^[A-Za-z0-9:._-]{1,128}$/.test(r.approval_request_id))) return "approval_request_id must be a request id or null";
  if (!isUint(r.total) || !isUint(r.created_at)) return "total and created_at must be unsigned integers";
  if (typeof r.currency !== "string" || !CCY.test(r.currency)) return "currency must be 3 uppercase letters";
  if (!(RAILS as readonly unknown[]).includes(r.rail)) return `rail must be one of ${RAILS.join(", ")}`;
  if (typeof r.settlement_ref !== "string" || !r.settlement_ref || r.settlement_ref.length > 256) return "settlement_ref must be 1 to 256 characters";
  if (r.proofs !== undefined && !Array.isArray(r.proofs)) return "proofs must be an array";
  return plainJson(r);
}

/** Adds `by`'s eddsa-jcs-2022 proof. Both parties sign the same bytes (the receipt without `proofs`), so the buyer countersigns without seeing the merchant's proof. A did:web merchant passes its own `verificationMethod`. */
export async function signReceipt(receipt: object, kp: KeyPair, by: Party, created?: string, verificationMethod?: string): Promise<Receipt> {
  const e = receiptError(receipt);
  if (e) throw new OpenEntityError("invalid_input", e);
  const r = receipt as Receipt;
  const signer = (verificationMethod ?? verificationMethodId(kp.did)).split("#")[0];
  if (signer !== r[`${by}_did`]) throw new OpenEntityError("invalid_input", `${by}_did is not the signing key's DID`);
  if (r.proofs?.some((p) => p.by === by)) throw new OpenEntityError("invalid_input", `already signed by ${by}`);
  const proof = await signProof(r, kp, created, verificationMethod);
  return { ...r, proofs: [...(r.proofs ?? []), { by, ...proof }] };
}

const PKH = /^did:pkh:eip155:\d+:(0x[0-9a-fA-F]{40})$/;
/** What a did:pkh party's wallet signs (EIP-712 typed data, OEIS-1 4.2) to sign a receipt: the digest of {objectType: "receipt/1", canonicalHash: SHA-256 of the receipt without `proof` and `proofs`, created}. The merchant's proof does not change it, so the buyer's wallet signs a receipt the merchant already signed. */
export function receiptEip712Digest(receipt: object, created: string): Uint8Array {
  const e = receiptError(receipt);
  if (e) throw new OpenEntityError("invalid_input", e);
  return eip712Digest(eip712ObjectType(receipt), toHex(sha256Sync(canonicalize(unsecured(receipt)))), created);
}

/** Adds `by`'s EIP-712 proof, the wallet's 65-byte signature over `receiptEip712Digest(receipt, created)`. Refused unless the signature recovers to the address of `${by}_did` (a did:pkh). */
export function addReceiptEip712Proof(receipt: object, by: Party, signature: string, created: string): Receipt {
  const digest = receiptEip712Digest(receipt, created), r = receipt as Receipt, did = r[`${by}_did`];
  const address = PKH.exec(did)?.[1];
  if (!address) throw new OpenEntityError("invalid_input", `${by}_did is not a did:pkh`);
  if (r.proofs?.some((p) => p.by === by)) throw new OpenEntityError("invalid_input", `already signed by ${by}`);
  let signer = "";
  try { signer = recoverEip712(digest, signature); } catch { /* not a signature */ }
  if (signer.toLowerCase() !== address.toLowerCase()) throw new OpenEntityError("invalid_input", `the signature is not by ${by}_did`);
  const proof = { by, type: "EthereumEip712Signature2021", created, verificationMethod: `${did}#blockchainAccountId`, proofPurpose: "assertionMethod", proofValue: signature };
  return { ...r, proofs: [...(r.proofs ?? []), proof as Proof & { by: Party }] };
}

export type ReceiptError = "malformed" | "missing_proof" | "wrong_signer" | "bad_proof";
export type ReceiptResult = { ok: true; signed_by: Party[] } | { ok: false; error: ReceiptError; message: string };
/** Verifies the proofs on a receipt. `require` (default merchant only) lists who must have signed; any proof present must verify, and its signer must be the receipt's merchant_did or agent_did named by `by`. */
export async function verifyReceipt(receipt: unknown, o: { resolver?: Resolver; require?: Party[] } = {}): Promise<ReceiptResult> {
  const e = receiptError(receipt);
  if (e) return { ok: false, error: "malformed", message: e };
  const r = receipt as Receipt, signed: Party[] = [];
  for (const p of r.proofs ?? []) {
    const { by, ...proof } = p as Proof & { by: unknown };
    if ((by !== "merchant" && by !== "agent") || signed.includes(by)) return { ok: false, error: "malformed", message: "each proof names a distinct by: merchant or agent" };
    if (typeof proof.verificationMethod !== "string" || proof.verificationMethod.split("#")[0] !== r[`${by}_did`]) return { ok: false, error: "wrong_signer", message: `the ${by} proof is not by ${by}_did` };
    const v = await verifyProof(r, proof as Proof, o.resolver);
    if (!v.ok) return { ok: false, error: "bad_proof", message: `${by}: ${v.error}` };
    signed.push(by);
  }
  for (const need of o.require ?? ["merchant"]) if (!signed.includes(need)) return { ok: false, error: "missing_proof", message: `no ${need} proof` };
  return { ok: true, signed_by: signed };
}

export type ChainError = "malformed" | "not_purchase" | "mismatch" | "over_refund";
/** Structural check that refunds and chargebacks are consistent with their purchase: each refers_to the purchase, same parties, currency and rail, no repeated receipt_id, and their sum at most the purchase total. Proofs are `verifyReceipt`'s job; run both. */
export function verifyReceiptChain(purchase: unknown, later: unknown[]): { ok: true; refunded: number } | { ok: false; error: ChainError; message: string } {
  const bad = (error: ChainError, message: string) => ({ ok: false as const, error, message });
  const e = receiptError(purchase) ?? later.map(receiptError).find((x) => x);
  if (e) return bad("malformed", e);
  const p = purchase as Receipt, ids = new Set([p.receipt_id]);
  if (p.kind !== "purchase") return bad("not_purchase", "the first receipt must be a purchase");
  let refunded = 0;
  for (const x of later as Receipt[]) {
    if (x.kind === "purchase" || x.refers_to !== p.receipt_id) return bad("mismatch", "each later receipt must be a refund or chargeback of this purchase");
    if (ids.has(x.receipt_id)) return bad("mismatch", "receipt_id repeats");
    ids.add(x.receipt_id);
    if (x.merchant_did !== p.merchant_did || x.agent_did !== p.agent_did || x.currency !== p.currency || x.rail !== p.rail) return bad("mismatch", "parties, currency and rail must equal the purchase's");
    refunded += x.total;
  }
  if (refunded > p.total) return bad("over_refund", "refunds and chargebacks exceed the purchase total");
  return { ok: true, refunded };
}

// ---------------------------------------------------------------- the checkout check

export interface AgentPolicy { min_level?: number; require_owner?: boolean; require_mandate?: boolean; min_security_band?: string; accept_issuers?: string[] }
/** What the caller knows about the agent from the registry (trust()): never taken from the request. */
export interface AgentFacts { level?: number; owner_did?: string; security_band?: string; security_issuer?: string }
export interface CheckoutInput {
  /** The agent's signed HTTP request; verified here. Or `agentDid`, when the caller already verified the signature. */
  request?: { method: string; url: string; headers: Record<string, string>; body?: Uint8Array; maxAge?: number };
  agentDid?: string;
  cart: unknown;
  merchantPolicy: AgentPolicy;
  agent?: AgentFacts;
  mandate?: unknown;
  /** The mandate issuer's key log, and the mandate status answer. */
  keyLog?: Pick<KeyLogState, "did" | "root" | "approvers" | "closed">;
  status?: MandateStatus;
  /** The owner's per-cart approval/2.0 for this exact cart: `verifierDid` and `requestId` are the merchant's own. */
  approval?: { approval: unknown; verifierDid: string; requestId: string; /** The WebAuthn counter stored for the signing key; store `evidence.approval_counter` after an allow. */ counter?: number };
  /** An organisation-owned purchase: the `approvals[]` bundle, checked by verifyQuorum against the org's key log (`mandate.issuer_did`) and the policy `m` and `of` that the org's account service published (GET /o/<id>/policy). Store `evidence.approval_counters` after an allow. */
  quorum?: { approvals: unknown; m: number; of: string[]; verifierDid: string; requestId: string; counters?: Record<string, number> };
  now?: number;
  origins?: string[];
}
export interface CheckoutDecision { decision: "allow" | "step_up" | "deny"; reasons: string[]; evidence: Obj }

/** The one-call check behind Agent Commerce Check: agent, owner, mandate, cart and merchant policy in, `allow`, `step_up` or `deny` with reasons out. Deny is final (bad signature, wrong agent, dead mandate, policy unmet); step_up means an owner approval of this exact cart would allow. */
export async function verifyAgentForCheckout(i: CheckoutInput): Promise<CheckoutDecision> {
  const now = i.now ?? Math.floor(Date.now() / 1000), evidence: Obj = {};
  const deny = (...reasons: string[]): CheckoutDecision => ({ decision: "deny", reasons, evidence });
  const cartBad = cartError(i.cart);
  if (cartBad) return deny("bad_cart");
  const cart = i.cart as Cart, pol = i.merchantPolicy ?? {};
  let agent = i.agentDid;
  if (i.request) {
    try {
      agent = (await verifyRequest({ ...i.request, now })).did;
      evidence.request = "verified";
    } catch {
      return deny("request_unverified");
    }
  }
  if (!agent) return deny("request_unverified");
  evidence.agent_did = agent;
  if (cart.agent_did !== agent) return deny("agent_mismatch");

  // Merchant policy on the agent itself.
  const f = i.agent ?? {};
  const reasons: string[] = [];
  if (pol.min_level !== undefined && !((f.level ?? -1) >= pol.min_level)) reasons.push("level_too_low");
  if (pol.min_security_band !== undefined) {
    const need = BANDS.indexOf(pol.min_security_band), got = BANDS.indexOf(f.security_band ?? "");
    if (got < 0 || got < need) reasons.push("security_band_too_low");
    else if (pol.accept_issuers?.length && !pol.accept_issuers.includes(f.security_issuer ?? "")) reasons.push("issuer_not_accepted");
  }

  // Mandate.
  let owner = f.owner_did, covered: ReturnType<typeof mandateCovers> | undefined;
  if (i.mandate !== undefined) {
    if (!i.keyLog) return deny("no_key_log");
    const v = verifyMandate(i.mandate, { keyLog: i.keyLog, agentDid: agent, now, status: i.status, origins: i.origins });
    if (!v.ok) return deny(`mandate_${v.error}`);
    owner = (i.mandate as Mandate).issuer_did;
    evidence.mandate_id = v.mandate_id;
    evidence.mandate_hash = toHex(mandateDigest(i.mandate));
    covered = mandateCovers(i.mandate as Mandate, cart, { spent: i.status });
    if (!covered.ok && covered.reason !== "over_limit" && covered.reason !== "out_of_scope") return deny(`mandate_${covered.reason}`);
  } else if (pol.require_mandate) reasons.push("mandate_required");
  if (pol.require_owner && !owner) reasons.push("owner_unknown");
  if (reasons.length) return deny(...reasons);

  // Per-cart approval: needed when there is no mandate, the mandate does not cover the cart, or the cart is over step_up_over.
  const needApproval = !covered || !covered.ok || covered.step_up_required;
  if (!needApproval) return { decision: "allow", reasons: ["mandate_covers_cart"], evidence };
  const why = !covered ? "no_mandate" : !covered.ok ? `mandate_${covered.reason}` : "step_up_over";
  if (i.quorum && i.keyLog && owner) {
    const q = verifyQuorum(i.quorum.approvals, { keyLog: i.keyLog, verifierDid: i.quorum.verifierDid, ownerDid: owner, requestId: i.quorum.requestId, payloadDigest: cartDigest(cart), now, origins: i.origins, m: i.quorum.m, of: i.quorum.of, counters: i.quorum.counters });
    if (q.ok) {
      evidence.approval_request_id = i.quorum.requestId;
      evidence.approval_kids = q.kids;
      evidence.approval_counters = q.counters;
      return { decision: "allow", reasons: ["owner_approved_cart", why], evidence };
    }
    evidence.approval_error = q.error;
  } else if (i.approval && i.keyLog && owner) {
    const a = verifyApproval(i.approval.approval, { keyLog: i.keyLog, verifierDid: i.approval.verifierDid, ownerDid: owner, requestId: i.approval.requestId, payloadDigest: cartDigest(cart), decisions: ["approve"], now, origins: i.origins, counter: i.approval.counter });
    if (a.ok) {
      evidence.approval_request_id = i.approval.requestId;
      evidence.approval_kid = a.kid;
      evidence.approval_counter = a.counter;
      return { decision: "allow", reasons: ["owner_approved_cart", why], evidence };
    }
    evidence.approval_error = (a as { error: ApprovalError }).error;
  }
  return { decision: "step_up", reasons: [why], evidence };
}
