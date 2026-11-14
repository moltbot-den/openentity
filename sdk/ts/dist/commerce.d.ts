import { type KeyPair, type Resolver, type Proof } from "./core.ts";
import { type KeyLogState } from "./owner.ts";
export declare const RAILS: readonly ["card", "x402", "mpp", "credits", "usdc"];
type Obj = Record<string, unknown>;
export interface Limits {
    currency: string;
    per_tx_max: number;
    period: string;
    period_max: number;
    total_max: number;
}
export interface Scope {
    merchants: string[];
    categories?: string[];
    rails: string[];
}
export interface Mandate {
    version: "mandate/1";
    mandate_id: string;
    issuer_did: string;
    agent_did: string;
    issued_at: number;
    expires_at: number;
    limits: Limits;
    scope: Scope;
    step_up_over: number;
    status: string;
    ap2?: {
        checkout_mandate_hash: string | null;
    };
    signature: {
        device_id: string;
        form: "p256" | "webauthn";
        signature: string;
        authenticator_data?: string;
        client_data_json?: string;
    };
}
export interface CartLine {
    sku: string;
    title: string;
    qty: number;
    unit: number;
    category?: string;
}
export interface Cart {
    profile: "cart/1";
    merchant: string;
    agent_did: string;
    lines: CartLine[];
    total: number;
    currency: string;
    rail: string;
    mandate_id: string | null;
}
export type MandateError = "malformed" | "bad_version" | "wrong_owner" | "owner_closed" | "wrong_agent" | "not_yet_valid" | "expired" | "unknown_key" | "bad_signature" | "bad_webauthn" | "revoked" | "exhausted" | "status_required";
export type MandateStatus = {
    status: "active" | "revoked" | "exhausted";
    period_spent?: number;
    total_spent?: number;
};
export type MandateResult = {
    ok: true;
    kid: string;
    mandate_id: string;
    limits: Limits;
    scope: Scope;
    step_up_over: number;
    period_spent?: number;
    total_spent?: number;
} | {
    ok: false;
    error: MandateError;
    message: string;
};
/** null when `c` is a well-formed cart/1 summary, else why not. */
export declare function cartError(c: unknown): string | null;
/** Lowercase hex payload digest of a cart/1 summary: the `payload_digest` of the approval/2.0 that approves this purchase. */
export declare function cartDigest(cart: unknown): string;
/** SHA-256 of `mandate/1|*|` + the RFC 8785 form of the mandate without its signature. The `*` is the verifier scope: any merchant may rely on it. */
export declare function mandateDigest(m: unknown): Uint8Array;
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
export declare function verifyMandate(mandate: unknown, o: MandateOptions): MandateResult;
export type CoverReason = "bad_cart" | "wrong_agent" | "wrong_mandate" | "wrong_currency" | "out_of_scope" | "over_limit";
export interface CoverOptions {
    spent?: {
        period_spent?: number;
        total_spent?: number;
    };
}
/** Whether a verified mandate allows this cart. `step_up_required` means the cart fits but is above `step_up_over`: the owner must approve this exact cart (approval/2.0 over `cartDigest`). */
export declare function mandateCovers(mandate: Pick<Mandate, "mandate_id" | "agent_did" | "limits" | "scope" | "step_up_over">, cart: unknown, o?: CoverOptions): {
    ok: boolean;
    step_up_required: boolean;
    reason?: CoverReason;
    detail?: string;
};
export type Party = "merchant" | "agent";
export interface Receipt {
    version: "receipt/1";
    receipt_id: string;
    kind: "purchase" | "refund" | "chargeback";
    refers_to: string | null;
    merchant_did: string;
    agent_did: string;
    mandate_id: string | null;
    mandate_hash: string | null;
    cart_digest: string;
    approval_request_id: string | null;
    total: number;
    currency: string;
    rail: string;
    settlement_ref: string;
    created_at: number;
    proofs?: (Proof & {
        by: Party;
    })[];
}
/** null when `r` is a well-formed receipt/1 (proofs aside), else why not. */
export declare function receiptError(r: unknown): string | null;
/** Adds `by`'s eddsa-jcs-2022 proof. Both parties sign the same bytes (the receipt without `proofs`), so the buyer countersigns without seeing the merchant's proof. A did:web merchant passes its own `verificationMethod`. */
export declare function signReceipt(receipt: object, kp: KeyPair, by: Party, created?: string, verificationMethod?: string): Promise<Receipt>;
export type ReceiptError = "malformed" | "missing_proof" | "wrong_signer" | "bad_proof";
export type ReceiptResult = {
    ok: true;
    signed_by: Party[];
} | {
    ok: false;
    error: ReceiptError;
    message: string;
};
/** Verifies the proofs on a receipt. `require` (default merchant only) lists who must have signed; any proof present must verify, and its signer must be the receipt's merchant_did or agent_did named by `by`. */
export declare function verifyReceipt(receipt: unknown, o?: {
    resolver?: Resolver;
    require?: Party[];
}): Promise<ReceiptResult>;
export interface AgentPolicy {
    min_level?: number;
    require_owner?: boolean;
    require_mandate?: boolean;
    min_security_band?: string;
    accept_issuers?: string[];
}
/** What the caller knows about the agent from the registry (trust()): never taken from the request. */
export interface AgentFacts {
    level?: number;
    owner_did?: string;
    security_band?: string;
    security_issuer?: string;
}
export interface CheckoutInput {
    /** The agent's signed HTTP request; verified here. Or `agentDid`, when the caller already verified the signature. */
    request?: {
        method: string;
        url: string;
        headers: Record<string, string>;
        body?: Uint8Array;
        maxAge?: number;
    };
    agentDid?: string;
    cart: unknown;
    merchantPolicy: AgentPolicy;
    agent?: AgentFacts;
    mandate?: unknown;
    /** The mandate issuer's key log, and the mandate status answer. */
    keyLog?: Pick<KeyLogState, "did" | "root" | "approvers" | "closed">;
    status?: MandateStatus;
    /** The owner's per-cart approval/2.0 for this exact cart: `verifierDid` and `requestId` are the merchant's own. */
    approval?: {
        approval: unknown;
        verifierDid: string;
        requestId: string;
    };
    now?: number;
    origins?: string[];
}
export interface CheckoutDecision {
    decision: "allow" | "step_up" | "deny";
    reasons: string[];
    evidence: Obj;
}
/** The one-call check behind Agent Commerce Check: agent, owner, mandate, cart and merchant policy in, `allow`, `step_up` or `deny` with reasons out. Deny is final (bad signature, wrong agent, dead mandate, policy unmet); step_up means an owner approval of this exact cart would allow. */
export declare function verifyAgentForCheckout(i: CheckoutInput): Promise<CheckoutDecision>;
export {};
