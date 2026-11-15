/** @internal */
export declare const RP_ID = "account.openentity.org";
/** @internal */
export declare const DAY = 86400;
/** @internal */
export declare const HEX64: RegExp;
/** @internal */
export declare const DID: RegExp;
/** A key in an owner key log: a device P-256 key (`p256`) or a passkey (`webauthn`). Descriptive fields (label, platform, attestation) pass through. */
export interface Credential {
    kid: string;
    type: "p256" | "webauthn";
    jwk: {
        kty: "EC";
        crv: "P-256";
        x: string;
        y: string;
    };
    credential_id?: string;
    rp_id?: string;
    [field: string]: unknown;
}
/** The verified state of an owner key log as of `now`. `approvers` are the keys that may sign approval/2.0 now: the root passkey alone while it is the log's only credential. */
export interface KeyLogState {
    did: string;
    seq: number;
    head: string;
    root: Credential;
    approvers: Credential[];
    revoked: {
        kid: string;
        at: number;
    }[];
    pending: {
        seq: number;
        op: "recover" | "replace_root";
        hash: string;
        effective_at: number;
    }[];
    closed: boolean;
}
export type KeyLogError = "malformed" | "bad_first_seen" | "closed" | "bad_seq" | "bad_prev" | "did_mismatch" | "bad_target" | "key_reused" | "unauthorized" | "bad_signature" | "bad_webauthn";
export type KeyLogResult = {
    ok: true;
    state: KeyLogState;
} | {
    ok: false;
    error: KeyLogError;
    seq: number;
    message: string;
};
export type ApprovalError = "malformed" | "bad_version" | "wrong_verifier" | "wrong_owner" | "owner_closed" | "wrong_request" | "wrong_payload" | "bad_decision" | "expired" | "expiry_too_far" | "unknown_key" | "bad_signature" | "bad_webauthn" | "counter_replayed";
export type ApprovalResult = {
    ok: true;
    kid: string;
    counter: number;
} | {
    ok: false;
    error: ApprovalError;
    message: string;
};
/** @internal shared with commerce.ts */
export declare class Fail {
    code: string;
    message: string;
    constructor(code: string, message: string);
}
/** @internal */
export declare const fail: (code: string, message: string) => never;
type Obj = Record<string, unknown>;
/** @internal */
export declare const isObj: (v: unknown) => v is Obj;
/** @internal */
export declare const exactKeys: (o: Obj, keys: string[]) => boolean;
/** @internal */
export declare const isUint: (v: unknown) => v is number;
/** Strict base64url: no padding, and only the one encoding of the bytes (re-encoding gives the same string). */
/** @internal */
export declare function b64u(s: unknown): Uint8Array | null;
/** Only safe integers (unless `ints` is false), well-formed strings and at most 64 nested containers, so all four SDKs read an entry, a summary or client data the same way. */
/** @internal */
export declare function plainJson(v: unknown, ints?: boolean, depth?: number): string | null;
/** @internal */
export interface SigOptions {
    origins: string[];
    rpId: string;
    lowS: boolean;
}
/** @internal */
export interface Signed {
    form: unknown;
    signature: unknown;
    authenticator_data?: unknown;
    client_data_json?: unknown;
}
/** Checks a p256 or webauthn signature by `cred` over `digest`; returns the WebAuthn signature counter (0 for p256). */
/** @internal */
export declare function checkSignature(cred: Credential, s: Signed, digest: Uint8Array, o: SigOptions): number;
/** Shape of the signature fields shared by approvals and key log `auth`. */
/** @internal */
export declare function signedShape(s: Obj): string | null;
/** ADR 0008: SHA-256 of `approval/2.0|verifier_did|owner_did|request_id|payload_digest|decision|expires_at`. Takes the approval object or the request fields. */
export declare function approvalDigest(a: {
    verifier_did: string;
    owner_did: string;
    request_id: string;
    payload_digest: string;
    decision: string;
    expires_at: number;
}): Uint8Array;
/** Lowercase hex SHA-256 of the RFC 8785 form of the summary the owner saw. Numbers must be integers within 2^53 (put amounts in minor units or strings). */
export declare function payloadDigest(summary: unknown): string;
export interface ApprovalOptions {
    /** The owner's verified key log (from verifyKeyLog), or at least its did, root, approvers and closed flag. */
    keyLog: Pick<KeyLogState, "did" | "root" | "approvers" | "closed">;
    /** This verifier's own DID. */
    verifierDid: string;
    /** The principal that owns the action. */
    ownerDid: string;
    /** The id this verifier issued for the action's current state, and the payload digest it recomputes now. Never the client's. */
    requestId: string;
    payloadDigest: string;
    /** Unix seconds; defaults to the clock. */
    now?: number;
    /** Decisions this action accepts; default both. */
    decisions?: string[];
    /** Accepted WebAuthn origins; default `https://<rpId>`. Add the Android app's `android:apk-key-hash:` origin. */
    origins?: string[];
    rpId?: string;
    /** The WebAuthn signature counter stored for this key; store the returned one. */
    counter?: number;
    /** Also accept the log's root passkey (WebAuthn). Off by default; only account-service flows turn it on, such as cancelling a deletion request. Revoked approvers never sign approvals. */
    allowRoot?: boolean;
}
/** Verifies an approval/2.0 object against the owner's key log. Rejects approval/1.0. */
export declare function verifyApproval(approval: unknown, o: ApprovalOptions): ApprovalResult;
export type QuorumError = ApprovalError | "bad_quorum" | "quorum_not_met" | "duplicate_device" | "not_in_quorum";
export type QuorumResult = {
    ok: true;
    kids: string[];
    counters: Record<string, number>;
} | {
    ok: false;
    error: QuorumError;
    message: string;
};
export interface QuorumOptions extends Omit<ApprovalOptions, "counter" | "decisions"> {
    /** Approvals needed, and the kids that may count: the policy the organisation's account service published (GET /o/<id>/policy). */
    m: number;
    of: string[];
    /** Stored WebAuthn counters by kid; the result returns the new ones. */
    counters?: Record<string, number>;
}
/**
 * Verifies the `approvals[]` bundle of an organisation-owned action: at least `m` approval/2.0 objects, each by a different
 * device in `of`, each approving this request_id and payload_digest against the organisation's key log. Fails closed: one
 * bad or duplicate approval refuses the bundle, so a client cannot pad it. Devices, not people: the account service lists
 * one device per member in `of`, which is what makes m devices m members.
 */
export declare function verifyQuorum(approvals: unknown, o: QuorumOptions): QuorumResult;
export interface KeyLogOptions {
    /** Unix seconds; defaults to the clock. Pending operations whose 24 hours have run by `now` take effect. */
    now?: number;
    /** The account service's close keys, which sign `close`: every P-256 assertionMethod key in did:web:account.openentity.org's did.json, current and retired. Never the token keys in jwks.json. */
    serviceKeys?: {
        kty: "EC";
        crv: "P-256";
        x: string;
        y: string;
    }[];
    /** Accepted WebAuthn origins; default `https://<rpId>`. Add the Android app's `android:apk-key-hash:` origin. */
    origins?: string[];
    rpId?: string;
}
/**
 * Verifies an owner key log (JSON Lines, one RFC 8785 entry per line) against the owner DID it must hash to.
 * `firstSeenAt[i]` is when this verifier first held entry i with its whole chain (unix seconds, never decreasing): every delay
 * runs from it, never from the entry's `ts`. Returns the state as of `now`, or the first failing entry's seq and rule.
 */
export declare function verifyKeyLog(did: string, lines: string[], firstSeenAt: number[], opts?: KeyLogOptions): KeyLogResult;
export {};
