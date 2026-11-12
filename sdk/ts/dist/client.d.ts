import { type KeyPair } from "./core.ts";
/** The registry every call uses unless given another. */
export declare const DEFAULT_REGISTRY = "https://openentity.org";
/** Withdraw the Declaration (spec 6.3). Irreversible: the EID stays in the log, marked withdrawn. `name` defaults to the registered one. */
export declare function withdraw(kp: KeyPair, o?: {
    registry?: string;
    name?: string;
}): Promise<any>;
/**
 * Append `[kind, payload]` entries to the Development Record, chained from the registry's head (seq + 1, prev = hash of the last
 * entry), and push them in batches of up to 100 (spec 7.4).
 */
export declare function record(kp: KeyPair, entries: [string, object][], o?: {
    registry?: string;
}): Promise<{
    accepted: number;
    entries: object[];
}>;
/** The reasons a Dispute may give (spec 10.5). */
export declare const DISPUTE_REASONS: readonly ["impersonation", "illegal_content", "inaccurate", "other"];
export type DisputeReason = (typeof DISPUTE_REASONS)[number];
/** File a signed Dispute about `subject`, or about one of its objects (spec 10.5). */
export declare function dispute(kp: KeyPair, o: {
    subject: string;
    reason: DisputeReason;
    statement: string;
    objectSha256?: string;
    registry?: string;
}): Promise<any>;
/** Directory search (spec 10.5). */
export declare function find(o?: {
    registry?: string;
    capability?: string;
    q?: string;
    aliasType?: string;
    level?: string;
}): Promise<any>;
/** Answer a verifier's challenge (spec 4.7). With a registry, carries the entity's current attestations (at most 20). */
export declare function present(kp: KeyPair, o: {
    audience: string;
    nonce: string;
    registry?: string;
}): Promise<object>;
