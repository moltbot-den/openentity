import { type KeyPair } from "./core.ts";
/** A KeyPair, or anything that holds one as `kp` (Identity from "@openentity/sdk/node"). */
export type Signer = KeyPair | {
    kp: KeyPair;
};
/** A product key for tools that still need one (PLAN 8.4): issued for 30 days, scoped to the granted permissions. */
export interface BearerCredential {
    product: string;
    kind: "bearer";
    key: string;
    expires_at: number;
}
export interface Paired {
    pairingId: string;
    ownerDid: string;
    permissions: string[];
    credentials: BearerCredential[];
    match: string[];
}
/** What the owner's channel delivers: a message, a command (checkup, fix, pause, resume), an approval result or new permissions. */
export interface InboxItem {
    type: "message" | "command" | "approval.result" | "permissions";
    id: string;
    created_at: number;
    [field: string]: unknown;
}
export type AgentState = "running" | "idle" | "blocked" | "error" | "done";
/**
 * Pair this agent with its owner (PLAN 8.1). `code` is the `OE-XXXX-XXXX` code the owner's app shows. Signs a Presentation
 * (audience = the account service DID, nonce = the code) into `POST /v1/pair`, checks that the service's match items equal the
 * ones computed here from this agent's own DID (else it refuses: a service must not be able to substitute another agent), hands
 * them to `onMatch` (default: prints `Match: ...`), then polls until the owner confirms, rejects or the code expires.
 * Errors: `pairing_rejected`, `pairing_expired`, `verification_failed` (match mismatch) or the service's code (`code_unknown`,
 * `code_used`, `code_expired`, ...). Bearer credentials appear only in this result: store them (PLAN 8.4).
 */
export declare function pair(code: string, o: {
    identity: Signer;
    framework?: string;
    sdk?: string;
    sdkVersion?: string;
    host?: string;
    account?: string;
    onMatch?: (names: string[]) => void | Promise<void>;
}): Promise<Paired>;
export interface Listener {
    close(): void;
    /** true after the service closed the socket with 4001 or sent a pause command, until a resume command arrives. */
    readonly paused: boolean;
    readonly mode: "socket" | "poll" | "closed";
}
/** The paired agent's channel to its owner. Construct it from the same key that paired; every call is RFC 9421-signed. */
export declare class Owner {
    #private;
    readonly did: string;
    readonly account: string;
    constructor(identity: Signer, o?: {
        account?: string;
    });
    /** Message the owner (at most 4096 UTF-8 bytes; 60 an hour). `attachments` are upload ids from POST /v1/agent/uploads. */
    message(text: string, o?: {
        attachments?: string[];
    }): Promise<{
        id: string;
    }>;
    /** Report what the agent is doing; the owner's app shows it (Live Activity). `progress` is 0 to 1. */
    status(s: {
        state: AgentState;
        summary: string;
        progress?: number;
    }): Promise<void>;
    /**
     * Ask the owner to approve something. The app labels it "Written by the agent" and no product accepts it as an approval of its
     * own: it is the owner's answer to this agent only. `expiresIn` is 60 to 600 seconds (default 600). With `wait`, polls every
     * 5 seconds until the owner decides or it expires, and returns the final state.
     */
    askApproval(a: {
        title: string;
        summary: string;
        risk: "low" | "medium" | "high";
        expiresIn?: number;
        details?: object;
    }, o?: {
        wait?: boolean;
    }): Promise<any>;
    /** Unacknowledged items, oldest first (up to 100), acknowledged on return unless `ack` is false. At most once every 15 seconds. */
    inbox(o?: {
        ack?: boolean;
    }): Promise<{
        items: InboxItem[];
        more: boolean;
    }>;
    /** New product keys for the agent (PLAN 8.4); the old ones stay valid for 1 hour. Default: every product it holds a key for. */
    renewCredentials(products?: string[]): Promise<BearerCredential[]>;
    /**
     * Receive the owner's channel (PLAN 8.2): every item (commands, messages, approval results, permissions) goes to `handler`,
     * one at a time, and is acknowledged once the handler returns; a handler that throws leaves it for the next delivery. Holds
     * the WebSocket at wss://agents.<account host>/ (signed connect, heartbeat every 9 minutes, a fresh socket before the 2-hour
     * limit, backoff on drops). When no socket opens three times running, or there is no WebSocket, it polls
     * GET /v1/agent/messages every 15 seconds and tries the socket again after 10 minutes. Close 4001 means paused (`onPaused`);
     * 4003 (unlinked) and 4008 (another socket of this agent took over) end it. `WebSocket` must send headers on the upgrade, as
     * Node's built-in one does; pass `WebSocket: null` to poll only.
     */
    onCommand(handler: (item: InboxItem) => void | Promise<void>, o?: {
        onPaused?: () => void;
        onError?: (e: unknown) => void;
        WebSocket?: unknown;
        url?: string;
    }): Listener;
}
