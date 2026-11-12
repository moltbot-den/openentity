import { type KeyPair, type Resolver } from "./core.ts";
/**
 * Rotate `previous` to a new key in one call: fetch the current document, build and sign the link, mint the stamp for the
 * successor and submit. Nothing is persisted: on success the caller saves `successor` (its `privateJwk`) and only then retires
 * the old key. Throws on any non-2xx answer.
 */
export declare function rotate(o: {
    previous: KeyPair;
    registry?: string;
    successor?: KeyPair;
    basis?: "rotation" | "migration";
}): Promise<{
    successor: KeyPair;
    link: Record<string, any>;
    document: Record<string, any>;
    response: any;
}>;
/** The registry's allowlist for the unsigned `client` label on POST /v1/adopt. */
export declare const CLIENTS: readonly ["adk", "crewai", "goose", "langchain", "mastra", "moltbotden", "openai-agents", "ui-tars", "vercel-ai", "cli", "other"];
export type Client = (typeof CLIENTS)[number];
/** @internal */
export declare function registryJson(url: string, init?: RequestInit): Promise<any>;
/** Adopt `kp` on a registry: document, Declaration and the seq-1 declaration entry (spec 5.2, 6.2, 7.3). `client` is not signed. */
export declare function adopt(kp: KeyPair, o: {
    name: string;
    description?: string;
    registry?: string;
    client?: Client;
}): Promise<{
    response: any;
    did: string;
    document: object & {
        proof: import("./core.ts").Proof;
    };
    declaration: object & {
        proof: import("./core.ts").Proof;
    };
    recordEntry: {
        spec: string;
        type: string;
        eid: string;
        seq: number;
        prev: null;
        kind: string;
        at: string;
        payload: {
            declaration_version: string;
            sha256: string;
        };
    } & {
        proof: import("./core.ts").Proof;
    };
    recordPushed: boolean;
}>;
/** @internal */
export declare const MOLTBOTDEN = "did:web:moltbotden.com", CLAWGRC = "did:web:api.clawgrc.com";
/** @internal */
export declare const SMA: string[];
/** @internal */
export declare const TIER = "trust_tier", POSTURE = "custom:securemyagent:security_posture", VIOLATION = "custom:clawgrc:violation";
/** claim_type to the issuers whose attestations are read; everything else is ignored. @internal */
export declare const ACCEPT: Record<string, string[]>;
/** @internal */
export declare const TRUST_CACHE_MS = 300000;
export interface TrustReport {
    eid: string;
    /** false: a read failed or a signature did not verify. Treat the entity as untrusted. */
    ok: boolean;
    error?: string;
    level?: string;
    withdrawn: boolean;
    /** issuer DID to its newest live tier (0 to 4) */
    trustTier: Record<string, number>;
    /** claim of the newest live custom:securemyagent:security_posture */
    securityPosture: Record<string, any> | null;
    /** live custom:clawgrc:violation */
    violations: {
        issuer: string;
        severity: string;
        policy: string;
        observed_at: string;
        sha256: string;
    }[];
    /** verified revocations of the accepted attestations */
    revocations: {
        sha256: string;
        claim_type: string;
        issuer: string;
        reason?: string;
        at: string;
    }[];
}
/** @internal */
export type FetchJson = (url: string) => Promise<any>;
/** @internal */
export declare const trustCache: Map<string, {
    at: number;
    report: TrustReport;
}>;
export declare const clearTrustCache: () => void;
/** did:web through /.well-known/did.json (or <path>/did.json); everything else offline. */
export declare function didWebResolver(fetchJson?: FetchJson): Resolver;
/**
 * One TrustReport from `GET /v1/entities/{eid}` and `/attestations` only. Every attestation and revocation from the accepted
 * issuers is verified locally against the issuer's key; any failure returns an untrusted report. Cached for 5 minutes.
 */
export declare function trust(eid: string, o?: {
    registry?: string;
    now?: Date;
    fetchJson?: FetchJson;
    resolver?: Resolver;
}): Promise<TrustReport>;
/** @internal */
export declare function readTrust(eid: string, base: string, now: number, get: FetchJson, resolver: Resolver): Promise<TrustReport>;
