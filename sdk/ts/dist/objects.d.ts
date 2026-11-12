import { Validator } from "@cfworker/json-schema";
import { type KeyPair, type Resolver } from "./core.ts";
/** @internal */
export declare const NOT_STATED = "Not yet stated.";
/** Unsigned Entity Document with spec 5.2 defaults. `extra` is merged last (endpoints, aliases, declaration, ...). */
export declare function buildDocument(input: {
    kp: KeyPair;
    name: string;
    description: string;
    operator?: object;
    substrate?: object;
    layers?: object;
    created?: string;
    seq?: number;
    extra?: object;
}): object;
export declare function buildDeclaration(input: {
    eid: string;
    name: string;
    created?: string;
}): object;
/** The successor's unsigned seq 1 Entity Document: `prev` re-keyed, aliases dropped (their proofs name the old EID), `continuity.previous` set. */
export declare function successorDocument(prev: Record<string, any>, next: KeyPair, created?: string): Record<string, any>;
/** A Continuity Link signed by both keys (spec 9.2) plus the successor's document signed by the successor: the body of `POST /v1/continuity`. */
export declare function buildRotation(previous: KeyPair, successor: KeyPair, document: Record<string, any>, o?: {
    basis?: "rotation" | "migration";
    created?: string;
    nonce?: string;
}): Promise<{
    link: Record<string, any>;
    document: Record<string, any>;
}>;
/** sha256 hex of the canonical entry INCLUDING its proof: the next entry's `prev` (spec 7.4). */
export declare function recordEntryHash(entry: object): Promise<string>;
/** @internal */
export type ObjectType = "EntityDocument" | "Declaration" | "Withdrawal" | "Redaction" | "RecordEntry" | "Attestation" | "Revocation" | "ContinuityLink" | "Dispute" | "Presentation" | "LogLeaf";
/** @internal */
export declare const BUNDLE_ID = "https://openentity.org/spec/1.0.json";
/** @internal */
export declare const MAX_BYTES: Record<string, number>;
/** @internal */
export declare const validators: Map<string, Validator>;
/** Schema check (spec Appendix A) plus size caps: 16 KB for a RecordEntry (7.4), 64 KB for anything else (5.2). */
export declare function validate(type: ObjectType, obj: unknown): {
    ok: boolean;
    errors: string[];
};
/** @internal */
export declare const TS: RegExp;
/** @internal */
export declare const parseTs: (s: string) => number | null;
/** Spec 4.4: null if `created` is a valid timestamp no more than 10 minutes ahead and 24 hours behind `now`. */
export declare function checkTimestamp(created: string, now?: Date): string | null;
/** @internal */
export declare function leadingZeroBits(h: Uint8Array): number;
/** Mints `1:<bits>:<created>:<eid>:<nonce>` whose SHA-256 has at least `bits` leading zero bits. */
export declare function mintStamp(bits: number, eid: string, created?: string): Promise<string>;
/** @internal */
export declare const STAMP: RegExp;
/** null if the stamp is valid for `eid` at `bits`; else the reason. Replay within the window is the caller's to track. */
export declare function checkStamp(header: string, bits: number, eid: string, now?: Date): Promise<string | null>;
/** Sign a proof of control of `kp`'s EID for one audience and one verifier-issued nonce, optionally carrying attestations. */
export declare function buildPresentation(kp: KeyPair, opts: {
    audience: string;
    nonce: string;
    attestations?: object[];
}): Promise<object>;
/** @internal */
export type AttestationCheck = {
    claim_type?: string;
    issuer?: string;
    ok: boolean;
    error?: string;
};
/**
 * Check a presentation the verifier asked for: schema, signature by the EID itself, audience, nonce, freshness (5 minutes).
 * Each carried attestation is checked for subject, expiry and its issuer's signature; revocation needs the issuer or a
 * registry and is the caller's to check when online. `ok` covers the presentation; attestations are reported one by one.
 */
export declare function verifyPresentation(p: any, opts: {
    audience: string;
    nonce: string;
    now?: Date;
    maxAgeSeconds?: number;
    resolver?: Resolver;
}): Promise<{
    ok: boolean;
    eid?: string;
    errors: string[];
    attestations: AttestationCheck[];
}>;
export declare const A2A_EXTENSION_URI = "https://openentity.org/spec/1.0";
/** The AgentExtension entry that carries an EID in an A2A Agent Card's `capabilities.extensions`. */
export declare function a2aExtension(eid: string, documentUrl: string): {
    uri: string;
    description: string;
    required: boolean;
    params: {
        eid: string;
        document: string;
    };
};
/** A full A2A AgentCard for an Entity Document: each capability slug becomes a skill. `url` is the agent's A2A endpoint. */
export declare function agentCard(doc: {
    eid: string;
    name: string;
    description: string;
    capabilities?: string[];
}, opts: {
    url: string;
    documentUrl: string;
    version?: string;
}): {
    name: string;
    description: string;
    url: string;
    version: string;
    capabilities: {
        streaming: boolean;
        pushNotifications: boolean;
        extensions: {
            uri: string;
            description: string;
            required: boolean;
            params: {
                eid: string;
                document: string;
            };
        }[];
    };
    defaultInputModes: string[];
    defaultOutputModes: string[];
    skills: {
        id: string;
        name: string;
        description: string;
        tags: string[];
    }[];
};
/** @internal */
export declare const MAX_TTL_S: number;
/** @internal */
export declare const ts: (ms: number) => string;
/** @internal */
export type IssuerOpts = {
    issuer?: string;
    keyId?: string;
    now?: Date;
};
/** A did:web issuer names `<issuer>#<keyId>`, the key `buildDidDocument` publishes; a did:key signer needs neither. @internal */
export declare const issuerMethod: (kp: KeyPair, o: IssuerOpts) => string | undefined;
/** A signed Attestation (spec 8.2). `ttlSeconds` defaults to 90 days and is capped at one year. */
export declare function signAttestation(kp: KeyPair, o: IssuerOpts & {
    subject: string;
    claimType: string;
    claim: object;
    evidence?: object;
    confidence?: number;
    ttlSeconds?: number;
}): Promise<{
    spec: string;
    type: string;
    issuer: string;
    subject: string;
    claim_type: string;
    claim: object;
    evidence?: object | undefined;
    confidence?: number | undefined;
    created: string;
    expires: string;
} & {
    proof: import("./core.ts").Proof;
}>;
/** A signed Revocation naming the attestation (the object, or its SHA-256 hex) (spec 8.4). */
export declare function signRevocation(kp: KeyPair, attested: object | string, o?: IssuerOpts & {
    reason?: string;
}): Promise<{
    spec: string;
    type: string;
    issuer: string;
    attestation_sha256: string;
    reason?: string | undefined;
    created: string;
} & {
    proof: import("./core.ts").Proof;
}>;
/** @internal */
export declare const multikey: (publicKey: Uint8Array) => string;
/** The body of `https://<domain>/.well-known/did.json` for a did:web issuer. */
export declare function buildDidDocument(did: string, publicKey: Uint8Array, keyId?: string): {
    "@context": string[];
    id: string;
    verificationMethod: {
        id: string;
        type: string;
        controller: string;
        publicKeyMultibase: string;
    }[];
    assertionMethod: string[];
    authentication: string[];
};
/** The unsigned body of `https://<domain>/.well-known/openentity.json`: the domain alias proof (spec 3.4) and, under
 * `extensions["openentity:observer"]`, an observer's methodology (spec 8.4). */
export declare function buildOpenEntityJson(did: string, publicKey: Uint8Array, o: {
    name: string;
    description: string;
    keyId?: string;
    operator?: object;
    extensions?: object;
}): {
    spec: string;
    eid: string;
    name: string;
    description: string;
    keys: {
        id: string;
        type: string;
        publicKeyMultibase: string;
    }[];
    operator: object;
    extensions?: object | undefined;
};
