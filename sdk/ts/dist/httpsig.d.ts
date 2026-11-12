import { type KeyPair } from "./core.ts";
/** @internal Ed25519 keys of allowed did:web signers by verification method id, per DID, from its did.json. */
export declare const didWebKeys: Map<string, {
    at: number;
    keys: Map<string, Uint8Array>;
}>;
/** @internal */
export declare const HTTPSIG_SKEW = 5;
/** @internal */
export declare const contentDigest: (body: Uint8Array) => string;
export declare function httpSigBase(method: string, url: string, components: string[], digest: string | undefined, params: string): Uint8Array;
/** Sign a request. `privateKey` is a KeyPair or an Ed25519 seed. Returns Signature-Input, Signature and, for a non-empty body, Content-Digest. */
export declare function signRequest(o: {
    method: string;
    url: string;
    body?: Uint8Array;
    privateKey: KeyPair | Uint8Array;
    did: string;
    created?: number;
    expiresIn?: number;
    nonce?: string;
}): Promise<Record<string, string>>;
/**
 * Verify a request signed by signRequest. Throws HttpSigError with `.code`. Nonce replay tracking is the caller's job.
 * A did:key keyid verifies offline. A `did:web:<host>#<key>` keyid verifies only when its DID is in `allowDidWeb`: the key comes from
 * the DID's did.json (Ed25519 Multikey or JsonWebKey), cached for ten minutes and refetched when it names an unknown key.
 */
export declare function verifyRequest(o: {
    method: string;
    url: string;
    headers: Record<string, string>;
    body?: Uint8Array;
    now?: number;
    maxAge?: number;
    allowDidWeb?: string[];
    fetchJson?: (url: string) => Promise<unknown>;
}): Promise<{
    did: string;
    keyid: string;
    created: number;
    expires: number;
    nonce: string;
}>;
