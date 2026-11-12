import { type KeyPair } from "./core.ts";
/** @internal Ed25519 `authentication` keys of allowed did:web signers by verification method id, per DID, from its did.json. */
export declare const didWebKeys: Map<string, {
    at: number;
    keys: Map<string, Uint8Array>;
}>;
/** @internal Ed25519 keys of a DID document by absolute method id (Ed25519 publicKeyMultibase or OKP publicKeyJwk); with `relationship`, only the methods it references. */
export declare function ed25519Methods(did: string, doc: any, relationship?: "authentication"): Map<string, Uint8Array>;
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
 * `expectDid` (one DID or a list) pins the signer: any other keyid, a did:key included, fails with `unexpected_signer` before any key
 * is read. Pass it whenever only known services may call. `allowDidWeb` alone is not a pin: it only lets those did:web DIDs be
 * resolved, and any did:key signer still verifies.
 * A did:key keyid verifies offline. A `did:web:<host>#<key>` keyid verifies only when its DID is in `expectDid` or `allowDidWeb`: the
 * key is an Ed25519 method listed under `authentication` in the DID's did.json, cached for ten minutes and refetched when it names an
 * unknown key.
 */
export declare function verifyRequest(o: {
    method: string;
    url: string;
    headers: Record<string, string>;
    body?: Uint8Array;
    now?: number;
    maxAge?: number;
    expectDid?: string | string[];
    allowDidWeb?: string[];
    fetchJson?: (url: string) => Promise<unknown>;
}): Promise<{
    did: string;
    keyid: string;
    created: number;
    expires: number;
    nonce: string;
}>;
/**
 * Verify a response signed by a did:web service, such as the OpenEntity Account's signed paused list. Throws HttpSigError with `.code`.
 * The signature covers `"@status"` and `"content-digest"`, lives at most `maxAge` seconds (one minute by default), and its keyid is a
 * `did:web:<host>#<key>` of a DID in `expectDid` (the signer pin, which refuses any other signer with `unexpected_signer`) or
 * `allowDidWeb`, resolved as verifyRequest resolves one.
 */
export declare function verifyResponse(o: {
    status: number;
    headers: Record<string, string>;
    body: Uint8Array;
    now?: number;
    maxAge?: number;
    expectDid?: string | string[];
    allowDidWeb?: string[];
    fetchJson?: (url: string) => Promise<unknown>;
}): Promise<{
    did: string;
    keyid: string;
    created: number;
    expires: number;
}>;
