export declare const SPEC = "openentity/1.0";
export declare const DECLARATION_VERSION = "1.0";
/** Exact bytes of spec/declaration-1.0.txt: the spec 6.1 code block, lines joined by \n, one trailing \n. */
export declare const DECLARATION_TEXT: string;
export declare const DECLARATION_SHA256 = "72671d5f20b9ba59ccc31848643ef7ca47b040ed55a837305e0a1509bd82c016";
/** @internal */
export declare const enc: TextEncoder;
/** @internal */
export declare const utf8: (s: string | Uint8Array) => Uint8Array;
/** @internal */
export declare const toHex: (b: Uint8Array) => string;
/** @internal */
export declare const fromHex: (h: string) => Uint8Array;
/** @internal */
export declare const concat: (...parts: Uint8Array[]) => Uint8Array;
/** @internal */
export declare const equal: (a: Uint8Array, b: Uint8Array) => boolean;
/** @internal */
export declare const b64: (b: Uint8Array) => string;
/** @internal */
export declare const unb64: (s: string) => Uint8Array;
/** @internal */
export declare const b64url: (b: Uint8Array) => string;
/** @internal */
export declare const unb64url: (s: string) => Uint8Array;
/** RFC 8785 (JCS) canonical form. Throws on values JSON cannot represent. */
export declare function canonicalize(obj: unknown): string;
/** Spec 4.3: parse JSON text that has no duplicate keys. JSON.parse keeps the last duplicate silently, so two implementations could read different objects. */
export declare function parseJson(text: string): unknown;
/** Spec 4.3: numbers are integers or decimal fractions with at most 6 decimal places. @internal */
export declare function badNumber(v: unknown): string | null;
/** @internal */
export declare const sha256Sync: (data: string | Uint8Array) => Uint8Array;
export declare function sha256(data: string | Uint8Array): Promise<Uint8Array>;
export declare function sha256Hex(data: string | Uint8Array): Promise<string>;
/** @internal */
export declare const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
export declare function base58btcEncode(b: Uint8Array): string;
export declare function base58btcDecode(s: string): Uint8Array;
export declare function randomNonce(): string;
export declare function nowSeconds(): string;
export interface KeyPair {
    did: string;
    publicKey: Uint8Array;
    privateKey: CryptoKey;
    privateJwk: JsonWebKey;
    publicJwk: JsonWebKey;
}
export declare function keyPairFromJwk(privateJwk: JsonWebKey): Promise<KeyPair>;
export declare function generateKeyPair(): Promise<KeyPair>;
/** Deterministic key pair from a 32-byte seed: test vectors, and `Identity` (sdk/ts/src/node.ts), which keeps the seed. */
export declare function keyPairFromSeed(seed32: Uint8Array): Promise<KeyPair>;
/** @internal */
export declare const ED25519_MULTICODEC: Uint8Array<ArrayBuffer>;
export declare function didKeyFromPublicKey(pk: Uint8Array): string;
export declare function publicKeyFromDidKey(did: string): Uint8Array;
export declare function verificationMethodId(did: string): string;
/** @internal The did.json URL of a did:web DID: /.well-known/did.json, or <path>/did.json for a DID with a path. */
export declare function didWebUrl(did: string): string;
export declare function normalizeEid(id: string): string;
export interface Proof {
    type: string;
    cryptosuite?: string;
    created: string;
    verificationMethod: string;
    proofPurpose: string;
    proofValue: string;
}
export type Resolver = (did: string) => Promise<{
    ed25519?: Uint8Array[];
    address?: string;
}>;
/** @internal */
export type VerifyResult = {
    ok: boolean;
    signer?: string;
    error?: string;
};
/** @internal */
export declare const defaultResolver: Resolver;
/** The signed content: the object minus `proof` (and `proofs`, for ContinuityLink). @internal */
export declare function unsecured(obj: object): object;
/** eddsa-jcs-2022 hashData: sha256(JCS(proof config)) || sha256(JCS(document)). */
export declare function hashData(obj: object, config: Omit<Proof, "proofValue">): Uint8Array;
/** `verificationMethod` defaults to the did:key of `kp`; a did:web signer passes its own method id (for example `did:web:x#key-1`). */
export declare function signProof(obj: object, kp: KeyPair, created?: string, verificationMethod?: string): Promise<Proof>;
export declare function signObject<T extends object>(obj: T, kp: KeyPair, created?: string, verificationMethod?: string): Promise<T & {
    proof: Proof;
}>;
export declare function verifyProof(obj: object, proof: Proof, resolver?: Resolver): Promise<VerifyResult>;
export declare function verifyObject(obj: {
    proof?: Proof;
}, resolver?: Resolver): Promise<VerifyResult>;
/** @internal */
export declare const keccak: (s: string | Uint8Array) => Uint8Array;
/** @internal */
export declare const EIP712_DOMAIN: Uint8Array<ArrayBufferLike>;
/** @internal */
export declare const OBJECT_TYPEHASH: Uint8Array<ArrayBufferLike>;
/** EIP-712 digest of OpenEntityObject{objectType, canonicalHash, created}, domain {name: "Open Entity", version: "1"}. */
export declare function eip712Digest(objectType: string, canonicalHashHex: string, created: string): Uint8Array;
/** Recovers the EIP-55 checksummed address from a 65-byte r||s||v signature over `digest`. */
export declare function recoverEip712(digest: Uint8Array, sigHex: string): string;
