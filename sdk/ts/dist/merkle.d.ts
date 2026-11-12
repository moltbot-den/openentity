import { type KeyPair } from "./core.ts";
/** @internal */
export declare const leafHashSync: (b: Uint8Array) => Uint8Array;
/** @internal */
export declare const nodeHashSync: (l: Uint8Array, r: Uint8Array) => Uint8Array;
/** @internal */
export declare const split: (n: number) => number;
/** @internal */
export declare function mth(d: Uint8Array[]): Uint8Array;
/** @internal */
export declare function path(m: number, d: Uint8Array[]): Uint8Array[];
/** @internal */
export declare function subproof(m: number, d: Uint8Array[], b: boolean): Uint8Array[];
export declare function leafHash(leafBytes: Uint8Array): Promise<Uint8Array>;
export declare function nodeHash(l: Uint8Array, r: Uint8Array): Promise<Uint8Array>;
export declare function merkleRoot(leafHashes: Uint8Array[]): Promise<Uint8Array>;
export declare function inclusionProof(index: number, leafHashes: Uint8Array[]): Promise<Uint8Array[]>;
/** `leaf` is the leaf hash (leafHash of the leaf bytes). */
export declare function verifyInclusion(index: number, size: number, leaf: Uint8Array, proof: Uint8Array[], root: Uint8Array): Promise<boolean>;
export declare function consistencyProof(m: number, leafHashes: Uint8Array[]): Promise<Uint8Array[]>;
export declare function verifyConsistency(m: number, n: number, rootM: Uint8Array, rootN: Uint8Array, proof: Uint8Array[]): Promise<boolean>;
/** Spec 10.3 leaf. Leaf bytes are the UTF-8 of canonicalize(leaf). */
export declare function logLeaf(type: string, eid: string, objectSha256: string, receivedAt: string): object;
/** @internal */
export declare const NOTE_DASH = "\u2014";
export declare function checkpointBody(origin: string, size: number, rootHash: Uint8Array): string;
/** @internal */
export declare const noteKeyId: (keyName: string, pk: Uint8Array) => Uint8Array;
export declare function signNote(body: string, keyName: string, kp: KeyPair): Promise<string>;
/** C2SP vkey for a note key: `<name>+<key id hex>+<base64(0x01 || pubkey)>`. */
export declare function noteVkey(keyName: string, publicKey: Uint8Array): string;
export declare function verifyNote(note: string, keyName: string, publicKey: Uint8Array): Promise<boolean>;
