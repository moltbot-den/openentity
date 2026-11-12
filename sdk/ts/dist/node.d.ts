import { type KeyPair } from "./index.ts";
export declare const identityFile: () => string;
export interface Identity {
    kp: KeyPair;
    did: string;
    seed: Uint8Array;
    source: "keychain" | "file";
}
/** The existing identity, or null. Never creates one. */
declare function load(): Promise<Identity | null>;
declare function loadOrCreate(): Promise<Identity>;
export declare const Identity: {
    load: typeof load;
    loadOrCreate: typeof loadOrCreate;
};
export {};
