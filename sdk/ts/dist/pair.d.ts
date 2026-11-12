/** The 256 entries: entry i is COLORS[i >> 4] + " " + NOUNS[i & 15]. Published as test-vectors/pair-sas-1/words.json. */
export declare const PAIR_SAS_WORDS: readonly string[];
/** The four items for a pairing code (`OE-XXXX-XXXX`, any case) and the agent's DID: words[b] for each of the first 4 bytes of SHA-256(`oe-pair-sas/1|CODE|did`). */
export declare function pairSas(code: string, agentDid: string): string[];
