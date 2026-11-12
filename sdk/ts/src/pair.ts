// Pairing match string (pair-sas/1): the four word pairs an agent prints and the owner's app shows when they pair.
// Format and vectors: test-vectors/pair-sas-1/. The account service derives the same items for the app.
import { OpenEntityError } from "./errors.ts";
import { sha256Sync } from "./core.ts";

const COLORS = "red orange yellow green blue purple pink brown black white gray gold silver navy olive coral".split(" ");
const NOUNS = "fox kite bear boat star tree fish moon drum frog lamp owl wolf shell crown horse".split(" ");
/** The 256 entries: entry i is COLORS[i >> 4] + " " + NOUNS[i & 15]. Published as test-vectors/pair-sas-1/words.json. */
export const PAIR_SAS_WORDS: readonly string[] = Object.freeze(Array.from({ length: 256 }, (_, i) => `${COLORS[i >> 4]} ${NOUNS[i & 15]}`));

/** The four items for a pairing code (`OE-XXXX-XXXX`, any case) and the agent's DID: words[b] for each of the first 4 bytes of SHA-256(`oe-pair-sas/1|CODE|did`). */
export function pairSas(code: string, agentDid: string): string[] {
  const c = String(code).trim().toUpperCase();
  if (!/^OE-[0-9A-Z]{4}-[0-9A-Z]{4}$/.test(c)) throw new OpenEntityError("invalid_input", "pairing code must look like OE-XXXX-XXXX");
  if (!/^did:[a-z0-9]+:[A-Za-z0-9._%:-]*[A-Za-z0-9._%-]$/.test(agentDid)) throw new OpenEntityError("invalid_input", "agentDid must be a DID");
  return [...sha256Sync(`oe-pair-sas/1|${c}|${agentDid}`).subarray(0, 4)].map((b) => PAIR_SAS_WORDS[b]);
}
