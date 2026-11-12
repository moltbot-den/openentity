# Pairing match string vectors (pair-sas/1)

When an agent pairs with its owner (`docs/mobile/PLAN.md` section 8.1), the agent prints four items and the owner's app shows four items. The owner confirms only if they match. The account service computes the app's copy; the SDKs compute the agent's (`pairSas` in `@openentity/sdk`, `pair_sas` in the Python `openentity` package).

## Derivation

```
h = SHA-256( UTF-8( "oe-pair-sas/1|" + CODE + "|" + agent_did ) )
items = [ words[h[0]], words[h[1]], words[h[2]], words[h[3]] ]
```

- `CODE` is the pairing code as issued, `OE-XXXX-XXXX`, in upper case. Implementations trim and upper-case what the user typed before hashing.
- `agent_did` is the agent's DID string exactly as it signs (its `did:key`).
- `words` is the 256-entry list in `words.json`, indexed by byte value. Four items carry 32 bits.

## The list

Entry `i` is `colors[i >> 4] + " " + nouns[i & 15]`: 16 colors times 16 nouns, so every entry is distinct and every item is two plain lowercase ASCII words that read the same in a terminal, VoiceOver and TalkBack. Within each half no two words sound alike.

- colors: red, orange, yellow, green, blue, purple, pink, brown, black, white, gray, gold, silver, navy, olive, coral
- nouns: fox, kite, bear, boat, star, tree, fish, moon, drum, frog, lamp, owl, wolf, shell, crown, horse

Show the four items in order, joined by `, ` (for example `red fox, blue kite, gold star, gray owl`). Changing the list or the derivation means `pair-sas/2`.

## Files

- `words.json`: `{colors, nouns, words}` with the 256 entries.
- `vectors.json`: cases `{code, agent_did, preimage, sha256, items}`. The agent DIDs are the published throwaway EIDs of `../keys.json`. The last case types the code in lower case and must give the same items as the first.
