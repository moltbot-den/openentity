# Test vectors

> **WARNING: PUBLISHED THROWAWAY KEYS.** Every key here comes from a seed printed in `keys.json`. Anyone can sign as these EIDs. Never use these seeds or keys for anything real.

| Key | Seed (32 bytes, hex) | Used for |
|---|---|---|
| entity | `0102...1f20` (bytes 0x01 to 0x20) | The entity: document, declaration, record entries, previous key of the continuity link |
| second | `2122...3f40` (bytes 0x21 to 0x40) | Attestation issuer and successor key of the continuity link |
| log | `4142...5f60` (bytes 0x41 to 0x60) | Signs the checkpoint note, key name `openentity.org/log` |

Every timestamp and nonce is fixed and Ed25519 is deterministic, so the files are byte-for-byte reproducible:

```
pnpm --filter @openentity/sdk gen:vectors
```

A test in `sdk/ts` regenerates them in memory and fails if a committed file differs.

## Files

`<name>.json` for each object is `{description, object, canonical, sha256, unsigned_canonical}`: `canonical` is the RFC 8785 (JCS) string of the object including `proof` (or `proofs`), `sha256` is the hex SHA-256 of its UTF-8 bytes (this is the leaf `object_sha256` and, for record entries, the next entry's `prev`), and `unsigned_canonical` is the JCS string without `proof`/`proofs`, the second half of the eddsa-jcs-2022 signing input.

| File | Content |
|---|---|
| `keys.json` | Seeds, EIDs, public keys and the log note vkey |
| `declaration.json` | Signed Declaration |
| `entity-document.json` | Signed Entity Document, `seq` 1, pointing at the declaration's hash |
| `record-1.json`, `record-2.json` | Two chained Record entries (`prev` of 2 is `sha256` of 1) |
| `attestation.json` | `stage` attestation by the second key about the entity |
| `continuity-link.json` | `rotation` link with proofs by both keys |
| `log-leaf-0.json` to `log-leaf-5.json` | Leaves for the six objects above in that order, each with `leaf_hash` = SHA-256 of 0x00 followed by the canonical bytes |
| `checkpoint.json` | Tree size, root, C2SP checkpoint body, signed note and the inclusion proof of every leaf |

The signed note's signature line starts with U+2014, which the JSON files carry escaped as `\u2014`.
