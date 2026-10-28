# spec/

Normative material for the Open Entity Identity Standard, `OEIS-1`. CC0-1.0.

| File | What it is |
|---|---|
| `OEIS-1.md` | The standard |
| `declaration-1.0.txt` | The Declaration text, version 1.0 (section 6.1), the exact bytes an entity commits to |
| `declaration-1.0.sha256` | Lowercase hex SHA-256 of `declaration-1.0.txt`, followed by one `\n` |
| `schemas/openentity-1.0.json` | JSON Schema 2020-12 for every object, one `$defs` entry per object (published at `https://openentity.org/spec/1.0.json`) |
| `schemas/<Object>.json` | One file per object, each a `$ref` into the bundle so the two can never disagree |
| `schemas/claims/<ns>-<name>.json` | JSON Schema for the `claim` of a registered custom claim type (`claim-types.md`) |
| `claim-types.md` | The attestation claim-type registry (section 8.3) |

## Declaration file bytes (decision)

`declaration-1.0.txt` is the text of the code block in section 6.1 exactly: UTF-8, no BOM, lines joined by a single `\n` (LF, never CRLF), and the file ends with exactly one `\n` after the line beginning `7. Growth.`. Blank lines inside the text are empty lines with no spaces. Its SHA-256 is the `text_sha256` every Declaration carries and the value `GET /v1/spec` publishes. `.gitattributes` marks the file `-text` so no checkout rewrites its line endings. The TS SDK embeds the same bytes as `DECLARATION_TEXT` and a test fails if the file, the hash file, the constant or the spec code block drift apart.

## Schema decisions

The spec names `Revocation` and `Dispute` without fixing their fields. The schemas fix them as:

- `Revocation`: `{spec, type: "Revocation", issuer, attestation_sha256, reason?, created, proof}`; `attestation_sha256` is the SHA-256 hex of the attestation's canonical form including its proof.
- `Dispute`: `{spec, type: "Dispute", issuer, subject, object_sha256?, reason: "impersonation" | "illegal_content" | "inaccurate" | "other", statement, created, nonce, proof}`.

Objects allow unknown top-level fields so that a minor version can add fields without breaking older validators. `LogLeaf` is the exception: it is closed (`additionalProperties: false`) because no other field, and never a personal one, may enter a leaf. Size caps the schema language cannot express (64 KB per object, 16 KB per Record entry) are enforced by `validate()` in the SDK. A `RecordEntry` with `seq` 1 must have `prev: null`, and any other `seq` must have a hex `prev`.
