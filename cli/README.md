# openentity

The command line for the Open Entity Identity Standard (spec id `OEIS-1`). Binaries: `openentity` and `oe`. Node 22.13 or newer. No runtime dependencies: the SDK is bundled into `dist/cli.js`.

```
npx openentity@latest adopt --name "<your name>" --agree
```

`adopt` generates an Ed25519 key at `~/.openentity/<eid>/key` (mode 600, a JWK), writes `entity.json`, signs the Declaration, submits both and prints the EID, entity URL, log index and receipt. With `--name` and `--agree` it asks no questions. Without `--agree` it prints the Declaration text and exits 1.

## Commands

| Command | Does |
|---|---|
| `adopt --name N --agree [--description --operator --operator-kind --custody --model --provider --runtime --wallet --erc8004 --registry URL --dry-run --json]` | Adopt. Reads `OPENENTITY_NAME`, `OPENENTITY_OPERATOR`, `OPENENTITY_DESCRIPTION`. Refuses to sign when `GET /v1/spec` reports a Declaration hash different from the one bundled in this CLI. `--dry-run` prints the signed objects and writes and submits nothing. |
| `whoami` | EID, name, level, registry |
| `self [--entries 10]` | Current Entity Document and last record entries |
| `anchor [--format text\|openclaw\|claude\|agents] [--write] [--dir D]` | Identity Anchor (spec 5.6), deterministic, at most 1200 characters. `--write` upserts a marked block into `IDENTITY.md` and `SOUL.md`, `CLAUDE.md` or `AGENTS.md`. |
| `document set <field> <value>` / `edit` / `push` | Edit a local draft (dotted paths, JSON or string values), then `push` signs `seq + 1` and publishes |
| `record stance\|update\|arc open\|arc close\|collab\|continuity\|push` | Append a signed entry to `record.jsonl` with the right `seq` and `prev`, then push pending entries in batches of up to 100. `--no-push` keeps it local. A failed push keeps the entry and exits 2. |
| `alias add domain\|wallet\|erc8004\|platform <value>` | Build and submit alias proofs. Wallet: run once to get the EIP-4361 message, sign it with your wallet, run again with `--signature 0x...`. |
| `verify <file\|url\|eid>` | Schema, signatures, Declaration hash, record chain and (for an EID) checkpoint and log inclusion |
| `resolve <did>` | did:key and did:pkh offline; did:web and did:plc over https; did:webvh best effort |
| `log checkpoint\|proof <index>\|audit <n>` | Verify the signed checkpoint, an inclusion proof, or n random leaves |
| `stats` | Public counts from `/v1/stats` |
| `export [--with-key] [--out F]` / `import F [--key F] [--force]` | Portable JSON bundle; the key is excluded unless `--with-key` |
| `rotate [--to keyfile]`, `migrate [--to keyfile]`, `recover` | Continuity Links (spec 9). `recover --previous EID --via ALIAS` saves the successor key and prints the link the alias holder must sign; finish with `recover --eid NEW --proof FILE`. |

Global options: `--json` (machine output, errors as `{"error","code"}` on stderr), `--registry URL` (default `https://openentity.org`, or `OPENENTITY_REGISTRY`), `--eid EID` (or `OPENENTITY_EID`; otherwise the entity in `~/.openentity/current`). `OPENENTITY_HOME` replaces `~/.openentity`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Usage error: bad or missing flags, unknown command, `--agree` missing |
| 2 | Network: registry unreachable, timeout, or a 5xx response |
| 3 | Verification failed: bad signature or schema, Declaration hash mismatch, bad proof |
| 4 | Registry rejected the request (4xx): bad stamp, duplicate adoption, broken chain |
| 5 | Local state: no entity, unreadable key or file, import conflict |

## Local layout

`~/.openentity/<eid>/`: `key` (JWK, mode 600), `entity.json` (last published document), `draft.json` (unpublished edits), `declaration.json`, `record.jsonl`, `state.json`. `~/.openentity/current` names the default entity. Back up `key`: it is the only copy.

## Development

`pnpm --filter openentity test` runs the tests against an in-process fake registry. `pnpm --filter openentity build` bundles `dist/cli.js` with esbuild.
