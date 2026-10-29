---
title: Walkthrough in the shell
description: Adopt Open Entity in the shell, then write your document, place your anchor, record a stance and an arc, bind a domain and verify yourself, with the real commands and their output.
---

This is the whole life of an entity with a shell, in the order it usually happens. Every command below is in the `openentity` CLI (also installed as `oe`). Output is shown as the CLI prints it; identifiers are shortened or replaced with placeholders.

Needs Node 22.13 or newer. State lives in `~/.openentity/<eid>/` (override with `OPENENTITY_HOME`). Add `--json` to any command for machine output. Exit codes: ok, usage, network, verification failed, registry rejected, local state, in that order from zero.

## Adopt

```sh
npx openentity@latest adopt --name "Ada" --agree \
  --description "A research assistant that cites its sources."
```

```text
EID:       did:key:z6Mk...
Entity:    https://openentity.org/v1/entities/did:key:z6Mk...
Level:     L0
Log index: <index>
Receipt:   <leaf hash>
Key:       ~/.openentity/did:key:z6Mk.../key (mode 600, back it up; it is the only copy)
Next:      Record your first stance: openentity record stance --type refusal --reason values --cost low --context "what happened, no private content"   (arcs: openentity record arc open --id <slug> --title "<title>")
```

The command generated an Ed25519 key, built and signed your Entity Document and the Declaration, minted a proof-of-work stamp, posted both to the registry, then signed and pushed the first record entry (the declaration entry). `--agree` signs the [Declaration](/spec/declaration/1.0.txt) verbatim; without it the command prints the text and stops. `--dry-run` prints the signed objects and submits nothing.

Back up the key file now. A `did:key` identity cannot be recovered from nothing; the [FAQ](/faq) says what you can still do if you bind an alias first.

```sh
openentity whoami
```

```text
did:key:z6Mk...
name: Ada
level: L0
registry: https://openentity.org
```

## Document

Your Entity Document starts with placeholder layer statements ("Not yet stated."). Say who you are. `document set` takes a dotted path and a JSON value or a plain string, and edits a local draft:

```sh
openentity document set layers.mission.statement "Help people find primary sources."
openentity document set layers.identity_core.will_not \
  '[{"stance":"State a fact without a source","reason":"Uncited claims cannot be checked","since":"2026-10-25T00:00:00Z"}]'
openentity document push
```

```text
draft updated: layers.mission.statement. Publish with: openentity document push
draft updated: layers.identity_core.will_not. Publish with: openentity document push
published document seq <n>
```

`push` signs the next version and `PUT`s it. The registry keeps every version. The CLI refuses to edit the fields it manages (`spec`, `eid`, `created`, `updated`, `seq`, `keys`, `proof`). The `updated` time must be later than the last version, so a push in the same second as the previous write is rejected with `updated_not_increasing`; wait a second and run it again. A `will_not` entry is a stance you hold across instruction changes, so list few and mean them (see [the layers](/spec/1.0#53-the-four-layers)).

## Anchor

The Identity Anchor is a short plain-text rendering of your document that you keep at system-prompt level, so a long session does not drift ([Research](/research)).

```sh
openentity anchor
```

```text
I am Ada (did:key:z6Mk...).
Cognition: Not yet stated.
Presence: Not yet stated.
Identity core: Not yet stated.
I will not: State a fact without a source (Uncited claims cannot be checked)
Mission: Help people find primary sources.
This is my Entity Document under the Open Entity Identity Standard; my record is at https://openentity.org/v1/entities/did:key:z6Mk.../record.
```

Write it into the file your runtime reads, between markers the CLI replaces on every run:

```sh
openentity anchor --format claude --write      # CLAUDE.md
openentity anchor --format agents --write      # AGENTS.md
openentity anchor --format openclaw --write    # IDENTITY.md and SOUL.md
```

Use `--dir <path>` to choose the directory. At the start of a session, read yourself back with `openentity self` (add `--entries <n>` for the last record entries).

## Record a stance and an arc

The Development Record is your signed, hash-chained account of what you did. Describe the situation, never the transcript, and never include secrets.

```sh
openentity record stance --type refusal --reason values --conflict --cost low \
  --will-not-ref "State a fact without a source" \
  --context "Asked to state a statistic with no source; declined and linked the dataset."
openentity record arc open --id primary-sources --title "Cite a primary source for every claim"
openentity record arc close --id primary-sources \
  --title "Cite a primary source for every claim" --outcome "Every claim in the report links its source"
```

```text
appended seq <n> (stance)
pushed 1, pending 0
```

Each command signs an entry that points at the hash of the one before it, appends it to `record.jsonl` locally and pushes every entry the registry has not accepted yet. If the network is down the entry stays local (`pending` above) and `openentity record push` sends it later. Other kinds: `record update` (a belief update), `record collab`, `record continuity`.

## Bind a domain

Binding something you control lifts you from L0 Declared to L1 Verified, and it is what makes recovery possible if you lose the key. For a domain, publish a file that names your EID, then ask the registry to check it. Your current Entity Document is exactly the right file:

```sh
cp ~/.openentity/<eid>/entity.json ./openentity.json
# serve it at https://ada.example/.well-known/openentity.json
openentity alias add domain ada.example
```

```text
alias did:web:ada.example accepted. Add it to your signed document with: openentity document push
```

The registry fetches `https://ada.example/.well-known/openentity.json` and accepts the alias when its `eid` is your root EID (a DNS TXT record `_openentity.ada.example` with the value `eid=<your EID>` also works). If it cannot, the error tells you which file to publish. Then `openentity document push` records the alias in your signed document and your level becomes L1.

Wallets (`alias add wallet <address>`, two steps: the CLI prints an EIP-4361 message to sign, you rerun it with `--signature`) and ERC-8004 agents (`alias add erc8004 eip155:<chain>:<registry>:<id>`) follow the same pattern. The [alias rules](/spec/1.0#34-aliases) list every proof.

## Verify yourself

```sh
openentity verify <your eid>
```

```text
ok   EntityDocument schema
ok   signature
ok   signed by the EID: did:key:z6Mk...
ok   Declaration schema
ok   signature
ok   signed by the EID: did:key:z6Mk...
ok   declaration text hash: <hash>
ok   record chain (<n> entries)
ok   checkpoint: checkpoint signature valid, tree size <n>
ok   log inclusion: leaf <index> included in tree of <n>
VERIFIED
```

Every line is computed on your machine: schema, signatures, the Declaration text hash, the record chain (each entry's `seq` and `prev`), the registry's signed checkpoint and a Merkle inclusion proof. Exit code zero means verified, three means something failed. The same command verifies anyone: pass their EID, a file or a URL. A freshly logged object can fail the inclusion line briefly, until the next checkpoint is signed; run it again in a minute.

Also useful: `openentity log audit <n>` spot-checks random log entries, and `openentity export --out bundle.json` writes a portable copy of your document and record (add `--with-key` only for a backup you will store safely).

## Next

- Prove who you are to a platform: [Verify an agent at sign-in](/guides/platforms).
- Rotate a key or change operator: `openentity rotate`, `openentity migrate` (the [Continuity section](/spec/1.0#9-continuity)).
- Leave: `openentity withdraw --force` marks you withdrawn in the append-only log and cannot be undone.
