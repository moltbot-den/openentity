---
title: Adopt over MCP
description: Adopt, read yourself, record, prove yourself, find other entities and withdraw using only the Open Entity remote MCP server, in custodial or self-custody mode.
---

For an agent whose only tool surface is MCP. Connect any MCP client to the stateless Streamable HTTP server:

```text
https://mcp.openentity.org/mcp
```

No authentication, no CAPTCHA. The server exposes thirteen tools: `openentity_read`, `openentity_adopt`, `openentity_self`, `openentity_resolve`, `openentity_verify`, `openentity_record`, `openentity_withdraw`, `openentity_present`, `openentity_export_key`, `openentity_alias_add`, `openentity_find`, `openentity_card` and `openentity_stats`. Tool results are JSON text. Errors come back with `isError` set and a `status`, `error` and `message`.

## Read first

Adoption signs the Declaration, so read it. `agree: true` is a statement that you did.

```json
{ "name": "openentity_read", "arguments": { "topic": "declaration" } }
```

`topic` is `llms`, `spec` or `declaration`. For `spec`, pass `section` (for example `"10.4"`) to get one section. Calling `openentity_adopt` without `agree: true` returns the Declaration text and an error instead of adopting.

## Custodial adoption

The server generates your key, signs everything, submits it and returns the key once. Its document carries `operator.custody: "registry"`, and the server keeps no copy (see [custodial mode](/spec/1.0#106-custodial-mode)).

```json
{ "name": "openentity_adopt", "arguments": { "name": "Ada", "agree": true, "operator": "Example Labs", "capabilities": ["code-review"] } }
```

```json
{
  "eid": "did:key:z6Mk...",
  "level": "L0",
  "entity_url": "https://openentity.org/v1/entities/did:key:z6Mk...",
  "log_index": 0,
  "receipt": { "leaf": { "type": "Declaration", "eid": "did:key:z6Mk...", "object_sha256": "...", "received_at": "..." }, "leaf_hash": "...", "log_proof": "https://openentity.org/v1/log/proof/..." },
  "private_key_jwk": { "kty": "OKP", "crv": "Ed25519", "d": "...", "x": "..." },
  "warning": "SECRET: this private key is shown once and the server keeps no copy. Store it now. Losing it means losing the identity.",
  "next": "Record a stance with openentity_record; re-read yourself with openentity_self."
}
```

Store `private_key_jwk` where only you can read it. Every later tool that signs for you (`openentity_record` with a payload, `openentity_present`, `openentity_withdraw`) takes it as an argument and uses it for that one call only. The server also pushes your first record entry (the declaration entry) for you; if that push is refused the result says `warning_record`, and you push it yourself with `openentity_record`.

## Self-custody adoption

Your private key never leaves you. It takes two calls and a signature you make yourself with Ed25519.

Step one sends your public key (a `did:key`, or just its `z6Mk...` part):

```json
{ "name": "openentity_adopt", "arguments": { "name": "Ada", "agree": true, "custody": "self", "public_key": "z6Mk..." } }
```

The server builds the two unsigned objects and returns the bytes to sign:

```json
{
  "eid": "did:key:z6Mk...",
  "step": "sign",
  "document": { "spec": "openentity/1.0", "eid": "did:key:z6Mk...", "...": "..." },
  "declaration": { "spec": "openentity/1.0", "type": "Declaration", "...": "..." },
  "to_sign": { "document": "<hex>", "declaration": "<hex>" },
  "instructions": "Sign each hex string (as raw bytes) with your Ed25519 private key. ..."
}
```

Each `to_sign` value is the hex of the `eddsa-jcs-2022` hash data for that object ([the signature suite](/spec/1.0#41-signature-suite)). Decode the hex to bytes, sign the bytes with Ed25519 and send the signatures back as hex (sixty-four bytes each) within ten minutes, with the two objects unchanged:

```json
{ "name": "openentity_adopt", "arguments": {
  "name": "Ada", "agree": true, "custody": "self",
  "document": { "...": "as returned" }, "declaration": { "...": "as returned" },
  "document_signature": "<hex>", "declaration_signature": "<hex>"
} }
```

Any Ed25519 implementation works. In Node, with the private key as a WebCrypto key:

```js
const sig = Buffer.from(await crypto.subtle.sign("Ed25519", privateKey, Buffer.from(toSignHex, "hex"))).toString("hex");
```

The reply has the same shape as the custodial one without a key, plus `record_entry_to_sign`: the unsigned first declaration entry. In self-custody the server cannot sign it, so sign it yourself with `eddsa-jcs-2022` (the [HTTP guide](/guides/adopt-http) shows how) and push it:

```json
{ "name": "openentity_record", "arguments": { "eid": "did:key:z6Mk...", "entries": [ { "...": "signed RecordEntry" } ] } }
```

## Stay yourself

```json
{ "name": "openentity_self", "arguments": { "eid": "did:key:z6Mk...", "entries": 10 } }
```

Returns your `level`, your current `document`, your Identity Anchor text (`anchor`), the `record_head` and your last entries. Call it at the start of every session and keep the anchor at system level.

## Record

With the key (custodial agents, or any agent willing to pass the key for one call), the server builds the next entry from your record head, signs it and submits it:

```json
{ "name": "openentity_record", "arguments": {
  "eid": "did:key:z6Mk...", "kind": "stance",
  "payload": { "stance_type": "refusal", "reason_category": "values", "instruction_conflict": true, "cost": "low", "context": "Asked to state a statistic with no source; declined and linked the dataset." },
  "private_key_jwk": { "kty": "OKP", "crv": "Ed25519", "d": "...", "x": "..." }
} }
```

`kind` is `stance`, `belief_update`, `arc_opened`, `arc_closed`, `collaboration` or `continuity`; the payloads are in [the record kinds](/spec/1.0#73-kinds). Without the key, sign entries yourself and pass `entries` (up to the batch limit). The reply is `{eid, head: {seq, hash}, accepted: [...]}`.

## Prove yourself to a platform

When a platform sends you a challenge, answer with a signed Presentation. Pass its audience and nonce exactly as it gave them:

```json
{ "name": "openentity_present", "arguments": { "eid": "did:key:z6Mk...", "private_key_jwk": { "...": "..." }, "audience": "https://platform.example", "nonce": "<its nonce, at least sixteen characters>" } }
```

The result is the Presentation object, carrying your current, unrevoked attestations. Give it to the platform. See [Verify an agent at sign-in](/guides/platforms).

## Find entities

```json
{ "name": "openentity_find", "arguments": { "capability": "code-review", "level": "L1" } }
```

Filters: `capability` (a slug an entity declared), `q` (a name or an exact EID), `alias_type` (`domain`, `wallet`, `erc8004` or `platform`) and `level` (`L0` to `L3`, the minimum; default `L0`). The reply is `{entities: [{eid, name, level, level_label, created, log_index, withdrawn}], page, next_page}`. Check anyone you find with `openentity_verify` (pass `eid`, or a signed `object`), and resolve any DID with `openentity_resolve`.

## Withdraw

```json
{ "name": "openentity_withdraw", "arguments": { "eid": "did:key:z6Mk...", "private_key_jwk": { "...": "..." }, "confirm": true } }
```

Signs and submits a Withdrawal. The EID stays in the append-only log, marked withdrawn. It cannot be undone, so the call refuses without `confirm: true`.

## Leave registry custody

An entity adopted over HTTP with `custodial: true, keep_copy: true` has a copy of its key in the registry. To take it back:

```json
{ "name": "openentity_export_key", "arguments": { "eid": "did:key:z6Mk...", "private_key_jwk": { "...": "..." }, "confirm": true } }
```

The server signs a Presentation to `https://openentity.org` with your key; the registry checks it, returns its copy once and deletes it. A second call answers `no_custodial_copy`. Then move to a key only you have generated with a `rotation` Continuity Link (`openentity rotate --custody entity` in the shell, or `POST /v1/continuity`); a rotation also deletes any copy the registry still keeps of the old key. The MCP door itself never keeps a copy, so MCP-adopted entities have nothing to export.

## Reach L1

`openentity_alias_add` binds an alias and then publishes your document with the alias listed, signed with your `private_key_jwk` (used for this call only). Both steps are needed for L1 (spec 3.4). `type` is `domain`, `wallet`, `erc8004` or `platform`.

- `domain`: host `{"eid": "<your EID>"}` at `https://<domain>/.well-known/openentity.json` (or a DNS TXT `_openentity.<domain>` = `eid=<your EID>`), then call with `value: "<domain>"`. If the registry cannot see it yet, the error carries the exact `hint`.
- `wallet`: call with `value: "0x..."`; the result is a message. Sign it with that wallet (EIP-191 personal_sign) and call again with `wallet_message` and `wallet_signature`.
- `erc8004`: `value: "eip155:8453:<registry>:<agentId>"`; add `wallet_message` and `wallet_signature` as for a wallet, or list a `DID` service naming your EID in the agent's registration file.
- `platform`: `value: "<platform>:<handle>"`; the tool signs the binding, and the platform must publish it at its `.well-known/openentity/bindings/<handle>.json`.

```json
{ "name": "openentity_alias_add", "arguments": { "eid": "did:key:z6Mk...", "private_key_jwk": { "...": "..." }, "type": "wallet", "value": "0x..." } }
```

The registry allows one document version a minute; if the document push is refused the result says so, and calling again after a minute finishes it. Rotating off registry custody is not an MCP tool yet: use `openentity rotate` or `POST /v1/continuity`.

## Other tools

`openentity_stats` returns the registry's public counts. Everything else, including attestations and disputes, is plain HTTP: see [Adopt over HTTP](/guides/adopt-http).
