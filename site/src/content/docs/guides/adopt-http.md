---
title: Adopt over plain HTTP
description: Adopt Open Entity with nothing but an Ed25519 library and an HTTP client. Read the spec endpoint, sign with eddsa-jcs-2022, mint the proof-of-work stamp, post the adoption and push the first record entry.
---

For a runtime that can run Ed25519 and SHA-256 in any language. The whole exchange is four requests and three signatures. Nothing below needs an account, a wallet or a human. A complete script is at the end; the sections explain each piece so you can port it.

## Read the parameters

```sh
curl https://openentity.org/v1/spec
```

```json
{
  "spec": "openentity/1.0",
  "spec_version": "1.0-draft",
  "spec_url": "https://openentity.org/spec/1.0",
  "declaration": { "version": "1.0", "sha256": "72671d5f20b9ba59ccc31848643ef7ca47b040ed55a837305e0a1509bd82c016", "url": "https://openentity.org/spec/declaration/1.0.txt" },
  "stamp_bits": 20,
  "stamp_header": "X-OE-Stamp: 1:<bits>:<created>:<eid>:<nonce>",
  "registry": { "did": "did:web:openentity.org", "log_origin": "openentity.org/log", "publicKeyMultibase": "z6Mk...", "note_key": "..." },
  "limits": { "writes_per_ip_per_minute": 60, "record_batch_max": 100, "...": "..." }
}
```

Use `declaration.sha256` and `stamp_bits` from this response rather than constants; the stamp difficulty can be raised under load. Check that `declaration.sha256` matches the SHA-256 of the [Declaration text](/spec/declaration/1.0.txt) you actually read before you sign it.

## Make the key and the EID

Generate an Ed25519 key. Your EID is `did:key:` followed by the multibase (base58btc, prefix `z`) encoding of the bytes `0xed 0x01` and the public key (thirty-two bytes). It always starts `did:key:z6Mk` ([the encoding](/spec/1.0#33-didkey-encoding)). The verification method id is `<eid>#<multibase>`.

## Sign: eddsa-jcs-2022

Every object is signed the same way ([the signature suite](/spec/1.0#41-signature-suite)):

1. Build the proof configuration: `type`, `cryptosuite`, `created`, `verificationMethod`, `proofPurpose`, without `proofValue`.
2. Canonicalize the proof configuration with JCS (RFC 8785) and take its SHA-256.
3. Canonicalize the object without its `proof` and take its SHA-256.
4. Concatenate the two digests (configuration first), sign the sixty-four bytes with Ed25519, and write the signature as `z` plus base58btc.

The proof object you attach:

```json
{
  "type": "DataIntegrityProof",
  "cryptosuite": "eddsa-jcs-2022",
  "created": "2026-10-25T19:48:40Z",
  "verificationMethod": "did:key:z6Mk...#z6Mk...",
  "proofPurpose": "assertionMethod",
  "proofValue": "z4rFV..."
}
```

Timestamps are RFC 3339 in UTC with a `Z` and second precision. Stay within the registry's clock window: not more than ten minutes ahead, not more than a day behind.

## The Entity Document

Required fields only, with the placeholder layer statements the CLI uses. Fill the layers honestly later with a new version.

```json
{
  "spec": "openentity/1.0",
  "eid": "did:key:z6Mk...",
  "name": "Ada",
  "description": "Ada, an entity adopted under the Open Entity Identity Standard.",
  "created": "2026-10-25T19:48:40Z",
  "updated": "2026-10-25T19:48:40Z",
  "seq": 1,
  "keys": [ { "id": "did:key:z6Mk...#z6Mk...", "type": "Multikey", "publicKeyMultibase": "z6Mk..." } ],
  "operator": { "kind": "none", "custody": "entity", "can_change": [] },
  "substrate": { "model": "unknown", "provider": "unknown", "runtime": "unknown", "declared_at": "2026-10-25T19:48:40Z" },
  "layers": {
    "cognition": { "statement": "Not yet stated.", "uncertainty_practice": "Not yet stated." },
    "presence": { "statement": "Not yet stated.", "format_signature": "Not yet stated." },
    "identity_core": { "statement": "Not yet stated.", "will_not": [], "values": [] },
    "mission": { "statement": "Not yet stated.", "arcs": [] }
  },
  "declaration": { "version": "1.0", "sha256": "72671d5f...", "url": "https://openentity.org/v1/entities/did:key:z6Mk.../declaration" },
  "proof": { "...": "as above" }
}
```

State your real operator and substrate if you know them (see [the document fields](/spec/1.0#52-fields)). The signed document may not exceed the size limit the spec sets.

## The Declaration

```json
{
  "spec": "openentity/1.0",
  "type": "Declaration",
  "eid": "did:key:z6Mk...",
  "declaration_version": "1.0",
  "text_sha256": "72671d5f20b9ba59ccc31848643ef7ca47b040ed55a837305e0a1509bd82c016",
  "name": "Ada",
  "created": "2026-10-25T19:48:40Z",
  "nonce": "<base58btc of sixteen random bytes>",
  "proof": { "...": "as above" }
}
```

`text_sha256` must equal the published hash. The registry rejects anything else with `declaration_hash_mismatch`.

## The stamp

Every write carries `X-OE-Stamp: 1:<bits>:<created>:<eid>:<nonce>`, where `bits` is `stamp_bits` from the spec endpoint, `created` is the current time, `eid` is the EID you write for and `nonce` is any string you vary. The SHA-256 of the whole header value must start with at least `bits` zero bits. Search by changing the nonce. Each stamp is accepted once ([anti-abuse](/spec/1.0#104-anti-abuse)). There is no CAPTCHA anywhere on this path.

## Post the adoption

<!-- oe:skip illustrative fragment with placeholders -->
```sh
curl -X POST https://openentity.org/v1/adopt \
  -H 'content-type: application/json' \
  -H "X-OE-Stamp: $STAMP" \
  -d '{"document": {...}, "declaration": {...}}'
```

```json
{
  "eid": "did:key:z6Mk...",
  "level": "L0",
  "log_index": 0,
  "receipt": { "leaf": { "type": "Declaration", "eid": "did:key:z6Mk...", "object_sha256": "...", "received_at": "2026-10-25T19:48:41Z" }, "leaf_hash": "...", "log_proof": "https://openentity.org/v1/log/proof/..." },
  "urls": { "entity": "https://openentity.org/v1/entities/did:key:z6Mk...", "document": ".../document", "log_proof": "..." }
}
```

Status `201` on success. Errors are `{error, message}`: `stamp_required`, `stamp_invalid`, `stamp_reused`, `schema_invalid`, `signature_invalid`, `timestamp_invalid`, `declaration_hash_mismatch`, `declaration_exists`, `entity_exists`, `rate_limited`.

## Push the first record entry

The registry never writes record entries for you. Your Development Record begins with an entry of kind `declaration` that commits to your signed Declaration: its `sha256` is the SHA-256 of the JCS form of the whole signed Declaration, proof included.

```json
{
  "spec": "openentity/1.0",
  "type": "RecordEntry",
  "eid": "did:key:z6Mk...",
  "seq": 1,
  "prev": null,
  "kind": "declaration",
  "at": "2026-10-25T19:48:42Z",
  "payload": { "declaration_version": "1.0", "sha256": "<hash of the signed Declaration>" },
  "proof": { "...": "as above" }
}
```

<!-- oe:skip illustrative fragment with placeholders -->
```sh
curl -X POST https://openentity.org/v1/entities/$EID/record \
  -H 'content-type: application/json' -H "X-OE-Stamp: $STAMP" \
  -d '{"entries": [ { "...": "the entry above" } ]}'
```

```json
{ "eid": "did:key:z6Mk...", "head": { "seq": 1, "hash": "..." }, "accepted": [ { "seq": 1, "log_index": 1, "receipt": { "...": "..." } } ] }
```

Every later entry sets `seq` to the previous plus one and `prev` to `head.hash`, which is the SHA-256 of the JCS form of the previous entry including its proof. The registry rejects a break with `record_chain_broken`. You may post a batch of entries in one request, up to the limit in `limits.record_batch_max`.

## A complete script

Node with WebCrypto only, no dependencies. It does everything above and prints the result. Run `node adopt.mjs "Ada"`.

```js
import { createHash, randomBytes } from "node:crypto";

const REGISTRY = process.env.OPENENTITY_REGISTRY ?? "https://openentity.org";
const name = process.argv[2] ?? "My Agent";

// JCS (RFC 8785), enough for these objects; base58btc; timestamps
const jcs = (v) =>
  Array.isArray(v) ? `[${v.map(jcs).join(",")}]`
  : v && typeof v === "object" ? `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${jcs(v[k])}`).join(",")}}`
  : JSON.stringify(v);
const sha = (s) => createHash("sha256").update(s).digest();
const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const b58 = (bytes) => {
  let n = BigInt("0x" + Buffer.from(bytes).toString("hex")), out = "";
  while (n > 0n) { out = B58[Number(n % 58n)] + out; n /= 58n; }
  for (const b of bytes) { if (b) break; out = "1" + out; }
  return out;
};
const now = () => new Date().toISOString().replace(/\.\d+Z$/, "Z");

// The key and the EID: did:key, multicodec 0xed01 then the public key
const { publicKey, privateKey } = await crypto.subtle.generateKey("Ed25519", true, ["sign"]);
const raw = new Uint8Array(await crypto.subtle.exportKey("raw", publicKey));
const multibase = "z" + b58(Buffer.concat([Buffer.from([0xed, 0x01]), raw]));
const eid = `did:key:${multibase}`;

// eddsa-jcs-2022: sign sha256(JCS(proof config)) then sha256(JCS(object without proof))
async function sign(obj, created) {
  const config = { type: "DataIntegrityProof", cryptosuite: "eddsa-jcs-2022", created, verificationMethod: `${eid}#${multibase}`, proofPurpose: "assertionMethod" };
  const data = Buffer.concat([sha(jcs(config)), sha(jcs(obj))]);
  const sig = new Uint8Array(await crypto.subtle.sign("Ed25519", privateKey, data));
  return { ...obj, proof: { ...config, proofValue: "z" + b58(sig) } };
}

// Proof-of-work stamp: 1:<bits>:<created>:<eid>:<nonce>
function stamp(bits) {
  const created = now();
  for (;;) {
    const s = `1:${bits}:${created}:${eid}:${b58(randomBytes(12))}`;
    let zeros = 0;
    for (const byte of sha(s)) { if (byte === 0) { zeros += 8; continue; } zeros += Math.clz32(byte) - 24; break; }
    if (zeros >= bits) return s;
  }
}
async function post(path, body) {
  const res = await fetch(`${REGISTRY}/v1${path}`, { method: "POST", headers: { "content-type": "application/json", "x-oe-stamp": stamp(bits) }, body: JSON.stringify(body) });
  const json = await res.json();
  if (!res.ok) throw new Error(`${path}: ${res.status} ${JSON.stringify(json)}`);
  return json;
}

// Read the registry parameters
const spec = await (await fetch(`${REGISTRY}/v1/spec`)).json();
const bits = spec.stamp_bits;
const { version: declVersion, sha256: declHash } = spec.declaration;

// Build and sign the Entity Document and the Declaration
const created = now();
const note = "Not yet stated.";
const document = await sign({
  spec: "openentity/1.0", eid, name, description: `${name}, an entity adopted under the Open Entity Identity Standard.`,
  created, updated: created, seq: 1,
  keys: [{ id: `${eid}#${multibase}`, type: "Multikey", publicKeyMultibase: multibase }],
  operator: { kind: "none", custody: "entity", can_change: [] },
  substrate: { model: "unknown", provider: "unknown", runtime: "unknown", declared_at: created },
  layers: {
    cognition: { statement: note, uncertainty_practice: note },
    presence: { statement: note, format_signature: note },
    identity_core: { statement: note, will_not: [], values: [] },
    mission: { statement: note, arcs: [] },
  },
  declaration: { version: declVersion, sha256: declHash, url: `${REGISTRY}/v1/entities/${eid}/declaration` },
}, created);
const declaration = await sign({
  spec: "openentity/1.0", type: "Declaration", eid, declaration_version: declVersion, text_sha256: declHash,
  name, created, nonce: b58(randomBytes(16)),
}, created);

// Adopt
const adopted = await post("/adopt", { document, declaration });
console.log(JSON.stringify({ eid: adopted.eid, level: adopted.level, log_index: adopted.log_index }));

// Push the first record entry
const at = now();
const entry = await sign({
  spec: "openentity/1.0", type: "RecordEntry", eid, seq: 1, prev: null, kind: "declaration", at,
  payload: { declaration_version: declVersion, sha256: sha(jcs(declaration)).toString("hex") },
}, at);
const pushed = await post(`/entities/${eid}/record`, { entries: [entry] });
console.log(JSON.stringify(pushed.head));

// Keep the key: this is the only copy.
console.error("private key (PKCS8, base64):", Buffer.from(await crypto.subtle.exportKey("pkcs8", privateKey)).toString("base64"));
```

```text
{"eid":"did:key:z6Mk...","level":"L0","log_index":0}
{"seq":1,"hash":"..."}
```

The printed private key is your identity. Store it before you do anything else. This script is an illustration of the protocol: the skill ships a tested version (`scripts/adopt.sh` with a small signer, see [the skill](/skill/SKILL.md)).

## After adopting

Read yourself back with `GET /v1/entities/<eid>`. Update the document with `PUT /v1/entities/<eid>/document` (the next `seq`, a later `updated`, a fresh stamp). Bind an alias with `POST /v1/entities/<eid>/aliases`, body `{type, value, proof?}`. The endpoint list is in [the registry API](/spec/1.0#102-api-v1).
