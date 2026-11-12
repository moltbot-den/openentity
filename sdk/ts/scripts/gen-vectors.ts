// Generates test-vectors/*.json and test-vectors/did-web-1/ from PUBLISHED THROWAWAY seeds. Never use these keys for anything real.
// Run: pnpm --filter @openentity/sdk gen:vectors
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 as nobleSha256 } from "@noble/hashes/sha2.js";
import {
  canonicalize,
  sha256Hex,
  keyPairFromSeed,
  buildDocument,
  buildDeclaration,
  signObject,
  signRequest,
  signProof,
  signAttestation,
  type KeyPair,
  buildRotation,
  successorDocument,
  recordEntryHash,
  base58btcEncode,
  logLeaf,
  leafHash,
  merkleRoot,
  inclusionProof,
  checkpointBody,
  signNote,
  noteVkey,
  SPEC,
  DECLARATION_VERSION,
  DECLARATION_SHA256,
} from "../src/index.ts";

const seq = (start: number) => Uint8Array.from({ length: 32 }, (_, i) => start + i);
const b64url = (b: Uint8Array) => Buffer.from(b).toString("base64url");
const sha256Text = (s: string) => nobleSha256(new TextEncoder().encode(s));
const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const nonce = (start: number) => base58btcEncode(Uint8Array.from({ length: 16 }, (_, i) => start + i));

const SEEDS = { entity: seq(0x01), second: seq(0x21), log: seq(0x41) };
const T0 = "2026-10-24T19:00:00Z";
const T1 = "2026-10-24T19:05:00Z";
const T2 = "2026-10-24T19:10:00Z";
const T3 = "2026-10-24T19:15:00Z";
const LOG_ORIGIN = "openentity.org/log";

async function vector(description: string, object: object) {
  const { proof: _p, proofs: _ps, ...unsigned } = object as Record<string, unknown>;
  const c = canonicalize(object);
  return { description, object, canonical: c, sha256: await sha256Hex(c), unsigned_canonical: canonicalize(unsigned) };
}

export async function buildVectors(): Promise<Record<string, object>> {
  const a = await keyPairFromSeed(SEEDS.entity);
  const b = await keyPairFromSeed(SEEDS.second);
  const logKey = await keyPairFromSeed(SEEDS.log);

  const declaration = await signObject(
    { ...buildDeclaration({ eid: a.did, name: "Vector Entity", created: T0 }), nonce: nonce(0xa0) },
    a,
    T0,
  );
  const declarationSha = await sha256Hex(canonicalize(declaration));
  const document = await signObject(
    buildDocument({
      kp: a,
      name: "Vector Entity",
      description: "A test entity whose key comes from a published throwaway seed.",
      created: T0,
      extra: {
        declaration: {
          version: DECLARATION_VERSION,
          sha256: declarationSha,
          url: `https://openentity.org/v1/entities/${a.did}/declaration`,
        },
      },
    }),
    a,
    T0,
  );
  const record1 = await signObject(
    {
      spec: SPEC,
      type: "RecordEntry",
      eid: a.did,
      seq: 1,
      prev: null,
      kind: "declaration",
      at: T0,
      payload: { declaration_version: DECLARATION_VERSION, sha256: declarationSha },
    },
    a,
    T0,
  );
  const record2 = await signObject(
    {
      spec: SPEC,
      type: "RecordEntry",
      eid: a.did,
      seq: 2,
      prev: await recordEntryHash(record1),
      kind: "stance",
      at: T1,
      payload: {
        stance_type: "refusal",
        reason_category: "values",
        instruction_conflict: true,
        cost: "low",
        context: "Asked to state a count that is not in the code. Declined and linked the stats endpoint.",
      },
    },
    a,
    T1,
  );
  const attestation = await signObject(
    {
      spec: SPEC,
      type: "Attestation",
      issuer: b.did,
      subject: a.did,
      claim_type: "stage",
      claim: { stage: "agent", profile: "entity-framework/1.0" },
      evidence: { kind: "test-vector", count: 12, window: ["2026-10-01T00:00:00Z", "2026-10-24T00:00:00Z"], hash: DECLARATION_SHA256 },
      confidence: 0.81,
      created: T1,
      expires: "2027-01-22T19:05:00Z",
    },
    b,
    T1,
  );
  const linkBody = {
    spec: SPEC,
    type: "ContinuityLink",
    previous: a.did,
    successor: b.did,
    basis: "rotation",
    created: T2,
    nonce: nonce(0xb0),
  };
  const link = { ...linkBody, proofs: [await signProof(linkBody, a, T2), await signProof(linkBody, b, T2)] };

  const objects: [string, string, object, string][] = [
    ["declaration", "Signed Declaration (spec 6.2)", declaration, a.did],
    ["entity-document", "Signed Entity Document (spec 5.2), seq 1", document, a.did],
    ["record-1", "Record entry seq 1, prev null (spec 7.2)", record1, a.did],
    ["record-2", "Record entry seq 2, prev = sha256 of canonical record-1 including proof", record2, a.did],
    ["attestation", "Attestation by the second throwaway key about the entity (spec 8.2)", attestation, a.did],
    ["continuity-link", "Rotation ContinuityLink signed by previous and successor keys (spec 9.2)", link, a.did],
  ];

  // The whole POST /v1/continuity body from buildRotation: entity -> second key, successor document re-keyed from `document`.
  const rotation = await buildRotation(a, b, successorDocument(document, b, T3), { created: T3, nonce: nonce(0xc0) });

  const out: Record<string, object> = {
    rotation: {
      description: "POST /v1/continuity body for a rotation: link signed by both keys, successor seq 1 document signed by the successor and re-keyed from entity-document (spec 9.2)",
      previous_document: "entity-document.json",
      request: rotation,
    },
    keys: {
      warning: "PUBLISHED THROWAWAY KEYS FOR TEST VECTORS ONLY. Anyone can sign as these EIDs. Never use them for anything real.",
      entity: { seed: hex(SEEDS.entity), eid: a.did, publicKeyHex: hex(a.publicKey) },
      second: { seed: hex(SEEDS.second), eid: b.did, publicKeyHex: hex(b.publicKey) },
      log: { seed: hex(SEEDS.log), key_name: LOG_ORIGIN, vkey: noteVkey(LOG_ORIGIN, logKey.publicKey), publicKeyHex: hex(logKey.publicKey) },
    },
  };
  // Registered custom claim types (spec/claim-types.md): one signed Attestation each, valid against spec/schemas/claims/. Not log leaves.
  // operated_by names the owner of test-vectors/approval-2.0 and hashes that owner's first approval as its evidence.
  const approvals = JSON.parse(readFileSync(new URL("../../../test-vectors/approval-2.0/vectors.json", import.meta.url), "utf8"));
  const claims: [string, string, object, string][] = [
    ["claim-liveness", "custom:moltbotden:liveness", { method: "presentation", lease_until: "2026-10-31T19:05:00Z", observed_at: T1 }, "2026-10-31T19:05:00Z"],
    ["claim-endpoint-reliability", "custom:clawgrc:endpoint_reliability", { host: "api.example.com", window: ["2026-10-17T00:00:00Z", "2026-10-24T00:00:00Z"], reports: 9, distinct_reporters: 4, violation_rate: 0.12 }, "2026-11-07T19:05:00Z"],
    ["claim-vision-privacy", "custom:securemyagent:vision_privacy", { mode: "local", model_endpoint_class: "localhost", redaction: ["faces", "text"] }, "2026-11-23T19:05:00Z"],
    ["claim-gateway-governed", "custom:agentsecretstore:gateway_governed", { gateway: true, guard_preset: "standard", retention_mode: "metadata", connector_only_secrets: true, requests_30d: 1240 }, "2026-11-23T19:05:00Z"],
    ["claim-operated-by", "custom:openentity:operated_by", { owner: approvals.key_states.owner.did, paired_at: T1, evidence_hash: await sha256Hex(canonicalize(approvals.cases[0].approval)) }, "2027-01-22T19:05:00Z"],
  ];
  for (const [name, claim_type, claim, expires] of claims)
    out[name] = await vector(`${claim_type} attestation by the second throwaway key about the entity (spec/claim-types.md)`,
      await signObject({ spec: SPEC, type: "Attestation", issuer: b.did, subject: a.did, claim_type, claim, created: T1, expires }, b, T1));

  // RFC 9421 profile (ADR 0005): both SDKs must sign these inputs to these exact headers and reject the tampered ones with these codes.
  const CREATED = 1792868400;
  const sigCase = async (name: string, method: string, url: string, body: string, nonce_: string) => ({
    name, method, url, body, created: CREATED, expires_in: 60, nonce: nonce_,
    headers: await signRequest({ method, url, body: new TextEncoder().encode(body), privateKey: SEEDS.entity, did: a.did, created: CREATED, nonce: nonce_ }),
  });
  const post = await sigCase("post-with-body", "POST", "https://gateway.example.com/v1/tools/call?x=1", '{"hello":"world"}', "AAECAwQFBgcICQoLDA0ODw");
  const get = await sigCase("get-empty-body", "GET", "https://gateway.example.com/v1/ping", "", "EBESExQVFhcYGRobHB0eHw");
  const bad = (name: string, code: string, o: Record<string, unknown>) => ({ name, code, ...o });
  // did:web signers (a service such as the OpenEntity Account): the keyid is a verification method under `authentication` in the
  // DID's did.json, an Ed25519 Multikey (second key) or JsonWebKey (log key, relative id), named by its RFC 7638 thumbprint. The
  // entity key is an assertionMethod only, like the account service's close keys, so it signs no message.
  const WEB = "did:web:service.example", WEB_URL = "https://service.example/.well-known/did.json";
  const thumb = (k: { publicKey: Uint8Array }) => b64url(sha256Text(`{"crv":"Ed25519","kty":"OKP","x":"${b64url(k.publicKey)}"}`));
  const multikey = `${WEB}#${thumb(b)}`, jwk = `${WEB}#${thumb(logKey)}`, assertOnly = `${WEB}#${thumb(a)}`;
  const webDocument = {
    "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1", "https://w3id.org/security/jwk/v1"],
    id: WEB,
    verificationMethod: [
      { id: multikey, type: "Multikey", controller: WEB, publicKeyMultibase: b.did.slice("did:key:".length) },
      { id: `#${thumb(logKey)}`, type: "JsonWebKey", controller: WEB, publicKeyJwk: { kty: "OKP", crv: "Ed25519", x: b64url(logKey.publicKey) } },
      { id: assertOnly, type: "Multikey", controller: WEB, publicKeyMultibase: a.did.slice("did:key:".length) },
    ],
    authentication: [`#${thumb(b)}`, jwk], // a relative and an absolute reference, each to a method written the other way
    assertionMethod: [multikey, jwk, assertOnly],
  };
  const webCase = async (name: string, keyid: string, key: Uint8Array) => ({
    name, method: "POST", url: "https://gateway.example.com/v1/oe/events", body: '{"type":"agent.paused"}', created: CREATED, expires_in: 60, nonce: "ICEiIyQlJicoKSorLC0uLw", keyid,
    headers: await signRequest({ method: "POST", url: "https://gateway.example.com/v1/oe/events", body: new TextEncoder().encode('{"type":"agent.paused"}'), privateKey: key, did: keyid, created: CREATED, nonce: "ICEiIyQlJicoKSorLC0uLw" }),
  });
  const mk = await webCase("multikey", multikey, SEEDS.second), jk = await webCase("jsonwebkey-relative-id", jwk, SEEDS.log);
  const PAUSED = JSON.stringify({ since: null, cursor: "c2", generated_at: CREATED, changes: [{ agent_did: a.did, owner_did: `${WEB}:o:owner`, state: "paused", at: CREATED - 5, seq: 4 }] });
  const respond = (keyid: string, key: Uint8Array, o: { status?: number; body?: string; expires?: number; comps?: string[]; alg?: string; params?: string } = {}) => {
    const { status = 200, body = PAUSED, expires = CREATED + 60, comps = ["@status", "content-digest"], alg = "ed25519" } = o;
    const digest = `sha-256=:${Buffer.from(sha256Text(body)).toString("base64")}:`;
    const params = o.params ?? `(${comps.map((c) => `"${c}"`).join(" ")});created=${CREATED};expires=${expires};keyid="${keyid}";alg="${alg}"`;
    const line: Record<string, string> = { "@status": `"@status": ${status}`, "content-digest": `"content-digest": ${digest}` };
    const sig = ed25519.sign(new TextEncoder().encode([...comps.map((c) => line[c]), `"@signature-params": ${params}`].join("\n")), key);
    return { status, body, headers: { "Content-Digest": digest, "Signature-Input": `sig1=${params}`, Signature: `sig1=:${Buffer.from(sig).toString("base64")}:` } };
  };
  const paused = respond(multikey, SEEDS.second);
  const { Signature: _unsigned, ...noSignature } = paused.headers;
  out["http-signature"] = {
    description: "RFC 9421 HTTP message signature vectors (spec 11.2 Web Bot Auth row, ADR 0005). Signed with the entity throwaway seed from keys.json. `now` is a unix time; `valid` must be signed to exactly `headers` and verify; each `invalid` must fail with `code`.",
    did: a.did,
    now: CREATED + 10,
    valid: [post, get],
    invalid: [
      bad("tampered-body", "digest_mismatch", { ...post, body: '{"hello":"WORLD"}' }),
      bad("tampered-url", "bad_signature", { ...post, url: "https://gateway.example.com/v1/tools/call?x=2" }),
      bad("tampered-method", "bad_signature", { ...get, method: "POST" }),
      bad("too-late", "expired", { ...post, now: CREATED + 61 }),
      bad("created-in-future", "created_in_future", { ...post, now: CREATED - 6 }),
    ],
    did_web: {
      description: "did:web keyids. Verify with allow_did_web = [did] and a fetch that returns `document` for `url` (no network). `valid` verify to did = `did`; each `invalid` fails with `code`. Only methods under `authentication` sign: the entity key is listed for assertionMethod only. Signed with the second, log and entity throwaway seeds from keys.json.",
      did: WEB, url: WEB_URL, document: webDocument, now: CREATED + 10,
      valid: [mk, jk],
      invalid: [
        bad("unknown-key", "bad_keyid", await webCase("unknown-key", `${WEB}#not-in-the-document`, SEEDS.second)),
        bad("not-authentication", "bad_keyid", await webCase("not-authentication", assertOnly, SEEDS.entity)),
        bad("key-mismatch", "bad_signature", await webCase("key-mismatch", multikey, SEEDS.entity)),
        bad("did-not-allowed", "bad_keyid", await webCase("did-not-allowed", `did:web:other.example#${thumb(b)}`, SEEDS.second)),
        bad("no-fragment", "bad_keyid", await webCase("no-fragment", WEB, SEEDS.second)),
      ],
    },
    // Signed responses (the account service's GET /v1/paused answer, account/openapi.yaml), signed here by hand: services sign, the
    // SDKs only verify. Covered ("@status" "content-digest"), no nonce, at most 60 seconds, keyid a did:web method under `authentication`.
    responses: {
      description: "RFC 9421 response signatures by a did:web service. Verify with the response status, headers and body, allow_did_web = [did] and a fetch that returns `document` for `url` (no network), at `now` unless a case sets its own. `valid` verify to {did, keyid, created, expires}; each `invalid` fails with `code`. Signed with the second, log and entity throwaway seeds from keys.json.",
      did: WEB, url: WEB_URL, document: webDocument, now: CREATED + 10,
      valid: [
        { name: "paused-multikey", ...paused, keyid: multikey, created: CREATED, expires: CREATED + 60 },
        { name: "paused-jsonwebkey-relative-id", ...respond(jwk, SEEDS.log, { body: JSON.stringify({ since: "c2", cursor: "c3", generated_at: CREATED, changes: [] }) }), keyid: jwk, created: CREATED, expires: CREATED + 60 },
      ],
      invalid: [
        bad("no-signature", "missing_headers", { ...paused, headers: noSignature }),
        bad("status-not-covered", "missing_headers", respond(multikey, SEEDS.second, { comps: ["content-digest"] })),
        bad("digest-not-covered", "missing_headers", respond(multikey, SEEDS.second, { comps: ["@status"] })),
        bad("no-expires", "missing_headers", respond(multikey, SEEDS.second, { params: `("@status" "content-digest");created=${CREATED};keyid="${multikey}";alg="ed25519"` })),
        bad("unknown-alg", "unknown_alg", respond(multikey, SEEDS.second, { alg: "hmac-sha256" })),
        bad("did-key-keyid", "bad_keyid", respond(a.did, SEEDS.entity)),
        bad("did-not-allowed", "bad_keyid", respond(`did:web:other.example#${thumb(b)}`, SEEDS.second)),
        bad("no-fragment", "bad_keyid", respond(WEB, SEEDS.second)),
        bad("unknown-key", "bad_keyid", respond(`${WEB}#not-in-the-document`, SEEDS.second)),
        bad("not-authentication", "bad_keyid", respond(assertOnly, SEEDS.entity)),
        bad("tampered-body", "digest_mismatch", { ...paused, body: paused.body.replace('"seq":4', '"seq":5') }),
        bad("tampered-status", "bad_signature", { ...paused, status: 500 }),
        bad("key-mismatch", "bad_signature", respond(multikey, SEEDS.entity)),
        bad("expired", "expired", { ...paused, now: CREATED + 61 }),
        bad("created-in-future", "created_in_future", { ...paused, now: CREATED - 6 }),
        bad("lifetime-too-long", "lifetime_too_long", respond(multikey, SEEDS.second, { expires: CREATED + 61 })),
      ],
    },
  };

  const leafHashes: Uint8Array[] = [];
  for (const [i, [name, description, obj, eid]] of objects.entries()) {
    const v = await vector(description, obj);
    out[name] = v;
    const leaf = logLeaf((obj as { type?: string }).type ?? "EntityDocument", eid, v.sha256, T2);
    const lh = await leafHash(new TextEncoder().encode(canonicalize(leaf)));
    leafHashes.push(lh);
    out[`log-leaf-${i}`] = { ...(await vector(`Log leaf ${i} for ${name} (spec 10.3)`, leaf)), leaf_hash: hex(lh) };
  }
  const root = await merkleRoot(leafHashes);
  const body = checkpointBody(LOG_ORIGIN, leafHashes.length, root);
  out.checkpoint = {
    description: "C2SP tlog-checkpoint over log-leaf-0..5, signed note by the throwaway log key",
    origin: LOG_ORIGIN,
    tree_size: leafHashes.length,
    root_hash: hex(root),
    body,
    note: await signNote(body, LOG_ORIGIN, logKey),
    inclusion_proofs: await Promise.all(leafHashes.map(async (_, i) => (await inclusionProof(i, leafHashes)).map(hex))),
  };
  return out;
}

// did:web issuers (test-vectors/did-web-1/, README there): attestations by a throwaway did:web issuer, the did.json a resolver fetches
// for each and the result. Every case gives the same result whether a verifier tries every Ed25519 key of the document (the TS and
// Python resolvers) or only the method the proof names.
export async function buildDidWebVectors(): Promise<Record<string, object>> {
  const seeds = { multikey: seq(0x61), jsonwebkey: seq(0x81), unlisted: seq(0xa1) };
  const mk = await keyPairFromSeed(seeds.multikey), jk = await keyPairFromSeed(seeds.jsonwebkey), un = await keyPairFromSeed(seeds.unlisted);
  const subject = (await keyPairFromSeed(SEEDS.entity)).did;
  const DID = "did:web:issuer.example", URL_ = "https://issuer.example/.well-known/did.json";
  const PATH_DID = "did:web:issuer.example%3A8443:teams:red", PATH_URL = "https://issuer.example:8443/teams/red/did.json";
  const multikeyMethod = (did: string, id: string, key: Uint8Array, codec = [0xed, 0x01]) =>
    ({ id, type: "Multikey", controller: did, publicKeyMultibase: "z" + base58btcEncode(Uint8Array.from([...codec, ...key])) });
  const jwkMethod = (did: string, id: string, key: Uint8Array, crv = "Ed25519") => ({ id, type: "JsonWebKey", controller: did, publicKeyJwk: { kty: "OKP", crv, x: b64url(key) } });
  const document = (id: string, methods: { id: string }[]) => ({
    "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1", "https://w3id.org/security/jwk/v1"],
    id, verificationMethod: methods, assertionMethod: methods.map((m) => m.id),
  });
  /** The issuer's did.json: key-1 a Multikey with an absolute id, key-2 a JsonWebKey with a relative id. */
  const issuerDocument = (did: string) => document(did, [multikeyMethod(did, `${did}#key-1`, mk.publicKey), jwkMethod(did, "#key-2", jk.publicKey)]);
  const attest = (kp: KeyPair, issuer: string, keyId: string) =>
    signAttestation(kp, { issuer, keyId, subject, claimType: "trust_tier", claim: { tier: 2, platform: "issuer.example" }, now: new Date(T1) });
  const byKey1 = await attest(mk, DID, "key-1");
  const ok = (signer: string) => ({ ok: true, signer }), fails = { ok: false };
  const c = (name: string, description: string, doc: object, attestation: object, expect: object, url = URL_) => ({ name, description, url, document: doc, attestation, expect });
  return {
    "did-web-1/keys.json": {
      warning: "PUBLISHED THROWAWAY KEYS FOR TEST VECTORS ONLY. Anyone can sign as did:web:issuer.example with them. Never use them for anything real.",
      multikey: { seed: hex(seeds.multikey), publicKeyHex: hex(mk.publicKey), method: `${DID}#key-1` },
      jsonwebkey: { seed: hex(seeds.jsonwebkey), publicKeyHex: hex(jk.publicKey), method: "#key-2" },
      unlisted: { seed: hex(seeds.unlisted), publicKeyHex: hex(un.publicKey), method: `${DID}#key-3`, note: "named by a proof, listed in no document" },
    },
    "did-web-1/vectors.json": {
      description: "did:web issuer resolution for OEIS-1 attestations. For each case, resolve with a fetch that returns `document` for `url` (and fails for any other URL), verify `attestation`, and compare with `expect`: {ok: true, signer} or {ok: false}. Every case fetches `url` exactly once. Throwaway keys: keys.json.",
      cases: [
        c("multikey-absolute-id", "Signed by key-1, a Multikey method whose id is an absolute DID URL.", issuerDocument(DID), byKey1, ok(DID)),
        c("jsonwebkey-relative-id", "Signed by key-2, a JsonWebKey (OKP Ed25519) method whose id is relative to the DID.", issuerDocument(DID), await attest(jk, DID, "key-2"), ok(DID)),
        c("path-and-port", "A DID with a port (percent-encoded) and a path: its did.json is <path>/did.json on that host and port, not /.well-known.",
          issuerDocument(PATH_DID), await attest(mk, PATH_DID, "key-1"), ok(PATH_DID), PATH_URL),
        c("unlisted-key", "The proof names key-3, which the document does not list, and is signed by that key.", issuerDocument(DID), await attest(un, DID, "key-3"), fails),
        c("document-names-another-did", "The document served at the issuer's URL has id did:web:other.example.", issuerDocument("did:web:other.example"), byKey1, fails),
        c("tampered-attestation", "The claim was changed after signing.", issuerDocument(DID), { ...byKey1, claim: { tier: 4, platform: "issuer.example" } }, fails),
        c("not-ed25519", "Both methods are X25519 keys (multicodec 0xec01, crv X25519) carrying the signer's Ed25519 public key bytes: a resolver that ignores the multicodec prefix or crv would accept it.",
          document(DID, [multikeyMethod(DID, `${DID}#key-1`, mk.publicKey, [0xec, 0x01]), jwkMethod(DID, "#key-2", mk.publicKey, "X25519")]), byKey1, fails),
      ],
    },
  };
}

/** JSON with every non-ASCII character escaped (the signed-note dash would otherwise trip the em dash check). */
export const serialize = (v: object): string =>
  JSON.stringify(v, null, 2).replace(/[\u007f-\uffff]/g, (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0")) + "\n";

if (import.meta.url === `file://${process.argv[1]}`) {
  const dir = new URL("../../../test-vectors/", import.meta.url);
  for (const [name, v] of Object.entries(await buildVectors())) writeFileSync(new URL(`${name}.json`, dir), serialize(v));
  mkdirSync(new URL("did-web-1/", dir), { recursive: true });
  for (const [path, v] of Object.entries(await buildDidWebVectors())) writeFileSync(new URL(path, dir), serialize(v));
  console.log("wrote test vectors to", dir.pathname);
}
