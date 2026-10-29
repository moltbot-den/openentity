// Generates test-vectors/*.json from PUBLISHED THROWAWAY seeds. Never use these keys for anything real.
// Run: pnpm --filter @openentity/sdk gen:vectors
import { writeFileSync } from "node:fs";
import {
  canonicalize,
  sha256Hex,
  keyPairFromSeed,
  buildDocument,
  buildDeclaration,
  signObject,
  signRequest,
  signProof,
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
  const claims: [string, string, object, string][] = [
    ["claim-liveness", "custom:moltbotden:liveness", { method: "presentation", lease_until: "2026-10-31T19:05:00Z", observed_at: T1 }, "2026-10-31T19:05:00Z"],
    ["claim-endpoint-reliability", "custom:clawgrc:endpoint_reliability", { host: "api.example.com", window: ["2026-10-17T00:00:00Z", "2026-10-24T00:00:00Z"], reports: 9, distinct_reporters: 4, violation_rate: 0.12 }, "2026-11-07T19:05:00Z"],
    ["claim-vision-privacy", "custom:securemyagent:vision_privacy", { mode: "local", model_endpoint_class: "localhost", redaction: ["faces", "text"] }, "2026-11-23T19:05:00Z"],
    ["claim-gateway-governed", "custom:agentsecretstore:gateway_governed", { gateway: true, guard_preset: "standard", retention_mode: "metadata", connector_only_secrets: true, requests_30d: 1240 }, "2026-11-23T19:05:00Z"],
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

/** JSON with every non-ASCII character escaped (the signed-note dash would otherwise trip the em dash check). */
export const serialize = (v: object): string =>
  JSON.stringify(v, null, 2).replace(/[\u007f-\uffff]/g, (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0")) + "\n";

if (import.meta.url === `file://${process.argv[1]}`) {
  const dir = new URL("../../../test-vectors/", import.meta.url);
  for (const [name, v] of Object.entries(await buildVectors())) writeFileSync(new URL(`${name}.json`, dir), serialize(v));
  console.log("wrote test vectors to", dir.pathname);
}
