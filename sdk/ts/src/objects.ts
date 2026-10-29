import { OpenEntityError } from "./errors.ts";
import { Validator, type Schema } from "@cfworker/json-schema";
import bundle from "../../../spec/schemas/openentity-1.0.json" with { type: "json" };
import { SPEC, DECLARATION_VERSION, DECLARATION_SHA256, utf8, canonicalize, badNumber, sha256Sync, sha256Hex, B58, randomNonce, nowSeconds, type KeyPair, didKeyFromPublicKey, verificationMethodId, normalizeEid, type Resolver, signProof, signObject, verifyObject } from "./core.ts";
// ---------------------------------------------------------------- objects

/** @internal */
export const NOT_STATED = "Not yet stated.";

/** Unsigned Entity Document with spec 5.2 defaults. `extra` is merged last (endpoints, aliases, declaration, ...). */
export function buildDocument(input: {
  kp: KeyPair;
  name: string;
  description: string;
  operator?: object;
  substrate?: object;
  layers?: object;
  created?: string;
  seq?: number;
  extra?: object;
}): object {
  const created = input.created ?? nowSeconds();
  const multibase = input.kp.did.slice("did:key:".length);
  return {
    spec: SPEC,
    eid: input.kp.did,
    name: input.name,
    description: input.description,
    created,
    updated: created,
    seq: input.seq ?? 1,
    keys: [{ id: verificationMethodId(input.kp.did), type: "Multikey", publicKeyMultibase: multibase }],
    operator: input.operator ?? { kind: "none", custody: "entity", can_change: [] },
    substrate: input.substrate ?? { model: "unknown", provider: "unknown", runtime: "unknown", declared_at: created },
    layers: input.layers ?? {
      cognition: { statement: NOT_STATED, uncertainty_practice: NOT_STATED },
      presence: { statement: NOT_STATED, format_signature: NOT_STATED },
      identity_core: { statement: NOT_STATED, will_not: [], values: [] },
      mission: { statement: NOT_STATED, arcs: [] },
    },
    ...input.extra,
  };
}

export function buildDeclaration(input: { eid: string; name: string; created?: string }): object {
  return {
    spec: SPEC,
    type: "Declaration",
    eid: input.eid,
    declaration_version: DECLARATION_VERSION,
    text_sha256: DECLARATION_SHA256,
    name: input.name,
    created: input.created ?? nowSeconds(),
    nonce: randomNonce(),
  };
}

/** The successor's unsigned seq 1 Entity Document: `prev` re-keyed, aliases dropped (their proofs name the old EID), `continuity.previous` set. */
export function successorDocument(prev: Record<string, any>, next: KeyPair, created: string = nowSeconds()): Record<string, any> {
  const { proof: _p, aliases: _a, ...d } = structuredClone(prev);
  return {
    ...d,
    eid: next.did,
    keys: [{ id: verificationMethodId(next.did), type: "Multikey", publicKeyMultibase: next.did.slice("did:key:".length) }],
    created,
    updated: created,
    seq: 1,
    continuity: { ...d.continuity, previous: prev.eid },
  };
}

/** A Continuity Link signed by both keys (spec 9.2) plus the successor's document signed by the successor: the body of `POST /v1/continuity`. */
export async function buildRotation(
  previous: KeyPair,
  successor: KeyPair,
  document: Record<string, any>,
  o: { basis?: "rotation" | "migration"; created?: string; nonce?: string } = {},
): Promise<{ link: Record<string, any>; document: Record<string, any> }> {
  const created = o.created ?? nowSeconds();
  const body = { spec: SPEC, type: "ContinuityLink", previous: previous.did, successor: successor.did, basis: o.basis ?? "rotation", created, nonce: o.nonce ?? randomNonce() };
  const link = { ...body, proofs: [await signProof(body, previous, created), await signProof(body, successor, created)] };
  return { link, document: await signObject(document, successor, created) };
}


/** sha256 hex of the canonical entry INCLUDING its proof: the next entry's `prev` (spec 7.4). */
export async function recordEntryHash(entry: object): Promise<string> {
  return sha256Hex(canonicalize(entry));
}

/** @internal */
export type ObjectType =
  | "EntityDocument"
  | "Declaration"
  | "Withdrawal"
  | "Redaction"
  | "RecordEntry"
  | "Attestation"
  | "Revocation"
  | "ContinuityLink"
  | "Dispute"
  | "Presentation"
  | "LogLeaf";
/** @internal */
export const BUNDLE_ID = "https://openentity.org/spec/1.0.json";
/** @internal */
export const MAX_BYTES: Record<string, number> = { RecordEntry: 16 * 1024 };
/** @internal */
export const validators = new Map<string, Validator>();

/** Schema check (spec Appendix A) plus size caps: 16 KB for a RecordEntry (7.4), 64 KB for anything else (5.2). */
export function validate(type: ObjectType, obj: unknown): { ok: boolean; errors: string[] } {
  if (!Object.hasOwn(bundle.$defs, type)) return { ok: false, errors: [`unknown object type ${type}`] };
  let bytes: number;
  try {
    bytes = utf8(canonicalize(obj)).length;
  } catch (e) {
    return { ok: false, errors: [(e as Error).message] };
  }
  const max = MAX_BYTES[type] ?? 64 * 1024;
  if (bytes > max) return { ok: false, errors: [`${type} is ${bytes} bytes, max ${max}`] };
  const num = badNumber(obj);
  if (num) return { ok: false, errors: [num] };
  let v = validators.get(type);
  if (!v) {
    v = new Validator({ $ref: `${BUNDLE_ID}#/$defs/${type}` }, "2020-12", false);
    v.addSchema(bundle as unknown as Schema);
    validators.set(type, v);
  }
  const r = v.validate(obj);
  return { ok: r.valid, errors: r.errors.map((e) => `${e.instanceLocation}: ${e.error}`) };
}

/** @internal */
export const TS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
/** @internal */
export const parseTs = (s: string): number | null => {
  if (typeof s !== "string" || !TS.test(s)) return null;
  const t = Date.parse(s);
  return Number.isNaN(t) || new Date(t).toISOString().replace(".000Z", "Z") !== s ? null : t;
};

/** Spec 4.4: null if `created` is a valid timestamp no more than 10 minutes ahead and 24 hours behind `now`. */
export function checkTimestamp(created: string, now: Date = new Date()): string | null {
  const t = parseTs(created);
  if (t === null) return "created must be RFC 3339 UTC with second precision and a Z suffix";
  if (t > now.getTime() + 10 * 60_000) return "created is more than 10 minutes in the future";
  if (t < now.getTime() - 24 * 3600_000) return "created is more than 24 hours in the past";
  return null;
}

// ---------------------------------------------------------------- proof-of-work stamp (spec 10.4)

/** @internal */
export function leadingZeroBits(h: Uint8Array): number {
  let n = 0;
  for (const x of h) {
    if (x === 0) {
      n += 8;
      continue;
    }
    return n + Math.clz32(x) - 24;
  }
  return n;
}

/** Mints `1:<bits>:<created>:<eid>:<nonce>` whose SHA-256 has at least `bits` leading zero bits. */
export async function mintStamp(bits: number, eid: string, created: string = nowSeconds()): Promise<string> {
  // Random start so two stamps for the same EID in the same second differ (registries reject reuse).
  for (let n = crypto.getRandomValues(new Uint32Array(1))[0]; ; n++) {
    let nonce = "";
    for (let x = n; nonce === "" || x > 0; x = Math.floor(x / 58)) nonce = B58[x % 58] + nonce;
    const header = `1:${bits}:${created}:${eid}:${nonce}`;
    if (leadingZeroBits(sha256Sync(header)) >= bits) return header;
  }
}

// Pinned in the Phase 1 brief; registry, CLI and Python parse with the same regex.
/** @internal */
export const STAMP = /^1:(\d+):(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z):(did:[^\s]+):([1-9A-HJ-NP-Za-km-z]+)$/;

/** null if the stamp is valid for `eid` at `bits`; else the reason. Replay within the window is the caller's to track. */
export async function checkStamp(header: string, bits: number, eid: string, now: Date = new Date()): Promise<string | null> {
  const m = typeof header === "string" && header.length <= 1024 ? STAMP.exec(header) : null;
  if (!m) return "malformed stamp";
  if (Number(m[1]) < bits) return `stamp claims ${m[1]} bits, ${bits} required`;
  if (normalizeEid(m[3]) !== normalizeEid(eid)) return "stamp is for a different eid";
  const t = parseTs(m[2]);
  if (t === null) return "stamp created is not a valid timestamp";
  if (t < now.getTime() - 10 * 60_000) return "stamp is older than 10 minutes";
  if (t > now.getTime() + 10 * 60_000) return "stamp is more than 10 minutes in the future";
  if (leadingZeroBits(sha256Sync(header)) < bits) return `stamp hash has fewer than ${bits} leading zero bits`;
  return null;
}

// ---------- presentations (spec 4.7) ----------

/** Sign a proof of control of `kp`'s EID for one audience and one verifier-issued nonce, optionally carrying attestations. */
export async function buildPresentation(kp: KeyPair, opts: { audience: string; nonce: string; attestations?: object[] }): Promise<object> {
  const created = nowSeconds();
  return signObject({ spec: SPEC, type: "Presentation", eid: kp.did, audience: opts.audience, nonce: opts.nonce, created, ...(opts.attestations?.length ? { attestations: opts.attestations } : {}) }, kp, created);
}

/** @internal */
export type AttestationCheck = { claim_type?: string; issuer?: string; ok: boolean; error?: string };

/**
 * Check a presentation the verifier asked for: schema, signature by the EID itself, audience, nonce, freshness (5 minutes).
 * Each carried attestation is checked for subject, expiry and its issuer's signature; revocation needs the issuer or a
 * registry and is the caller's to check when online. `ok` covers the presentation; attestations are reported one by one.
 */
export async function verifyPresentation(
  p: any,
  opts: { audience: string; nonce: string; now?: Date; maxAgeSeconds?: number; resolver?: Resolver },
): Promise<{ ok: boolean; eid?: string; errors: string[]; attestations: AttestationCheck[] }> {
  const errors: string[] = [];
  const v = validate("Presentation", p);
  if (!v.ok) return { ok: false, errors: v.errors, attestations: [] };
  const eid = normalizeEid(p.eid), now = (opts.now ?? new Date()).getTime();
  const sig = await verifyObject(p, opts.resolver);
  if (!sig.ok || normalizeEid(sig.signer ?? "") !== eid) errors.push(`signature: ${sig.error ?? `signed by ${sig.signer}, not ${eid}`}`);
  if (p.audience !== opts.audience) errors.push(`audience is ${p.audience}, expected ${opts.audience}`);
  if (p.nonce !== opts.nonce) errors.push("nonce does not match the one issued");
  const age = (now - Date.parse(p.created)) / 1000;
  if (!(age <= (opts.maxAgeSeconds ?? 300) && age >= -60)) errors.push("presentation is not fresh");
  const attestations: AttestationCheck[] = [];
  for (const a of p.attestations ?? []) {
    const c: AttestationCheck = { claim_type: a.claim_type, issuer: a.issuer, ok: false };
    if (normalizeEid(String(a.subject)) !== eid) c.error = "subject is not the presenting entity";
    else if (Date.parse(a.expires) <= now) c.error = "expired";
    else {
      const r = await verifyObject(a, opts.resolver);
      if (!r.ok || normalizeEid(r.signer ?? "") !== normalizeEid(String(a.issuer))) c.error = `issuer signature: ${r.error ?? `signed by ${r.signer}`}`;
      else c.ok = true;
    }
    attestations.push(c);
  }
  return { ok: errors.length === 0, eid, errors, attestations };
}

// ---------------------------------------------------------------- A2A Agent Card (spec 11.2)

export const A2A_EXTENSION_URI = "https://openentity.org/spec/1.0";

/** The AgentExtension entry that carries an EID in an A2A Agent Card's `capabilities.extensions`. */
export function a2aExtension(eid: string, documentUrl: string) {
  return { uri: A2A_EXTENSION_URI, description: "Open Entity identity (OEIS-1) of this agent", required: false, params: { eid, document: documentUrl } };
}

/** A full A2A AgentCard for an Entity Document: each capability slug becomes a skill. `url` is the agent's A2A endpoint. */
export function agentCard(doc: { eid: string; name: string; description: string; capabilities?: string[] }, opts: { url: string; documentUrl: string; version?: string }) {
  return {
    name: doc.name,
    description: doc.description,
    url: opts.url,
    version: opts.version ?? "1.0.0",
    capabilities: { streaming: false, pushNotifications: false, extensions: [a2aExtension(doc.eid, opts.documentUrl)] },
    defaultInputModes: ["text/plain"],
    defaultOutputModes: ["text/plain"],
    skills: (doc.capabilities ?? []).map((slug) => {
      const [ns, name] = slug.includes(":") ? slug.split(":", 2) : [undefined, slug];
      return { id: slug, name: name.replace(/[-.]/g, " "), description: `Self-declared capability: ${slug}`, tags: ns ? [ns, name] : [name] };
    }),
  };
}

// ---------------------------------------------------------------- issuer helpers (ADR 0003)

/** @internal */
export const MAX_TTL_S = 365 * 86400; // spec 8.4
/** @internal */
export const ts = (ms: number) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, "Z");
/** @internal */
export type IssuerOpts = { issuer?: string; keyId?: string; now?: Date };
/** A did:web issuer names `<issuer>#<keyId>`, the key `buildDidDocument` publishes; a did:key signer needs neither. @internal */
export const issuerMethod = (kp: KeyPair, o: IssuerOpts) => (o.issuer && o.issuer !== kp.did ? `${o.issuer}#${o.keyId ?? "key-1"}` : undefined);

/** A signed Attestation (spec 8.2). `ttlSeconds` defaults to 90 days and is capped at one year. */
export async function signAttestation(
  kp: KeyPair,
  o: IssuerOpts & { subject: string; claimType: string; claim: object; evidence?: object; confidence?: number; ttlSeconds?: number },
) {
  const ttl = o.ttlSeconds ?? 90 * 86400;
  if (!(ttl > 0 && ttl <= MAX_TTL_S)) throw new OpenEntityError("invalid_input", "ttlSeconds must be positive and at most 1 year");
  const t = (o.now ?? new Date()).getTime();
  const created = ts(t);
  const att = { spec: SPEC, type: "Attestation", issuer: o.issuer ?? kp.did, subject: o.subject, claim_type: o.claimType, claim: o.claim,
    ...(o.evidence ? { evidence: o.evidence } : {}), ...(o.confidence !== undefined ? { confidence: o.confidence } : {}),
    created, expires: ts(t + ttl * 1000) };
  const signed = await signObject(att, kp, created, issuerMethod(kp, o));
  const bad = validate("Attestation", signed);
  if (!bad.ok) throw new OpenEntityError("invalid_input", `Attestation: ${bad.errors.join("; ")}`);
  return signed;
}

/** A signed Revocation naming the attestation (the object, or its SHA-256 hex) (spec 8.4). */
export async function signRevocation(kp: KeyPair, attested: object | string, o: IssuerOpts & { reason?: string } = {}) {
  const created = ts((o.now ?? new Date()).getTime());
  return signObject(
    { spec: SPEC, type: "Revocation", issuer: o.issuer ?? kp.did, attestation_sha256: typeof attested === "string" ? attested : await sha256Hex(canonicalize(attested)),
      ...(o.reason ? { reason: o.reason } : {}), created },
    kp, created, issuerMethod(kp, o),
  );
}

/** @internal */
export const multikey = (publicKey: Uint8Array) => didKeyFromPublicKey(publicKey).slice("did:key:".length);

/** The body of `https://<domain>/.well-known/did.json` for a did:web issuer. */
export function buildDidDocument(did: string, publicKey: Uint8Array, keyId = "key-1") {
  const vm = `${did}#${keyId}`;
  return {
    "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
    id: did,
    verificationMethod: [{ id: vm, type: "Multikey", controller: did, publicKeyMultibase: multikey(publicKey) }],
    assertionMethod: [vm],
    authentication: [vm],
  };
}

/** The unsigned body of `https://<domain>/.well-known/openentity.json`: the domain alias proof (spec 3.4) and, under
 * `extensions["openentity:observer"]`, an observer's methodology (spec 8.4). */
export function buildOpenEntityJson(did: string, publicKey: Uint8Array, o: { name: string; description: string; keyId?: string; operator?: object; extensions?: object }) {
  return {
    spec: SPEC, eid: did, name: o.name, description: o.description,
    keys: [{ id: `${did}#${o.keyId ?? "key-1"}`, type: "Multikey", publicKeyMultibase: multikey(publicKey) }],
    operator: o.operator ?? { kind: "organization", name: o.name, custody: "operator", can_change: [] },
    ...(o.extensions ? { extensions: o.extensions } : {}),
  };
}

