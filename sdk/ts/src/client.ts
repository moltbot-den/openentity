// The rest of the registry client: the same calls as the Python client (withdraw, record, dispute, find, present).
import { OpenEntityError } from "./errors.ts";
import { SPEC, DECLARATION_VERSION, canonicalize, sha256Hex, nowSeconds, randomNonce, type KeyPair, signObject } from "./core.ts";
import { mintStamp, buildPresentation } from "./objects.ts";
import { registryJson } from "./registry.ts";

/** The registry every call uses unless given another. */
export const DEFAULT_REGISTRY = "https://openentity.org";

const base = (registry?: string) => (registry ?? DEFAULT_REGISTRY).replace(/\/+$/, "");
async function postSigned(registry: string, path: string, body: object, kp: KeyPair, bits?: number) {
  bits ??= (await registryJson(`${registry}/v1/spec`)).stamp_bits as number;
  return registryJson(registry + path, { method: "POST", headers: { "content-type": "application/json", "x-oe-stamp": await mintStamp(bits, kp.did) }, body: JSON.stringify(body) });
}

/** Withdraw the Declaration (spec 6.3). Irreversible: the EID stays in the log, marked withdrawn. `name` defaults to the registered one. */
export async function withdraw(kp: KeyPair, o: { registry?: string; name?: string } = {}) {
  const registry = base(o.registry);
  const name = o.name ?? (await registryJson(`${registry}/v1/entities/${kp.did}`)).document.name;
  const w = await signObject({ spec: SPEC, type: "Withdrawal", eid: kp.did, declaration_version: DECLARATION_VERSION, name, created: nowSeconds(), nonce: randomNonce() }, kp);
  return postSigned(registry, "/v1/withdraw", w, kp);
}

/**
 * Append `[kind, payload]` entries to the Development Record, chained from the registry's head (seq + 1, prev = hash of the last
 * entry), and push them in batches of up to 100 (spec 7.4).
 */
export async function record(kp: KeyPair, entries: [string, object][], o: { registry?: string } = {}) {
  const registry = base(o.registry);
  const head = (await registryJson(`${registry}/v1/entities/${kp.did}/record?after=0`)).head;
  let seq: number = head ? head.seq : 0, prev: string | null = head ? head.hash : null;
  const signed: object[] = [];
  for (const [kind, payload] of entries) {
    const at = nowSeconds();
    const e = await signObject({ spec: SPEC, type: "RecordEntry", eid: kp.did, seq: ++seq, prev, kind, at, payload }, kp, at);
    signed.push(e);
    prev = await sha256Hex(canonicalize(e));
  }
  const bits = (await registryJson(`${registry}/v1/spec`)).stamp_bits as number;
  for (let i = 0; i < signed.length; i += 100) await postSigned(registry, `/v1/entities/${kp.did}/record`, { entries: signed.slice(i, i + 100) }, kp, bits);
  return { accepted: signed.length, entries: signed };
}

/** The reasons a Dispute may give (spec 10.5). */
export const DISPUTE_REASONS = ["impersonation", "illegal_content", "inaccurate", "other"] as const;
export type DisputeReason = (typeof DISPUTE_REASONS)[number];

/** File a signed Dispute about `subject`, or about one of its objects (spec 10.5). */
export async function dispute(kp: KeyPair, o: { subject: string; reason: DisputeReason; statement: string; objectSha256?: string; registry?: string }) {
  if (!DISPUTE_REASONS.includes(o.reason)) throw new OpenEntityError("invalid_input", `reason must be one of ${DISPUTE_REASONS.join(", ")}`);
  if (o.objectSha256 !== undefined && !/^[0-9a-f]{64}$/.test(o.objectSha256)) throw new OpenEntityError("invalid_input", "object_sha256 must be 64 lowercase hex characters");
  const d = await signObject({ spec: SPEC, type: "Dispute", issuer: kp.did, subject: o.subject, ...(o.objectSha256 ? { object_sha256: o.objectSha256 } : {}),
    reason: o.reason, statement: o.statement, created: nowSeconds(), nonce: randomNonce() }, kp);
  return postSigned(base(o.registry), "/v1/disputes", d, kp);
}

/** Directory search (spec 10.5). */
export async function find(o: { registry?: string; capability?: string; q?: string; aliasType?: string; level?: string } = {}) {
  const qs = new URLSearchParams();
  for (const [k, v] of [["capability", o.capability], ["q", o.q], ["alias_type", o.aliasType], ["level", o.level]] as [string, string | undefined][]) if (v) qs.set(k, v);
  return registryJson(`${base(o.registry)}/v1/entities?${qs}`);
}

/** Answer a verifier's challenge (spec 4.7). With a registry, carries the entity's current attestations (at most 20). */
export async function present(kp: KeyPair, o: { audience: string; nonce: string; registry?: string }) {
  let attestations: object[] = [];
  if (o.registry) {
    const rows: any[] = (await registryJson(`${base(o.registry)}/v1/entities/${kp.did}/attestations`)).attestations ?? [];
    attestations = rows.filter((r) => !r.expired && !r.revoked_at && !r.inherited_from).map((r) => r.attestation).slice(0, 20);
  }
  return buildPresentation(kp, { audience: o.audience, nonce: o.nonce, attestations });
}
