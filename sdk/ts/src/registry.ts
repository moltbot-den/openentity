import { OpenEntityError, registryError } from "./errors.ts";
import { SPEC, DECLARATION_VERSION, DECLARATION_SHA256, canonicalize, sha256Hex, nowSeconds, type KeyPair, generateKeyPair, publicKeyFromDidKey, type Resolver, defaultResolver, signObject, verifyObject } from "./core.ts";
import { buildDocument, buildDeclaration, successorDocument, buildRotation, mintStamp } from "./objects.ts";
/**
 * Rotate `previous` to a new key in one call: fetch the current document, build and sign the link, mint the stamp for the
 * successor and submit. Nothing is persisted: on success the caller saves `successor` (its `privateJwk`) and only then retires
 * the old key. Throws on any non-2xx answer.
 */
export async function rotate(o: { previous: KeyPair; registry?: string; successor?: KeyPair; basis?: "rotation" | "migration" }) {
  const registry = (o.registry ?? "https://openentity.org").replace(/\/+$/, "");
  const call = async (path: string, init?: RequestInit) => {
    const r = await fetch(registry + path, init);
    const text = await r.text();
    if (!r.ok) throw registryError(r.status, path, text);
    return JSON.parse(text);
  };
  const next = o.successor ?? (await generateKeyPair());
  const prevDoc = await call(`/v1/entities/${o.previous.did}/document`);
  const { link, document } = await buildRotation(o.previous, next, successorDocument(prevDoc, next), { basis: o.basis });
  const { stamp_bits } = await call("/v1/spec");
  const response = await call("/v1/continuity", {
    method: "POST",
    headers: { "content-type": "application/json", "x-oe-stamp": await mintStamp(stamp_bits, next.did) },
    body: JSON.stringify({ link, document }),
  });
  return { successor: next, link, document, response };
}
// ---------------------------------------------------------------- adopt with a client label

/** The registry's allowlist for the unsigned `client` label on POST /v1/adopt. */
export const CLIENTS = ["adk", "crewai", "goose", "langchain", "mastra", "openai-agents", "ui-tars", "vercel-ai", "cli", "other"] as const;
export type Client = (typeof CLIENTS)[number];

/** @internal */
export async function registryJson(url: string, init?: RequestInit): Promise<any> {
  const r = await fetch(url, init);
  const text = await r.text();
  if (!r.ok) throw registryError(r.status, url, text);
  return JSON.parse(text);
}

/** Adopt `kp` on a registry: document, Declaration and the seq-1 declaration entry (spec 5.2, 6.2, 7.3). `client` is not signed. */
export async function adopt(kp: KeyPair, o: { name: string; description?: string; registry?: string; client?: Client }) {
  if (o.client && !CLIENTS.includes(o.client)) throw new OpenEntityError("invalid_input", `client must be one of ${CLIENTS.join(", ")}`);
  const registry = (o.registry ?? "https://openentity.org").replace(/\/+$/, "");
  const created = nowSeconds();
  const document = await signObject(
    buildDocument({ kp, name: o.name, description: o.description ?? "An Open Entity adopted through the TypeScript SDK.", created,
      extra: { declaration: { version: DECLARATION_VERSION, sha256: DECLARATION_SHA256, url: `${registry}/v1/entities/${kp.did}/declaration` } } }),
    kp, created);
  const declaration = await signObject(buildDeclaration({ eid: kp.did, name: o.name, created }), kp, created);
  const { stamp_bits } = await registryJson(`${registry}/v1/spec`);
  const post = async (path: string, body: object) =>
    registryJson(registry + path, { method: "POST", headers: { "content-type": "application/json", "x-oe-stamp": await mintStamp(stamp_bits, kp.did) }, body: JSON.stringify(body) });
  const response = await post("/v1/adopt", { document, declaration, ...(o.client ? { client: o.client } : {}) });
  const at = nowSeconds();
  const entry = await signObject({ spec: SPEC, type: "RecordEntry", eid: kp.did, seq: 1, prev: null, kind: "declaration", at,
    payload: { declaration_version: DECLARATION_VERSION, sha256: await sha256Hex(canonicalize(declaration)) } }, kp, at);
  // The registry never writes entries; on failure the signed entry is returned so the caller can push it later.
  const recordPushed = await post(`/v1/entities/${kp.did}/record`, { entries: [entry] }).then(() => true, () => false);
  return { response, did: kp.did, document, declaration, recordEntry: entry, recordPushed };
}

// ---------------------------------------------------------------- trust(eid): one TrustReport from registry reads (ADR 0002)

/** @internal */
export const MOLTBOTDEN = "did:web:moltbotden.com", CLAWGRC = "did:web:api.clawgrc.com";
/** @internal */
export const SMA = ["did:web:securemyagent.ai", "did:pkh:eip155:8453:0x62fef02E2859726EC1c0B534853Ad2cdd5FdDE1a"];
/** @internal */
export const TIER = "trust_tier", POSTURE = "custom:securemyagent:security_posture", VIOLATION = "custom:clawgrc:violation";
/** claim_type to the issuers whose attestations are read; everything else is ignored. @internal */
export const ACCEPT: Record<string, string[]> = { [TIER]: [MOLTBOTDEN, CLAWGRC], [POSTURE]: SMA, [VIOLATION]: [CLAWGRC] };
/** @internal */
export const TRUST_CACHE_MS = 300_000;

export interface TrustReport {
  eid: string;
  /** false: a read failed or a signature did not verify. Treat the entity as untrusted. */
  ok: boolean;
  error?: string;
  level?: string;
  withdrawn: boolean;
  /** issuer DID to its newest live tier (0 to 4) */
  trustTier: Record<string, number>;
  /** claim of the newest live custom:securemyagent:security_posture */
  securityPosture: Record<string, any> | null;
  /** live custom:clawgrc:violation */
  violations: { issuer: string; severity: string; policy: string; observed_at: string; sha256: string }[];
  /** verified revocations of the accepted attestations */
  revocations: { sha256: string; claim_type: string; issuer: string; reason?: string; at: string }[];
}
/** @internal */
export type FetchJson = (url: string) => Promise<any>;
/** @internal */
export const trustCache = new Map<string, { at: number; report: TrustReport }>();
export const clearTrustCache = () => trustCache.clear();

/** did:web through /.well-known/did.json (or <path>/did.json); everything else offline. */
export function didWebResolver(fetchJson: FetchJson = registryJson): Resolver {
  return async (did) => {
    if (!did.startsWith("did:web:")) return defaultResolver(did);
    const [host, ...path] = did.slice(8).split(":").map(decodeURIComponent);
    const doc = await fetchJson(`https://${host}/${path.length ? path.join("/") : ".well-known"}/did.json`);
    if (doc.id !== did) throw new OpenEntityError("verification_failed", `${did} document names ${doc.id}`);
    const ed25519: Uint8Array[] = [];
    for (const vm of doc.verificationMethod ?? []) {
      try {
        ed25519.push(publicKeyFromDidKey("did:key:" + vm.publicKeyMultibase));
      } catch {
        /* not an Ed25519 Multikey */
      }
    }
    return { ed25519 };
  };
}

/**
 * One TrustReport from `GET /v1/entities/{eid}` and `/attestations` only. Every attestation and revocation from the accepted
 * issuers is verified locally against the issuer's key; any failure returns an untrusted report. Cached for 5 minutes.
 */
export async function trust(eid: string, o: { registry?: string; now?: Date; fetchJson?: FetchJson; resolver?: Resolver } = {}): Promise<TrustReport> {
  const registry = (o.registry ?? "https://openentity.org").replace(/\/+$/, "");
  const key = `${registry} ${eid}`, hit = trustCache.get(key);
  if (hit && Date.now() - hit.at < TRUST_CACHE_MS) return hit.report;
  try {
    const report = await readTrust(eid, registry, (o.now ?? new Date()).getTime(), o.fetchJson ?? registryJson, o.resolver ?? didWebResolver(o.fetchJson));
    trustCache.set(key, { at: Date.now(), report });
    return report;
  } catch (e) { // fail closed on anything: network, registry, schema, signature
    return { eid, ok: false, error: (e as Error).message, withdrawn: false, trustTier: {}, securityPosture: null, violations: [], revocations: [] };
  }
}

/** @internal */
export async function readTrust(eid: string, base: string, now: number, get: FetchJson, resolver: Resolver): Promise<TrustReport> {
  if (!eid.startsWith("did:")) throw new OpenEntityError("invalid_input", "eid must be a DID");
  const ent = await get(`${base}/v1/entities/${eid}`);
  if (ent.eid !== eid) throw new OpenEntityError("verification_failed", `registry answered for ${ent.eid}`);
  const rows: any[] = (await get(`${base}/v1/entities/${eid}/attestations`)).attestations;
  const report: TrustReport = { eid, ok: true, level: ent.level, withdrawn: !!ent.withdrawn, trustTier: {}, securityPosture: null, violations: [], revocations: [] };
  for (const r of [...rows].sort((x, y) => (y.attestation.created > x.attestation.created ? 1 : -1))) {
    const a = r.attestation, ct: string = a.claim_type;
    if (!(ACCEPT[ct] ?? []).some((i) => i.toLowerCase() === String(a.issuer).toLowerCase())) continue;
    if (r.inherited_from && ct !== VIOLATION) continue; // a rotation does not carry positive claims; a strike follows the entity
    const sha: string = r.sha256;
    if (a.subject !== (r.inherited_from ?? eid) || (await sha256Hex(canonicalize(a))) !== sha) throw new OpenEntityError("verification_failed", `attestation ${sha} does not match what the registry served`);
    const v = await verifyObject(a, resolver);
    if (!v.ok || v.signer !== a.issuer) throw new OpenEntityError("verification_failed", `attestation ${sha}: ${v.error ?? `signed by ${v.signer}`}`);
    const rv = r.revocation;
    if (rv) {
      const rvv = await verifyObject(rv, resolver);
      if (!rvv.ok || rvv.signer !== a.issuer || rv.attestation_sha256 !== sha) throw new OpenEntityError("verification_failed", `revocation of ${sha}: ${rvv.error ?? `signed by ${rvv.signer}`}`);
      report.revocations.push({ sha256: sha, claim_type: ct, issuer: a.issuer, reason: rv.reason, at: rv.created });
    } else if (r.revoked_at) throw new OpenEntityError("verification_failed", `registry reports a revocation of ${sha} it does not carry`);
    if (rv || Date.parse(a.expires) <= now) continue;
    const c = a.claim;
    if (ct === TIER) report.trustTier[a.issuer] ??= c.tier;
    else if (ct === POSTURE) report.securityPosture ??= c;
    else report.violations.push({ issuer: a.issuer, severity: c.severity, policy: c.policy, observed_at: c.observed_at, sha256: sha });
  }
  return report;
}

