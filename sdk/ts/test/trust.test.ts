import { beforeEach, describe, expect, it } from "vitest";
import * as oe from "../src/index.ts";

const seeded = (n: number) => oe.keyPairFromSeed(Uint8Array.from({ length: 32 }, () => n));
const MBD = "did:web:moltbotden.com", GRC = "did:web:api.clawgrc.com", SMA = "did:web:securemyagent.ai", EVIL = "did:web:evil.example";
const KEYS: Record<string, oe.KeyPair> = { [MBD]: await seeded(10), [GRC]: await seeded(11), [SMA]: await seeded(12), [EVIL]: await seeded(13) };
const SUBJECT = (await seeded(1)).did;
const NOW = new Date();
const ago = (ms: number) => new Date(NOW.getTime() - ms);
const H = 3600_000, D = 24 * H;
const evidence = "0".repeat(64);

const att = (did: string, claimType: string, claim: object, o: { ttlSeconds?: number; now?: Date } = {}) =>
  oe.signAttestation(KEYS[did], { issuer: did, subject: SUBJECT, claimType, claim, now: ago(H), ...o });
const row = async (a: any, rev: any = null, extra = {}) => ({ sha256: await oe.sha256Hex(oe.canonicalize(a)), attestation: a, revocation: rev, revoked_at: rev?.created ?? null, ...extra });

function registry(rows: any[], entity: object = {}) {
  const calls: string[] = [];
  const fetchJson = async (url: string) => {
    calls.push(url);
    if (url.endsWith("/did.json")) {
      const did = `did:web:${new URL(url).host}`;
      return oe.buildDidDocument(did, KEYS[did].publicKey);
    }
    return url.endsWith("/attestations") ? { attestations: rows } : { eid: SUBJECT, level: "L2", withdrawn: false, ...entity };
  };
  return { calls, fetchJson };
}

beforeEach(() => oe.clearTrustCache());

async function full() {
  const old = await att(MBD, "trust_tier", { tier: 1, platform: "m" }, { ttlSeconds: 60 * 86400, now: ago(2 * D) });
  const viol = (policy: string, severity: string) => att(GRC, "custom:clawgrc:violation", { policy, severity, evidence_hash: evidence, observed_at: "2026-10-01T00:00:00Z" });
  const [live, struck] = [await viol("p", "high"), await viol("q", "low")];
  const rev = await oe.signRevocation(KEYS[GRC], struck, { issuer: GRC, reason: "dispute upheld" });
  const rows = [
    await row(old), await row(await att(MBD, "trust_tier", { tier: 3, platform: "m" })), await row(await att(GRC, "trust_tier", { tier: 2, platform: "g" })),
    await row(await att(SMA, "custom:securemyagent:security_posture", { score_band: "A", checks_passed: [], scanner_version: "1", evidence_hash: evidence })),
    await row(live), await row(struck, rev),
  ];
  return { rows, struck };
}

describe("trust()", () => {
  it("builds the report from registry reads only", async () => {
    const { rows, struck } = await full();
    const reg = registry(rows);
    const r = await oe.trust(SUBJECT, { fetchJson: reg.fetchJson });
    expect([r.ok, r.level, r.withdrawn]).toEqual([true, "L2", false]);
    expect(r.trustTier).toEqual({ [MBD]: 3, [GRC]: 2 });
    expect(r.securityPosture?.score_band).toBe("A");
    expect(r.violations.map((v) => [v.severity, v.policy])).toEqual([["high", "p"]]);
    expect(r.revocations.map((x) => [x.sha256, x.reason])).toEqual([[await oe.sha256Hex(oe.canonicalize(struck)), "dispute upheld"]]);
    expect(reg.calls.every((u) => /^https:\/\/(openentity\.org\/v1\/|moltbotden\.com|api\.clawgrc\.com|securemyagent\.ai)/.test(u))).toBe(true);
  });
  it("caches for five minutes", async () => {
    const reg = registry((await full()).rows);
    const a = await oe.trust(SUBJECT, { fetchJson: reg.fetchJson }), n = reg.calls.length;
    expect(await oe.trust(SUBJECT, { fetchJson: reg.fetchJson })).toBe(a);
    expect(reg.calls.length).toBe(n);
  });
  it("fails closed on a forged claim, a foreign key, a hidden strike, a missing revocation, a wrong subject and a dead registry", async () => {
    const good = await att(MBD, "trust_tier", { tier: 4, platform: "m" });
    const viol = await att(GRC, "custom:clawgrc:violation", { policy: "p", severity: "critical", evidence_hash: evidence, observed_at: "2026-10-01T00:00:00Z" });
    const cases: Record<string, any[]> = {
      "forged claim": [{ ...(await row(good)), attestation: { ...good, claim: { tier: 4, platform: "evil" } } }],
      "signed by another key": [await row(await oe.signAttestation(KEYS[EVIL], { issuer: MBD, subject: SUBJECT, claimType: "trust_tier", claim: { tier: 4, platform: "x" }, now: NOW }))],
      "hidden strike": [await row(viol, await oe.signRevocation(KEYS[MBD], viol, { issuer: GRC }))],
      "revocation not carried": [{ ...(await row(viol)), revoked_at: "2026-10-02T00:00:00Z" }],
      "wrong subject": [await row(await oe.signAttestation(KEYS[MBD], { issuer: MBD, subject: SUBJECT.slice(0, -1) + "x", claimType: "trust_tier", claim: { tier: 4 }, now: NOW }))],
    };
    for (const [name, rows] of Object.entries(cases)) {
      oe.clearTrustCache();
      const r = await oe.trust(SUBJECT, { fetchJson: registry(rows).fetchJson });
      expect([name, r.ok, !!r.error, r.trustTier, r.level]).toEqual([name, false, true, {}, undefined]);
    }
    expect((await oe.trust(SUBJECT, { fetchJson: async () => { throw new Error("registry down"); } })).ok).toBe(false);
    expect((await oe.trust("not-a-did", { fetchJson: registry([]).fetchJson })).ok).toBe(false);
    expect((await oe.trust(SUBJECT, { fetchJson: registry([], { eid: "did:key:other" }).fetchJson })).ok).toBe(false);
  });
  it("ignores expired attestations and issuers it does not read, without fetching them", async () => {
    const expired = await att(MBD, "trust_tier", { tier: 4, platform: "m" }, { ttlSeconds: 86400, now: ago(3 * D) });
    const reg = registry([await row(expired), await row(await att(EVIL, "trust_tier", { tier: 4, platform: "x" }))]);
    const r = await oe.trust(SUBJECT, { fetchJson: reg.fetchJson });
    expect([r.ok, r.trustTier]).toEqual([true, {}]);
    expect(reg.calls.some((u) => u.includes("evil.example"))).toBe(false);
  });
  it("reports withdrawn", async () => {
    expect((await oe.trust(SUBJECT, { fetchJson: registry([], { withdrawn: true }).fetchJson })).withdrawn).toBe(true);
  });
});
