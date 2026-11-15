// Agent Commerce Check: the hosted POST /v1/commerce/check, its evidence chain and its single-use guards.
// The owner is the published throwaway owner of test-vectors/keylog-1/add-approver.json; its iPhone approver key signs the mandates.
import { readFileSync } from "node:fs";
import { p256 } from "@noble/curves/nist.js";
import { describe, expect, it } from "vitest";
import { E, adopted, call } from "./helpers.ts";
import { approvalDigest, cartDigest, generateKeyPair, mandateDigest, signRequest, type KeyPair } from "../src/sdk.ts";
import { evidenceIntact, sweepCommerce, type CommerceEnv } from "../src/commerce.ts";

const vec = (p: string) => JSON.parse(readFileSync(new URL(`../../test-vectors/${p}`, import.meta.url), "utf8"));
const LOG = vec("keylog-1/add-approver.json"), KEYS = vec("approval-2.0/keys.json").keys;
const OWNER = LOG.did as string;
const unhex = (h: string) => Uint8Array.from(h.match(/../g)!.map((x) => parseInt(x, 16)));
const b64url = (b: Uint8Array) => Buffer.from(b).toString("base64url");
const sign = (digest: Uint8Array) => ({ device_id: KEYS.ios.kid, form: "p256", signature: b64url(p256.sign(digest, unhex(KEYS.ios.secret), { prehash: false, lowS: true })) });

let statusAnswer: unknown = "active";
const CE: CommerceEnv = {
  ...E,
  commerceOwner: async (did) => (did === OWNER ? { lines: LOG.log, serviceKeys: LOG.service_keys, origins: LOG.origins } : null),
  commerceStatus: async (url) => (statusAnswer === null ? null : { mandate_id: url.split("/")[5], status: statusAnswer }),
};
const B32 = "abcdefghijklmnopqrstuvwxyz234567";
let n = 0;
const mdId = () => `md_${"a".repeat(25)}${B32[++n % 32]}`;

const MERCHANT = "did:web:shop.example";
const T = Math.floor(Date.now() / 1000);
function mandate(agent: string, o: Record<string, unknown> = {}) {
  const id = mdId();
  const b = {
    version: "mandate/1", mandate_id: id, issuer_did: OWNER, agent_did: agent, issued_at: T - 60, expires_at: T + 10 * 86400,
    limits: { currency: "USD", per_tx_max: 5000, period: "P1D", period_max: 20000, total_max: 100000 },
    scope: { merchants: [MERCHANT], rails: ["credits", "card"] }, step_up_over: 2500,
    status: `https://account.openentity.org/v1/mandates/${id}/status`, ...o,
  };
  return { ...b, signature: sign(mandateDigest(b)) };
}
const cart = (agent: string, total: number, mandateId: string | null) => ({
  profile: "cart/1", merchant: MERCHANT, agent_did: agent, lines: [{ sku: "lst_1", title: "Dataset", qty: 1, unit: total }], total, currency: "USD", rail: "credits", mandate_id: mandateId,
});
let ipN = 0;
async function check(kp: KeyPair, o: { cart: unknown; mandate?: unknown; policy?: object; approval?: unknown; tamper?: boolean; headers?: Record<string, string>; ip?: string }) {
  const url = "https://shop.example/buy";
  const sig = o.headers ?? (await signRequest({ method: "POST", url, privateKey: kp, did: kp.did }));
  const body = { request: { method: "POST", url: o.tamper ? url + "?x=1" : url, headers: sig }, cart: o.cart, policy: o.policy ?? {}, mandate: o.mandate, approval: o.approval };
  const r = await call("POST", "/commerce/check", body, { "x-forwarded-for": o.ip ?? `10.1.${(ipN >> 8) & 255}.${++ipN & 255}` }, CE);
  return { ...r, headers: sig };
}
const POLICY = { require_mandate: true, require_owner: true };

describe("Agent Commerce Check", () => {
  it("allows a cart a live mandate covers and returns evidence the merchant can check", async () => {
    const kp = await generateKeyPair(), m = mandate(kp.did);
    const r = await check(kp, { cart: cart(kp.did, 1000, m.mandate_id), mandate: m, policy: POLICY });
    expect(r.body).toMatchObject({ decision: "allow", reasons: ["mandate_covers_cart"], agent_did: kp.did, owner_did: OWNER, mandate_id: m.mandate_id });
    const ev = await call("GET", `/commerce/evidence/${r.body.evidence_id}`);
    expect(ev.body).toMatchObject({ decision: "allow", intact: true, agent_did: kp.did, verifier_version: "commerce-check/1" });
    expect(ev.body.checks.map((c: any) => `${c.check}:${c.result}`)).toEqual(["signature:pass", "registry:pass", "owner:pass", "security:pass", "mandate:pass", "policy:pass"]);
    expect(ev.body.mandate_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("carries the mandate in the OE-Mandate header too", async () => {
    const kp = await generateKeyPair(), m = mandate(kp.did);
    const headers = { ...(await signRequest({ method: "POST", url: "https://shop.example/buy", privateKey: kp, did: kp.did })), "OE-Mandate": b64url(new TextEncoder().encode(JSON.stringify(m))) };
    const r = await check(kp, { cart: cart(kp.did, 1000, m.mandate_id), headers, policy: POLICY });
    expect(r.body.decision).toBe("allow");
  });

  it("answers step_up with the cart summary above step_up_over, and allows it once the owner approved that exact cart", async () => {
    const kp = await generateKeyPair(), m = mandate(kp.did), c = cart(kp.did, 4000, m.mandate_id);
    const up = await check(kp, { cart: c, mandate: m, policy: POLICY });
    expect(up.body).toMatchObject({ decision: "step_up", reasons: ["step_up_over"], cart: c, cart_digest: cartDigest(c) });
    const a = { version: "approval/2.0", verifier_did: "did:web:shop.example", owner_did: OWNER, request_id: "req_1", payload_digest: cartDigest(c), decision: "approve", expires_at: T + 300 };
    const approval = { approval: { ...a, ...sign(approvalDigest(a)) }, verifier_did: a.verifier_did, request_id: a.request_id };
    const ok = await check(kp, { cart: c, mandate: m, policy: POLICY, approval });
    expect(ok.body).toMatchObject({ decision: "allow", reasons: ["owner_approved_cart", "step_up_over"] });
    // The same approval cannot buy twice.
    const again = await check(kp, { cart: c, mandate: m, policy: POLICY, approval });
    expect(again.body).toMatchObject({ decision: "deny", reasons: ["approval_replayed"] });
    // An approval of another cart does not approve this one.
    const other = cart(kp.did, 4100, m.mandate_id);
    const wrong = await check(kp, { cart: other, mandate: m, policy: POLICY, approval: { ...approval, request_id: "req_2" } });
    expect(wrong.body.decision).toBe("step_up");
  });

  it("steps up a cart with no mandate when the merchant does not require one", async () => {
    const kp = await generateKeyPair();
    const r = await check(kp, { cart: cart(kp.did, 900, null), policy: {} });
    expect(r.body).toMatchObject({ decision: "step_up", reasons: ["no_mandate"] });
  });

  it("denies: bad signature, replayed request, wrong agent, dead mandate, missing mandate, other owner's mandate", async () => {
    const kp = await generateKeyPair(), other = await generateKeyPair(), m = mandate(kp.did), c = cart(kp.did, 1000, m.mandate_id);
    expect((await check(kp, { cart: c, mandate: m, policy: POLICY, tamper: true })).body).toMatchObject({ decision: "deny", reasons: ["request_unverified"] });
    const first = await check(kp, { cart: c, mandate: m, policy: POLICY });
    expect(first.body.decision).toBe("allow");
    // The very same signed request again: nonce already used.
    expect((await check(kp, { cart: c, mandate: m, policy: POLICY, headers: first.headers })).body).toMatchObject({ decision: "deny", reasons: ["request_replayed"] });
    // Another agent presents this agent's mandate.
    const stolen = await check(other, { cart: cart(other.did, 1000, m.mandate_id), mandate: m, policy: POLICY });
    expect(stolen.body).toMatchObject({ decision: "deny", reasons: ["mandate_wrong_agent"] });
    // A cart for another agent than the signer.
    expect((await check(other, { cart: c, mandate: m, policy: POLICY })).body.reasons).toEqual(["agent_mismatch"]);
    expect((await check(kp, { cart: c, policy: POLICY })).body).toMatchObject({ decision: "deny", reasons: ["mandate_required", "owner_unknown"] });
    // Tampered limits break the owner's signature.
    const forged = { ...m, limits: { ...m.limits, per_tx_max: 999999 } };
    expect((await check(kp, { cart: c, mandate: forged, policy: POLICY })).body.reasons).toEqual(["mandate_bad_signature"]);
    // An owner this registry cannot read a key log for.
    const m2 = mandate(kp.did, { issuer_did: "did:web:account.openentity.org:o:" + "a".repeat(52) });
    expect((await check(kp, { cart: cart(kp.did, 1000, m2.mandate_id), mandate: m2, policy: POLICY })).body.reasons).toEqual(["no_key_log"]);
    statusAnswer = "revoked";
    const m3 = mandate(kp.did);
    expect((await check(kp, { cart: cart(kp.did, 1000, m3.mandate_id), mandate: m3, policy: POLICY })).body.reasons).toEqual(["mandate_revoked"]);
    statusAnswer = null; // status unreachable: only a mandate that expires within a day is accepted
    expect((await check(kp, { cart: cart(kp.did, 1000, m3.mandate_id), mandate: m3, policy: POLICY })).body.reasons).toEqual(["mandate_status_required"]);
    const short = mandate(kp.did, { expires_at: T + 3600 });
    expect((await check(kp, { cart: cart(kp.did, 1000, short.mandate_id), mandate: short, policy: POLICY })).body.decision).toBe("allow");
    statusAnswer = "active";
  });

  it("applies registry facts: level, withdrawn, security band, and a live ClawGRC violation", async () => {
    const kp = (await adopted("Agent One")).kp, m = mandate(kp.did), c = cart(kp.did, 1000, m.mandate_id);
    const ok = (policy: object) => check(kp, { cart: c, mandate: m, policy: { ...POLICY, ...policy } }).then((r) => r.body);
    expect((await ok({ min_level: 1 })).reasons).toEqual(["level_too_low"]);
    expect((await ok({ min_level: 0 })).decision).toBe("allow");
    const issuer = "did:web:securemyagent.ai", fake = "did:web:self-issued.example";
    expect((await ok({ min_security_band: "good" })).reasons).toEqual(["security_band_too_low"]);
    const att = (sha: string, by: string, type: string, claim: object) => E.db.run("INSERT INTO attestations (sha256, issuer, subject, claim_type, json, created, expires) VALUES ($1,$2,$3,$4,$5,$6,$7)", [sha, by, kp.did, type, JSON.stringify({ claim }), new Date().toISOString(), new Date(Date.now() + 86400_000).toISOString()]);
    await att("p1", fake, "custom:securemyagent:security_posture", { score_band: "strong" });
    expect((await ok({ min_security_band: "good" })).reasons).toEqual(["security_band_too_low"]); // not an accredited observer
    await E.db.run("INSERT INTO observers (did, name, accredited_at) VALUES ($1, 'SMA', $2)", [issuer, new Date().toISOString()]);
    await att("p2", issuer, "custom:securemyagent:security_posture", { score_band: "strong" });
    expect((await ok({ min_security_band: "good", accept_issuers: [issuer] })).decision).toBe("allow");
    await att("v1", issuer, "custom:clawgrc:violation", { policy: "x" });
    expect((await ok({ min_security_band: "good" })).reasons).toEqual(["clawgrc_violation"]);
    expect((await ok({})).decision).toBe("allow"); // no security minimum: a violation is the merchant's to weigh
    await E.db.run("UPDATE entities SET withdrawn_at = $1 WHERE eid = $2", [new Date().toISOString(), kp.did]);
    expect((await ok({})).reasons).toEqual(["agent_withdrawn"]);
  });

  it("chains the evidence: each record names the hash of the one before, and an edit breaks its own hash", async () => {
    const kp = await generateKeyPair();
    const ids: string[] = [];
    for (let i = 0; i < 3; i++) ids.push((await check(kp, { cart: cart(kp.did, 100, null), policy: {} })).body.evidence_id);
    const recs = [];
    for (const id of ids) recs.push((await call("GET", `/commerce/evidence/${id}`)).body);
    expect(recs[1].prev_hash).toBe(recs[0].hash);
    expect(recs[2].prev_hash).toBe(recs[1].hash);
    expect(recs[2].seq).toBe(recs[0].seq + 2);
    expect((await call("GET", "/commerce/head")).body).toMatchObject({ seq: recs[2].seq, hash: recs[2].hash });
    const { intact: _i, ...plain } = recs[0];
    expect(await evidenceIntact(plain)).toBe(true);
    expect(await evidenceIntact({ ...plain, decision: "allow" })).toBe(false);
    expect((await call("GET", "/commerce/evidence/ev_" + "a".repeat(26))).status).toBe(404);
  });

  it("denies when an owner key log entry changes after this registry saw it, or the log shrinks", async () => {
    const kp = await generateKeyPair(), m = mandate(kp.did), c = cart(kp.did, 1000, m.mandate_id);
    const run = async (lines: string[]) => {
      const env: CommerceEnv = { ...CE, commerceOwner: async () => ({ lines, serviceKeys: LOG.service_keys, origins: LOG.origins }) };
      const sig = await signRequest({ method: "POST", url: "https://shop.example/buy", privateKey: kp, did: kp.did });
      return (await call("POST", "/commerce/check", { request: { method: "POST", url: "https://shop.example/buy", headers: sig }, cart: c, mandate: m, policy: POLICY }, { "x-forwarded-for": "10.7.7.7" }, env)).body.reasons;
    };
    expect(await run(LOG.log)).toEqual(["mandate_covers_cart"]);
    expect(await run([LOG.log[0] + " ", ...LOG.log.slice(1)])).toEqual(["owner_key_log_fork"]);
    expect(await run(LOG.log.slice(0, 1))).toEqual(["owner_key_log_fork"]);
  });

  it("verifies a mandate on its own", async () => {
    const kp = await generateKeyPair(), m = mandate(kp.did), ip = { "x-forwarded-for": "10.6.6.6" };
    const v = (body: object) => call("POST", "/commerce/mandate", body, ip, CE).then((r) => r.body);
    expect(await v({ mandate: m, agent_did: kp.did })).toMatchObject({ ok: true, mandate_id: m.mandate_id, owner_did: OWNER, step_up_over: 2500 });
    expect(await v({ mandate: m, agent_did: (await generateKeyPair()).did })).toMatchObject({ ok: false, error: "wrong_agent" });
    expect(await v({ mandate: { ...m, step_up_over: 9 } })).toMatchObject({ ok: false, error: "bad_signature" });
    expect((await call("POST", "/commerce/mandate", { nope: 1 }, ip, CE)).body.error).toBe("bad_request");
  });

  it("deletes evidence after 400 days", async () => {
    const kp = await generateKeyPair();
    const id = (await check(kp, { cart: cart(kp.did, 100, null), policy: {} })).body.evidence_id;
    await E.db.run("UPDATE commerce_evidence SET created_at = $1 WHERE evidence_id = $2", [new Date(Date.now() - 401 * 86400_000).toISOString(), id]);
    await sweepCommerce(E);
    expect((await call("GET", `/commerce/evidence/${id}`)).status).toBe(404);
  });

  it("rate limits per IP, needs no key or stamp, and rejects a malformed body", async () => {
    expect((await call("POST", "/commerce/check", { nope: 1 }, { "x-forwarded-for": "10.9.9.9" }, CE)).body.error).toBe("bad_request");
    let last = 0;
    for (let i = 0; i < 31; i++) last = (await call("POST", "/commerce/check", { nope: 1 }, { "x-forwarded-for": "10.8.8.8" }, CE)).status;
    expect(last).toBe(429);
  });
});
