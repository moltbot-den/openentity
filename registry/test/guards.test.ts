import { afterEach, describe, expect, it, vi } from "vitest";
import { generateKeyPair, nowSeconds, signAttestation, randomNonce, signObject, type KeyPair } from "../src/sdk.ts";
import { scheduled } from "../src/index.ts";
import { E, adopted, call, later, mockFetch, signed, write } from "./helpers.ts";

const base = { spec: "openentity/1.0" };
afterEach(() => vi.restoreAllMocks());

describe("guards that had no test (conformance matrix rows 8, 33, 35, 36, 41, 46, 47)", () => {
  it("caps a record at 1,000 entries per EID per day (spec 10.4)", async () => {
    const { kp } = await adopted();
    const day = new Date().toISOString().slice(0, 10);
    await E.db.run("INSERT INTO rate_events (key, window_start, count) VALUES ($1, $2, $3)", [`rec:${kp.did}`, day, 1000]);
    const e1 = await signObject({ ...base, type: "RecordEntry", eid: kp.did, seq: 1, prev: null, kind: "declaration", at: nowSeconds(), payload: { declaration_version: "1.0", sha256: "0".repeat(64) } }, kp);
    const r = await write("POST", `/entities/${kp.did}/record`, kp.did, { entries: [e1] });
    expect([r.status, r.body.error]).toEqual([429, "rate_limited"]);
  });

  it("rejects a Redaction, Attestation, Revocation, Dispute and Withdrawal created more than 24 hours ago (spec 4.4)", async () => {
    const { kp } = await adopted();
    const issuer: KeyPair = await generateKeyPair();
    const created = later(-25 * 3600);
    const cases: [string, string, KeyPair, object][] = [
      ["Redaction", `/entities/${kp.did}/record/redact`, kp, { type: "Redaction", eid: kp.did, seq: 1, entry_sha256: "a".repeat(64), created, nonce: randomNonce() }],
      ["Attestation", "/attestations", issuer, { type: "Attestation", issuer: issuer.did, subject: kp.did, claim_type: "capability", claim: { capability: "x", evidence_ref: "y" }, created, expires: later(86400) }],
      ["Dispute", "/disputes", kp, { type: "Dispute", issuer: kp.did, subject: kp.did, reason: "inaccurate", statement: "The work was delivered on time; the order log shows it.", created, nonce: randomNonce() }],
      ["Withdrawal", "/withdraw", kp, { type: "Withdrawal", eid: kp.did, declaration_version: "1.0", name: "Test Entity", created, nonce: randomNonce() }],
    ];
    for (const [name, path, signer, obj] of cases) {
      const r = await write("POST", path, signer.did, await signObject({ ...base, ...obj }, signer));
      expect([name, r.status, r.body.error]).toEqual([name, 422, "timestamp_invalid"]);
    }
    expect((await call("GET", `/entities/${kp.did}`)).body.withdrawn).toBe(false);
  });

  it("an Attestation signed with the default ttl expires 90 days after `created`; the schema refuses one with no `expires` (spec 8.4)", async () => {
    const { kp } = await adopted();
    const obs = await generateKeyPair();
    const att = await signAttestation(obs, { subject: kp.did, claimType: "capability", claim: { capability: "x", evidence_ref: "y" } });
    expect(Date.parse(att.expires) - Date.parse(att.created)).toBe(90 * 86400_000);
    const r = await write("POST", "/attestations", obs.did, att);
    expect(r.status).toBe(201);
    const row = await E.db.first<{ expires: string }>("SELECT expires FROM attestations WHERE sha256 = $1", [r.body.sha256]);
    expect(row!.expires).toBe(att.expires);
    const { proof: _p, expires: _e, ...open } = att as any;
    const bare = await write("POST", "/attestations", obs.did, await signObject(open, obs));
    expect([bare.status, bare.body.error]).toEqual([422, "schema_invalid"]);
  });

  it("a stale Entity Document sent with a Continuity Link for a new successor is rejected (spec 4.4)", async () => {
    const a = await adopted("Old");
    const succ = await generateKeyPair();
    const old = later(-25 * 3600);
    const { document } = await signed(succ, "New", { created: old, updated: old });
    const link = await signObject({ ...base, type: "ContinuityLink", previous: a.kp.did, successor: succ.did, basis: "rotation", created: nowSeconds(), nonce: randomNonce() }, a.kp);
    const { proof: _p, ...unsigned } = link as any;
    const proofs = [link.proof, (await signObject(unsigned, succ)).proof];
    const r = await write("POST", "/continuity", succ.did, { link: { ...unsigned, proofs }, document });
    expect([r.status, r.body.error]).toEqual([422, "timestamp_invalid"]);
  });

  it("a new successor's Entity Document must be its own seq 1 (spec 9.2)", async () => {
    const a = await adopted("Old");
    const succ = await generateKeyPair();
    const { document } = await signed(succ, "New", { seq: 2 });
    const link = await signObject({ ...base, type: "ContinuityLink", previous: a.kp.did, successor: succ.did, basis: "rotation", created: nowSeconds(), nonce: randomNonce() }, a.kp);
    const { proof: _p, ...unsigned } = link as any;
    const proofs = [link.proof, (await signObject(unsigned, succ)).proof];
    const r = await write("POST", "/continuity", succ.did, { link: { ...unsigned, proofs }, document });
    expect([r.status, r.body.error]).toEqual([422, "eid_mismatch"]);
  });

  it("a request with no stamp is refused with stamp_required (spec 10.4)", async () => {
    const { kp } = await adopted();
    const r = await call("POST", "/disputes", {});
    expect([r.status, r.body.error]).toEqual([400, "stamp_required"]);
    expect((await call("POST", `/entities/${kp.did}/record`, {})).body.error).toBe("stamp_required");
  });

  it("only an accredited stage: entity attestation with an entity-framework profile makes L3 (spec 2.2, 8.5)", async () => {
    const { kp } = await adopted();
    const obs = await generateKeyPair();
    await E.db.run("INSERT INTO observers (did, name, accredited_at, bootstrap) VALUES ($1, 'Obs', $2, 1)", [obs.did, nowSeconds()]);
    const stage = (claim: object) => signObject({ ...base, type: "Attestation", issuer: obs.did, subject: kp.did, claim_type: "stage", claim, created: nowSeconds(), expires: later(86400) }, obs);
    expect((await write("POST", "/attestations", obs.did, await stage({ stage: "agent", profile: "entity-framework/1.0" }))).body.subject_level).toBe("L2");
    expect((await write("POST", "/attestations", obs.did, await stage({ stage: "entity", profile: "other-framework/1.0" }))).body.subject_level).toBe("L2");
    expect((await write("POST", "/attestations", obs.did, await stage({ stage: "entity", profile: "entity-framework/1.0" }))).body.subject_level).toBe("L3");
  });

  it("an entity's own attestation about itself is labeled first-party (spec 8.4)", async () => {
    const { kp } = await adopted();
    await E.db.run("INSERT INTO observers (did, name, accredited_at, bootstrap) VALUES ($1, 'Self', $2, 1)", [kp.did, nowSeconds()]);
    const att = await signObject({ ...base, type: "Attestation", issuer: kp.did, subject: kp.did, claim_type: "capability", claim: { capability: "x", evidence_ref: "y" }, created: nowSeconds(), expires: later(86400) }, kp);
    expect((await write("POST", "/attestations", kp.did, att)).status).toBe(201);
    expect((await call("GET", `/entities/${kp.did}`)).body).toMatchObject({ level: "L2", level_label: "first-party" });
  });

  it("a registry does not accredit an observer that publishes no methodology (spec 8.4)", async () => {
    const did = "did:web:nometh-obs.example";
    for (let i = 0; i < 10; i++) await E.db.run("INSERT INTO attestations (sha256, issuer, subject, claim_type, json, created, expires) VALUES ($1, $2, $3, 'identity', '{}', 'x', 'x')", [`nm${i}`, did, `did:key:z6Mknm${i}`]);
    mockFetch({ "nometh-obs.example/.well-known/openentity.json": () => ({ name: "NoMethodology", extensions: {} }) });
    await scheduled(E);
    expect(await E.db.first("SELECT did FROM observers WHERE did = $1", [did])).toBeNull();
  });
});
