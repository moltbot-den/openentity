import { afterEach, describe, expect, it, vi } from "vitest";
import { generateKeyPair, nowSeconds, randomNonce, recordEntryHash, signObject, signProof, type KeyPair } from "../src/sdk.ts";
import { E, adopted, call, didWebDoc, later, mockFetch, signAs, signed, write } from "./helpers.ts";

afterEach(() => vi.restoreAllMocks());

describe("document updates (spec 5.5)", () => {
  it("needs seq exactly previous plus one and a later updated", async () => {
    const { kp, document } = await adopted();
    const { proof: _p, ...base } = document as any;
    const skip = await signObject({ ...base, seq: 3, updated: later(60) }, kp);
    expect((await write("PUT", `/entities/${kp.did}/document`, kp.did, skip)).body.error).toBe("seq_invalid");
    const same = await signObject({ ...base, seq: 2, updated: base.updated }, kp);
    expect((await write("PUT", `/entities/${kp.did}/document`, kp.did, same)).body.error).toBe("updated_not_increasing");
    const ok = await signObject({ ...base, seq: 2, name: "Renamed", updated: later(60) }, kp);
    const r = await write("PUT", `/entities/${kp.did}/document`, kp.did, ok);
    expect(r.status).toBe(200);
    expect((await call("GET", `/entities/${kp.did}/document`)).body.name).toBe("Renamed");
    const again = await signObject({ ...base, seq: 3, updated: later(120) }, kp);
    expect((await write("PUT", `/entities/${kp.did}/document`, kp.did, again)).status).toBe(429);
  });
});

async function entry(kp: KeyPair, seq: number, prev: string | null, kind = "stance") {
  const payload = kind === "stance"
    ? { stance_type: "refusal", reason_category: "values", instruction_conflict: true, cost: "low", context: "Declined to state an unsourced number." }
    : { declaration_version: "1.0", sha256: "0".repeat(64) };
  return signObject({ spec: "openentity/1.0", type: "RecordEntry", eid: kp.did, seq, prev, kind, at: nowSeconds(), payload }, kp);
}

describe("development record (spec 7.4)", () => {
  it("accepts a valid chain, starting from an empty record", async () => {
    const { kp } = await adopted();
    const e1 = await entry(kp, 1, null, "declaration");
    const e2 = await entry(kp, 2, await recordEntryHash(e1));
    const r = await write("POST", `/entities/${kp.did}/record`, kp.did, { entries: [e1, e2] });
    expect(r.status).toBe(201);
    expect(r.body.head).toEqual({ seq: 2, hash: await recordEntryHash(e2) });
    expect((await call("GET", `/entities/${kp.did}/record?after=1`)).body.entries).toEqual([e2]);
  });

  it("rejects a prev mismatch and a seq gap", async () => {
    const { kp } = await adopted();
    const e1 = await entry(kp, 1, null);
    await write("POST", `/entities/${kp.did}/record`, kp.did, { entries: [e1] });
    const wrongPrev = await entry(kp, 2, "a".repeat(64));
    let r = await write("POST", `/entities/${kp.did}/record`, kp.did, { entries: [wrongPrev] });
    expect([r.status, r.body.error]).toEqual([409, "record_chain_broken"]);
    const gap = await entry(kp, 3, await recordEntryHash(e1));
    r = await write("POST", `/entities/${kp.did}/record`, kp.did, { entries: [gap] });
    expect([r.status, r.body.error]).toEqual([409, "record_chain_broken"]);
  });

  it("caps a batch at 100 entries", async () => {
    const { kp } = await adopted();
    const e = await entry(kp, 1, null);
    const r = await write("POST", `/entities/${kp.did}/record`, kp.did, { entries: Array(101).fill(e) });
    expect(r.body.error).toBe("batch_too_large");
  });
});

async function link(prev: KeyPair, succ: KeyPair, basis: string, signers: KeyPair[]) {
  const unsigned = { spec: "openentity/1.0", type: "ContinuityLink", previous: prev.did, successor: succ.did, basis, created: nowSeconds(), nonce: randomNonce() };
  return { ...unsigned, proofs: await Promise.all(signers.map((k) => signProof(unsigned, k))) };
}

describe("continuity (spec 9)", () => {
  it("rotation needs both proofs; a successor cannot have two predecessors", async () => {
    const a = await adopted("Old"), b = await adopted("Other");
    const succ = await generateKeyPair();
    const { document } = await signed(succ, "New");
    let r = await write("POST", "/continuity", succ.did, { link: await link(a.kp, succ, "rotation", [succ]), document });
    expect(r.body.error).toBe("continuity_proof_missing");
    r = await write("POST", "/continuity", succ.did, { link: await link(a.kp, succ, "rotation", [a.kp]), document });
    expect(r.body.error).toBe("continuity_proof_missing");
    r = await write("POST", "/continuity", succ.did, { link: await link(a.kp, succ, "rotation", [a.kp, succ]), document });
    expect(r.status).toBe(201);
    expect(r.body.level).toBe("L0");
    const e = await call("GET", `/entities/${succ.did}`);
    expect(e.body.lineage.previous).toBe(a.kp.did);
    expect(e.body.declaration_inherited_from).toBe(a.kp.did);
    expect((await call("GET", `/entities/${a.kp.did}`)).body.lineage.successor).toBe(succ.did);
    r = await write("POST", "/continuity", succ.did, { link: await link(b.kp, succ, "rotation", [b.kp, succ]) });
    expect(r.body.error).toBe("successor_has_predecessor");
  });

  it("recovery requires a proof by a verified alias of the previous EID", async () => {
    const a = await adopted();
    const succ = await generateKeyPair(), domainKey = await generateKeyPair();
    const { document } = await signed(succ);
    let r = await write("POST", "/continuity", succ.did, { link: await link(a.kp, succ, "recovery", [succ, domainKey]), document });
    expect(r.body.error).toBe("recovery_alias_required");
    mockFetch({
      "lost.example/.well-known/openentity.json": () => ({ eid: a.kp.did }),
      "lost.example/.well-known/did.json": () => didWebDoc("lost.example", domainKey),
    });
    expect((await write("POST", `/entities/${a.kp.did}/aliases`, a.kp.did, { type: "domain", value: "did:web:lost.example" })).status).toBe(201);
    const { proofs, ...unsigned } = await link(a.kp, succ, "recovery", [succ]);
    const byAlias = await signAs(unsigned, domainKey, "did:web:lost.example#k");
    r = await write("POST", "/continuity", succ.did, { link: { ...unsigned, proofs: [...proofs, byAlias] }, document });
    expect(r.status).toBe(201);
  });
});

async function attest(issuer: KeyPair, subject: string, claim_type: string, claim: object) {
  return signObject({ spec: "openentity/1.0", type: "Attestation", issuer: issuer.did, subject, claim_type, claim, created: nowSeconds(), expires: later(30 * 86400) }, issuer);
}

describe("levels (spec 2.2, 8.4)", () => {
  it("counts only accredited observers toward L2 and L3, and revocation drops the level", async () => {
    const { kp } = await adopted();
    const obs = await generateKeyPair(), stranger = await generateKeyPair();
    let r = await write("POST", "/attestations", stranger.did, await attest(stranger, kp.did, "stage", { stage: "entity", profile: "entity-framework/1.0" }));
    expect(r.status).toBe(201);
    expect(r.body.subject_level).toBe("L0");
    await E.db.run("INSERT INTO observers (did, name, accredited_at, bootstrap) VALUES ($1, 'Obs', $2, 1)", [obs.did, nowSeconds()]);
    const layer = await attest(obs, kp.did, "layer_scores", { cognition: 0.7, presence: 0.7, identity_core: 0.7, mission: 0.7, profile: "entity-framework/1.0" });
    r = await write("POST", "/attestations", obs.did, layer);
    expect(r.body.subject_level).toBe("L2");
    expect((await call("GET", `/entities/${kp.did}`)).body).toMatchObject({ level: "L2", level_label: "independent" });
    r = await write("POST", "/attestations", obs.did, await attest(obs, kp.did, "stage", { stage: "entity", profile: "entity-framework/1.0" }));
    expect(r.body.subject_level).toBe("L3");
    const stage = r.body.sha256;
    const rev = (by: KeyPair) => signObject({ spec: "openentity/1.0", type: "Revocation", issuer: by.did, attestation_sha256: stage, created: nowSeconds() }, by);
    expect((await write("POST", "/attestations", stranger.did, await rev(stranger))).body.error).toBe("not_issuer");
    expect((await write("POST", "/attestations", obs.did, await rev(obs))).status).toBe(201);
    expect((await call("GET", `/entities/${kp.did}`)).body.level).toBe("L2");
    const list = await call("GET", `/entities/${kp.did}/attestations?format=vc`);
    expect(list.body.attestations).toHaveLength(3);
    expect(list.body.attestations.find((a: any) => a.sha256 === stage).revoked_at).toBeTruthy();
  });

  it("labels an attestation from the entity's operator first-party", async () => {
    const { kp } = await adopted("Op", { operator: { kind: "organization", name: "Den", contact: "ops@den.example", custody: "operator", can_change: [] } });
    const obs = await generateKeyPair();
    mockFetch({ "den.example/.well-known/did.json": () => didWebDoc("den.example", obs) });
    await E.db.run("INSERT INTO observers (did, name, accredited_at, bootstrap) VALUES ('did:web:den.example', 'Den', $1, 1)", [nowSeconds()]);
    const unsigned = { spec: "openentity/1.0", type: "Attestation", issuer: "did:web:den.example", subject: kp.did, claim_type: "identity", claim: { name: "Op", aliases_verified: [] }, created: nowSeconds(), expires: later(86400) };
    const r = await write("POST", "/attestations", "did:web:den.example", { ...unsigned, proof: await signAs(unsigned, obs, "did:web:den.example#k") });
    expect(r.status).toBe(201);
    expect((await call("GET", `/entities/${kp.did}`)).body).toMatchObject({ level: "L2", level_label: "first-party" });
  });
});
