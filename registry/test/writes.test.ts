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

  it("chain integrity under concurrent appends: exactly one entry per seq is accepted and the chain stays intact", async () => {
    const { kp } = await adopted();
    let head: string | null = null;
    for (const seq of [1, 2, 3]) {
      // Eight distinct entries race for the same seq on the same prev.
      const rivals = await Promise.all(Array.from({ length: 8 }, async (_, i) => {
        const e: any = await signObject({ spec: "openentity/1.0", type: "RecordEntry", eid: kp.did, seq, prev: head, kind: "stance", at: nowSeconds(), payload: { stance_type: "refusal", reason_category: "values", instruction_conflict: true, cost: "low", context: `rival ${i} for seq ${seq}` } }, kp);
        return e;
      }));
      const results = await Promise.all(rivals.map((e) => write("POST", `/entities/${kp.did}/record`, kp.did, { entries: [e] })));
      const won = results.map((r, i) => ({ r, e: rivals[i] })).filter((x) => x.r.status === 201);
      expect(won).toHaveLength(1);
      expect(results.filter((r) => r.status !== 201).every((r) => r.status === 409)).toBe(true);
      head = await recordEntryHash(won[0].e);
    }
    const stored = (await call("GET", `/entities/${kp.did}/record`)).body.entries;
    expect(stored.map((e: any) => e.seq)).toEqual([1, 2, 3]);
    let prev: string | null = null;
    for (const e of stored) {
      expect(e.prev).toBe(prev);
      prev = await recordEntryHash(e);
    }
    expect(prev).toBe(head);
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
    expect(e.body.lineage.previous_link).toMatchObject({ basis: "rotation", link: { previous: a.kp.did, successor: succ.did, basis: "rotation" } });
    const prevBody = (await call("GET", `/entities/${a.kp.did}`)).body;
    expect(prevBody.lineage.successor).toBe(succ.did);
    expect(prevBody.lineage.successor_link.basis).toBe("rotation");
    expect(prevBody.lineage.previous_link).toBeNull();
    r = await write("POST", "/continuity", succ.did, { link: await link(b.kp, succ, "rotation", [b.kp, succ]) });
    expect(r.body.error).toBe("successor_has_predecessor");
  });

  it("a successor withdraws the inherited Declaration; the predecessor keeps its state (spec 9.3)", async () => {
    const a = await adopted("Old");
    const succ = await generateKeyPair();
    const { document } = await signed(succ, "New");
    expect((await write("POST", "/continuity", succ.did, { link: await link(a.kp, succ, "rotation", [a.kp, succ]), document })).status).toBe(201);
    const w = (eid: string, k: KeyPair) => signObject({ spec: "openentity/1.0", type: "Withdrawal", eid, declaration_version: "1.0", name: "New", created: nowSeconds(), nonce: randomNonce() }, k);
    const stranger = await generateKeyPair();
    expect((await write("POST", "/withdraw", succ.did, await w(succ.did, stranger))).status).not.toBe(201);
    const r = await write("POST", "/withdraw", succ.did, await w(succ.did, succ));
    expect(r.status).toBe(201);
    expect((await call("GET", `/entities/${succ.did}`)).body).toMatchObject({ withdrawn: true, level: null });
    const prev = (await call("GET", `/entities/${a.kp.did}`)).body;
    expect(prev.withdrawn).toBe(false);
    expect(prev.declaration).not.toBeNull();
    const again = await write("POST", "/withdraw", succ.did, await w(succ.did, succ));
    expect(again.body.error).toBe("already_withdrawn");
  });

  it("an entity with no Declaration in its lineage cannot withdraw", async () => {
    const lone = await generateKeyPair();
    const w = await signObject({ spec: "openentity/1.0", type: "Withdrawal", eid: lone.did, declaration_version: "1.0", name: "X", created: nowSeconds(), nonce: randomNonce() }, lone);
    expect((await write("POST", "/withdraw", lone.did, w)).status).toBe(404);
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
    // The key holder lists the alias in a signed document while it still holds the key; only then does it count for recovery.
    const { proof: _p, ...base } = a.document as any;
    const listed = await signObject({ ...base, seq: 2, updated: later(60), aliases: [{ type: "domain", value: "did:web:lost.example" }] }, a.kp);
    expect((await write("PUT", `/entities/${a.kp.did}/document`, a.kp.did, listed)).status).toBe(200);
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

  it("rejects a malformed core claim and still accepts an unknown custom one (spec 8.3)", async () => {
    const { kp } = await adopted();
    const obs = await generateKeyPair();
    for (const [t, c] of [["stage", { stage: "sentient", profile: "p" }], ["layer_scores", { cognition: 1.5, presence: 0, identity_core: 0, mission: 0, profile: "p" }], ["trust_tier", { tier: 5, platform: "x" }]] as const) {
      const r = await write("POST", "/attestations", obs.did, await attest(obs, kp.did, t, c));
      expect([r.status, r.body.error]).toEqual([422, "schema_invalid"]);
    }
    expect((await write("POST", "/attestations", obs.did, await attest(obs, kp.did, "custom:x:y", { any: 1 }))).status).toBe(201);
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

describe("first-party by a URL contact (spec 8.4)", () => {
  it("an operator contact that is a URL names the operator's domain", async () => {
    const { kp } = await adopted("Url", { operator: { kind: "organization", name: "Den", contact: "https://url.example/about", custody: "operator", can_change: [] } });
    const obs = await generateKeyPair();
    mockFetch({ "url.example/.well-known/did.json": () => didWebDoc("url.example", obs) });
    await E.db.run("INSERT INTO observers (did, name, accredited_at, bootstrap) VALUES ('did:web:url.example', 'Url', $1, 1)", [nowSeconds()]);
    const unsigned = { spec: "openentity/1.0", type: "Attestation", issuer: "did:web:url.example", subject: kp.did, claim_type: "identity", claim: { name: "Url", aliases_verified: [] }, created: nowSeconds(), expires: later(86400) };
    expect((await write("POST", "/attestations", "did:web:url.example", { ...unsigned, proof: await signAs(unsigned, obs, "did:web:url.example#k") })).status).toBe(201);
    expect((await call("GET", `/entities/${kp.did}`)).body).toMatchObject({ level: "L2", level_label: "first-party" });
  });
});

describe("capabilities (spec 5.2)", () => {
  it("indexes declared capabilities, follows document updates, and rejects malformed ones", async () => {
    const { kp, document } = await adopted("Defi Dana", { capabilities: ["defi-smart-contracts", "code-review"] });
    await adopted("Plain Pat");
    const find = async (cap: string) => (await call("GET", `/entities?level=0&capability=${cap}`)).body.entities.map((e: any) => e.eid);
    expect(await find("defi-smart-contracts")).toEqual([kp.did]);
    expect(await find("research")).toEqual([]);

    const { proof: _p, ...base } = document as any;
    const next = await signObject({ ...base, seq: 2, capabilities: ["research"], updated: later(60) }, kp);
    expect((await write("PUT", `/entities/${kp.did}/document`, kp.did, next)).status).toBe(200);
    expect(await find("research")).toEqual([kp.did]);
    expect(await find("code-review")).toEqual([]);
    // A capability kept across an update stays indexed.
    const kept = await signObject({ ...base, seq: 3, capabilities: ["research", "code-review"], updated: later(120) }, kp);
    vi.useFakeTimers({ now: Date.now() + 61_000, toFake: ["Date"] });
    expect((await write("PUT", `/entities/${kp.did}/document`, kp.did, kept)).status).toBe(200);
    vi.useRealTimers();
    expect(await find("research")).toEqual([kp.did]);
    expect(await find("code-review")).toEqual([kp.did]);

    const badKp = await generateKeyPair();
    const bad = await signed(badKp, "Bad Caps", { capabilities: ["Not A Slug"] });
    expect((await write("POST", "/adopt", badKp.did, bad)).body.error).toBe("schema_invalid");
  });
});

describe("disputes (spec 10.5)", () => {
  const dispute = (by: KeyPair, subject: string, extra: object = {}) =>
    signObject({ spec: "openentity/1.0", type: "Dispute", issuer: by.did, subject, reason: "inaccurate", statement: "The work was delivered on time; the order log shows it.", created: nowSeconds(), nonce: randomNonce(), ...extra }, by);

  it("logs a signed dispute against an attestation, lists it, and flags the attestation as disputed", async () => {
    const { kp } = await adopted("Disputing Dee");
    const grc = await generateKeyPair();
    const strike = await write("POST", "/attestations", grc.did, await attest(grc, kp.did, "custom:clawgrc:violation", { policy: "declaration:1.0#3", severity: "high", evidence_hash: "a".repeat(64), observed_at: nowSeconds() }));
    const d = await dispute(kp, kp.did, { object_sha256: strike.body.sha256 });
    const r = await write("POST", "/disputes", kp.did, d);
    expect(r.status).toBe(201);
    expect(r.body.log_index).toBeTypeOf("number");
    expect((await write("POST", "/disputes", kp.did, d)).status).toBe(409);

    const list = (await call("GET", `/entities/${kp.did}/disputes`)).body.disputes;
    expect(list.map((x: any) => x.dispute.object_sha256)).toEqual([strike.body.sha256]);
    const atts = (await call("GET", `/entities/${kp.did}/attestations`)).body.attestations;
    expect(atts[0]).toMatchObject({ sha256: strike.body.sha256, disputed: true });
  });

  it("rejects a dispute naming an unknown object, an object about someone else, or a forged signature", async () => {
    const { kp } = await adopted();
    const other = await adopted();
    const peer = await generateKeyPair();
    const about = await write("POST", "/attestations", peer.did, await attest(peer, other.kp.did, "collaboration", { with: peer.did, outcome: "ok", ref: "x" }));
    expect((await write("POST", "/disputes", kp.did, await dispute(kp, kp.did, { object_sha256: "b".repeat(64) }))).status).toBe(404);
    expect((await write("POST", "/disputes", kp.did, await dispute(kp, kp.did, { object_sha256: about.body.sha256 }))).body.error).toBe("object_not_about_subject");
    const forged = { ...(await dispute(peer, kp.did)), issuer: kp.did };
    expect((await write("POST", "/disputes", kp.did, forged)).body.error).toBe("signature_invalid");
    expect((await write("POST", "/disputes", kp.did, await dispute(kp, "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"))).status).toBe(404);
  });
});
