// Guards of spec/OEIS-1.md that no other test pins down; docs/CONFORMANCE-MATRIX.md lists each with its test.
import { afterEach, describe, expect, it, vi } from "vitest";
import { buildDeclaration, buildDocument, generateKeyPair, nowSeconds, randomNonce, recordEntryHash, signObject, signProof, type KeyPair } from "../src/sdk.ts";
import { scheduled } from "../src/index.ts";
import { E, adopted, call, didWebDoc, later, mockFetch, signed, write } from "./helpers.ts";

afterEach(() => vi.restoreAllMocks());

async function link(prev: KeyPair, succ: KeyPair, basis: string, signers: KeyPair[], created = nowSeconds()) {
  const unsigned = { spec: "openentity/1.0", type: "ContinuityLink", previous: prev.did, successor: succ.did, basis, created, nonce: randomNonce() };
  return { ...unsigned, proofs: await Promise.all(signers.map((k) => signProof(unsigned, k))) };
}
const post = (succ: KeyPair, body: object) => write("POST", "/continuity", succ.did, body);

describe("canonical JSON (spec 4.3)", () => {
  it("rejects a body with a duplicate key before reading any object from it", async () => {
    const { kp, document, declaration } = await adopted();
    const dup = JSON.stringify({ document, declaration }).replace('"name":"Test Entity"', '"name":"Test Entity","name":"Other"');
    expect(dup).toContain('"name":"Other"');
    const r = await write("POST", "/adopt", kp.did, dup);
    expect([r.status, r.body.error]).toEqual([400, "bad_json"]);
    expect(r.body.message).toMatch(/duplicate key/);
  });

  it("rejects a number with more than 6 decimal places", async () => {
    const { kp } = await adopted();
    const obs = await generateKeyPair();
    const att = (confidence: number) => signObject({ spec: "openentity/1.0", type: "Attestation", issuer: obs.did, subject: kp.did, claim_type: "stage", claim: { stage: "agent", profile: "entity-framework/1.0" }, confidence, created: nowSeconds(), expires: later(86400) }, obs);
    const bad = await write("POST", "/attestations", obs.did, await att(0.1234567));
    expect([bad.status, bad.body.error]).toEqual([422, "schema_invalid"]);
    expect(bad.body.message).toMatch(/6 decimal places/);
    expect((await write("POST", "/attestations", obs.did, await att(0.123456))).status).toBe(201);
  });
});

describe("objects must be signed by, and name, the entity (spec 4.5, 6.3, 5.5, 7.4, 4.4)", () => {
  it("adopt: a Declaration naming another EID is rejected even when this entity's key signed it", async () => {
    const kp = await generateKeyPair(), other = await generateKeyPair();
    const { document } = await signed(kp);
    const declaration = await signObject(buildDeclaration({ eid: other.did, name: "Test Entity" }), kp);
    const r = await write("POST", "/adopt", kp.did, { document, declaration });
    expect([r.status, r.body.error]).toEqual([422, "eid_mismatch"]);
  });

  it("adopt: a Document older than 24 hours is rejected", async () => {
    const kp = await generateKeyPair();
    const old = new Date(Date.now() - 25 * 3600_000).toISOString().replace(/\.\d+Z$/, "Z");
    const document = await signObject({ ...(buildDocument({ kp, name: "Old", description: "A test entity.", created: old }) as any), updated: old }, kp);
    const declaration = await signObject(buildDeclaration({ eid: kp.did, name: "Old" }), kp);
    const r = await write("POST", "/adopt", kp.did, { document, declaration });
    expect([r.status, r.body.error]).toEqual([422, "timestamp_invalid"]);
  });

  it("a document update signed by another key is rejected", async () => {
    const { kp, document } = await adopted();
    const { proof: _p, ...base } = document as any;
    const forged = await signObject({ ...base, seq: 2, name: "Forged", updated: later(60) }, await generateKeyPair());
    const r = await write("PUT", `/entities/${kp.did}/document`, kp.did, forged);
    expect([r.status, r.body.error]).toEqual([422, "signature_invalid"]);
  });

  it("a document update older than 24 hours is rejected", async () => {
    const { kp, document } = await adopted();
    const { proof: _p, ...base } = document as any;
    const old = await signObject({ ...base, seq: 2, updated: later(-25 * 3600) }, kp);
    expect((await write("PUT", `/entities/${kp.did}/document`, kp.did, old)).body.error).toBe("timestamp_invalid");
  });

  it("record entries signed by another key are rejected", async () => {
    const { kp } = await adopted();
    const e = await signObject({ spec: "openentity/1.0", type: "RecordEntry", eid: kp.did, seq: 1, prev: null, kind: "declaration", at: nowSeconds(), payload: { declaration_version: "1.0", sha256: "0".repeat(64) } }, await generateKeyPair());
    const r = await write("POST", `/entities/${kp.did}/record`, kp.did, { entries: [e] });
    expect([r.status, r.body.error]).toEqual([422, "signature_invalid"]);
  });
});

describe("EID methods (spec 3.1)", () => {
  it("rejects a method the registry cannot resolve", async () => {
    const kp = await generateKeyPair();
    const eid = "did:ethr:0x742d35cc6634c0532925a3b844bc9e7595f0beb0";
    const base = buildDocument({ kp, name: "Odd", description: "A test entity." }) as any;
    const document = await signObject({ ...base, eid }, kp);
    const declaration = await signObject(buildDeclaration({ eid, name: "Odd" }), kp);
    const r = await write("POST", "/adopt", eid, { document, declaration });
    expect([r.status, r.body.error]).toEqual([422, "unsupported_method"]);
  });
});

describe("attestation expiry (spec 8.4)", () => {
  it("accepts at most one year and a later expiry than creation", async () => {
    const { kp } = await adopted();
    const obs = await generateKeyPair();
    const att = (expires: string, created = nowSeconds()) => signObject({ spec: "openentity/1.0", type: "Attestation", issuer: obs.did, subject: kp.did, claim_type: "capability", claim: { capability: "x", evidence_ref: "y" }, created, expires }, obs);
    expect((await write("POST", "/attestations", obs.did, await att(later(367 * 86400)))).body.error).toBe("expires_invalid");
    expect((await write("POST", "/attestations", obs.did, await att(later(-60)))).body.error).toBe("expires_invalid");
    expect((await write("POST", "/attestations", obs.did, await att(later(360 * 86400)))).status).toBe(201);
  });

  it("serves the revocation with the attestation and filters by issuer (spec 8.4)", async () => {
    const { kp } = await adopted();
    const a = await generateKeyPair(), b = await generateKeyPair();
    const mk = (k: KeyPair) => signObject({ spec: "openentity/1.0", type: "Attestation", issuer: k.did, subject: kp.did, claim_type: "capability", claim: { capability: k.did.slice(-6), evidence_ref: "y" }, created: nowSeconds(), expires: later(86400) }, k);
    const ra = await write("POST", "/attestations", a.did, await mk(a));
    await write("POST", "/attestations", b.did, await mk(b));
    const rev = await signObject({ spec: "openentity/1.0", type: "Revocation", issuer: a.did, attestation_sha256: ra.body.sha256, created: nowSeconds() }, a);
    expect((await write("POST", "/attestations", a.did, rev)).status).toBe(201);
    const only = (await call("GET", `/entities/${kp.did}/attestations?issuer=${encodeURIComponent(a.did)}`)).body.attestations;
    expect(only).toHaveLength(1);
    expect(only[0].revocation).toMatchObject({ type: "Revocation", attestation_sha256: ra.body.sha256 });
    expect((await call("GET", `/entities/${kp.did}/attestations`)).body.attestations).toHaveLength(2);
  });
});

describe("continuity (spec 9.2, 9.3)", () => {
  it("a successor cannot have two predecessors by migration or by recovery either", async () => {
    for (const second of ["migration", "recovery"]) {
      const a = await adopted("Old"), b = await adopted("Other");
      const succ = await generateKeyPair();
      const { document } = await signed(succ, "New");
      expect((await post(succ, { link: await link(a.kp, succ, "migration", [a.kp, succ]), document })).status).toBe(201);
      const r = await post(succ, { link: await link(b.kp, succ, second, [b.kp, succ]) });
      expect([second, r.body.error]).toEqual([second, "successor_has_predecessor"]);
    }
  });

  it("a predecessor continues as one successor only; a fork is two entities", async () => {
    const a = await adopted("Old");
    const s1 = await generateKeyPair(), s2 = await generateKeyPair();
    expect((await post(s1, { link: await link(a.kp, s1, "rotation", [a.kp, s1]), document: (await signed(s1, "One")).document })).status).toBe(201);
    const r = await post(s2, { link: await link(a.kp, s2, "rotation", [a.kp, s2]), document: (await signed(s2, "Two")).document });
    expect(r.body.error).toBe("previous_has_successor");
  });

  it("recovery: a verified alias of the previous EID is not enough without its proof, and a pending alias counts for nothing", async () => {
    const a = await adopted();
    const succ = await generateKeyPair();
    const { document } = await signed(succ);
    // Previous key alone (the key is not lost) plus the successor: still no recovery without an alias proof.
    let r = await post(succ, { link: await link(a.kp, succ, "recovery", [a.kp, succ]), document });
    expect(r.body.error).toBe("recovery_alias_required");
    // A proof by an unrelated key is not a proof by an alias.
    r = await post(succ, { link: await link(a.kp, succ, "recovery", [succ, await generateKeyPair()]), document });
    expect(r.body.error).toBe("recovery_alias_required");
    // The successor key alone is rejected for every basis.
    r = await post(succ, { link: await link(a.kp, succ, "recovery", [succ]), document });
    expect(r.body.error).toBe("recovery_alias_required");
  });

  it("recovery: a proof that names a wallet alias but is not signed by that wallet does not count", async () => {
    const a = await adopted();
    const succ = await generateKeyPair(), walletKey = await generateKeyPair();
    const { document } = await signed(succ);
    // The alias row is inserted directly: how a wallet alias gets verified is pinned in aliases.test.ts.
    const value = `did:pkh:eip155:1:0x${"ab".repeat(20)}`;
    await E.db.run("INSERT INTO aliases (eid, type, value, proof_json, verified_at, last_checked, status, log_index) VALUES ($1, 'wallet', $2, 'null', $3, $3, 'verified', 0)", [a.kp.did, value, nowSeconds()]);
    const { proofs, ...unsigned } = await link(a.kp, succ, "recovery", [succ]);
    const byWallet = { ...(await signProof(unsigned, walletKey)), verificationMethod: `${value}#controller` };
    const r = await post(succ, { link: { ...unsigned, proofs: [...proofs, byWallet] }, document });
    // A forged verificationMethod naming the wallet does not verify: the signature must recover to its address.
    expect(r.body.error).toBe("recovery_alias_required");
  });

  it("needs the successor's seq 1 document for a new successor, a known previous, and two different EIDs", async () => {
    const a = await adopted("Old");
    const succ = await generateKeyPair();
    const { document } = await signed(succ);
    expect((await post(succ, { link: await link(a.kp, succ, "rotation", [a.kp, succ]) })).body.error).toBe("document_required");
    const other = await generateKeyPair();
    expect((await post(succ, { link: await link(a.kp, succ, "rotation", [a.kp, succ]), document: (await signed(other)).document })).body.error).toBe("eid_mismatch");
    const stranger = await generateKeyPair();
    expect((await post(succ, { link: await link(stranger, succ, "rotation", [stranger, succ]), document })).status).toBe(404);
    expect((await post(a.kp, { link: await link(a.kp, a.kp, "rotation", [a.kp]) })).body.error).toBe("schema_invalid");
  });

  it("rejects a link outside the 24 hour window (spec 4.4)", async () => {
    const a = await adopted("Old");
    const succ = await generateKeyPair();
    const { document } = await signed(succ);
    const old = new Date(Date.now() - 25 * 3600_000).toISOString().replace(/\.\d+Z$/, "Z");
    expect((await post(succ, { link: await link(a.kp, succ, "rotation", [a.kp, succ], old), document })).body.error).toBe("timestamp_invalid");
  });

  it("carries the predecessor's Declaration, Record head and attestations forward as inherited, and shows the lineage on both (spec 9.3)", async () => {
    const a = await adopted("Old");
    const e1 = await signObject({ spec: "openentity/1.0", type: "RecordEntry", eid: a.kp.did, seq: 1, prev: null, kind: "declaration", at: nowSeconds(), payload: { declaration_version: "1.0", sha256: "0".repeat(64) } }, a.kp);
    expect((await write("POST", `/entities/${a.kp.did}/record`, a.kp.did, { entries: [e1] })).status).toBe(201);
    const obs = await generateKeyPair();
    const att = await signObject({ spec: "openentity/1.0", type: "Attestation", issuer: obs.did, subject: a.kp.did, claim_type: "capability", claim: { capability: "x", evidence_ref: "y" }, created: nowSeconds(), expires: later(86400) }, obs);
    expect((await write("POST", "/attestations", obs.did, att)).status).toBe(201);
    const succ = await generateKeyPair();
    const { document } = await signed(succ, "New");
    expect((await post(succ, { link: await link(a.kp, succ, "rotation", [a.kp, succ]), document })).status).toBe(201);
    const s = (await call("GET", `/entities/${succ.did}`)).body;
    expect(s.declaration_inherited_from).toBe(a.kp.did);
    expect(s.inherited_record_head).toEqual({ eid: a.kp.did, seq: 1, hash: await recordEntryHash(e1) });
    expect(s.counts.attestations).toBe(1);
    expect(s.lineage).toMatchObject({ previous: a.kp.did, chain: [succ.did, a.kp.did] });
    expect((await call("GET", `/entities/${succ.did}/attestations`)).body.attestations[0].inherited_from).toBe(a.kp.did);
    const p = (await call("GET", `/entities/${a.kp.did}`)).body;
    expect(p.lineage).toMatchObject({ successor: succ.did });
    expect(p.inherited_record_head).toBeNull();
  });
});

describe("aliases and directory (spec 3.4, 10.2, 10.4, 10.5)", () => {
  it("binds an alias once", async () => {
    const a = await adopted();
    const key = await generateKeyPair();
    mockFetch({ "dup.example/.well-known/openentity.json": () => ({ eid: a.kp.did }), "dup.example/.well-known/did.json": () => didWebDoc("dup.example", key) });
    const bind = () => write("POST", `/entities/${a.kp.did}/aliases`, a.kp.did, { type: "domain", value: "did:web:dup.example" });
    expect((await bind()).status).toBe(201);
    expect((await bind()).body.error).toBe("alias_exists");
  });

  it("an alias counts toward the level and shows as verified only when the entity's own document lists it (spec 3.4)", async () => {
    const { kp, document } = await adopted("Victim");
    const key = await generateKeyPair();
    // The attacker controls evil.example and its file names the victim's EID: the proof is valid, the entity never consented.
    mockFetch({ "evil.example/.well-known/openentity.json": () => ({ eid: kp.did }), "evil.example/.well-known/did.json": () => didWebDoc("evil.example", key) });
    const bound = await write("POST", `/entities/${kp.did}/aliases`, kp.did, { type: "domain", value: "did:web:evil.example" });
    expect([bound.status, bound.body.level, bound.body.alias.status]).toEqual([201, "L0", "unclaimed"]);
    const view = async () => (await call("GET", `/entities/${kp.did}`)).body;
    const row = async () => (await call("GET", "/entities?level=0&alias_type=domain&q=Victim")).body.entities;
    expect([(await view()).level, (await view()).aliases[0].status, await row()]).toEqual(["L0", "unclaimed", []]);
    expect((await call("GET", "/entities?level=0&q=Victim")).body.entities[0].aliases).toEqual([]);
    // The entity lists it in a new signed document: now it counts.
    const { proof: _p, ...base } = document as any;
    const listed = await signObject({ ...base, seq: 2, updated: later(60), aliases: [{ type: "domain", value: "did:web:evil.example" }] }, kp);
    expect((await write("PUT", `/entities/${kp.did}/document`, kp.did, listed)).status).toBe(200);
    expect([(await view()).level, (await view()).aliases[0].status]).toEqual(["L1", "verified"]);
    expect((await row())[0]).toMatchObject({ level: "L1", aliases: ["domain"] });
    // Dropping it from the next document takes the level away again.
    const dropped = await signObject({ ...base, seq: 3, updated: later(180) }, kp);
    await E.db.run("DELETE FROM rate_events WHERE key LIKE 'doc:%'");
    expect((await write("PUT", `/entities/${kp.did}/document`, kp.did, dropped)).status).toBe(200);
    expect([(await view()).level, (await view()).aliases[0].status]).toEqual(["L0", "unclaimed"]);
  });

  it("the scheduled run puts a stored level written before the rule right", async () => {
    const { kp } = await adopted("Stale");
    await E.db.run("INSERT INTO aliases (eid, type, value, status, verified_at, log_index) VALUES ($1, 'domain', 'did:web:stale.example', 'verified', $2, 1)", [kp.did, nowSeconds()]);
    await E.db.run("UPDATE entities SET level = 1 WHERE eid = $1", [kp.did]);
    await scheduled(E);
    expect((await call("GET", `/entities/${kp.did}`)).body.level).toBe("L0");
  });

  it("answers any sort other than newest or attested with 422", async () => {
    expect((await call("GET", "/entities?sort=oldest")).body.error).toBe("bad_sort");
  });

  it("shows the not-a-warranty note with every Declaration (spec 6.3)", async () => {
    const { kp } = await adopted();
    expect((await call("GET", `/entities/${kp.did}`)).body.declaration_note).toMatch(/not a warranty, a contract or a claim about the entity's capabilities/);
  });

  it("marks an entity dormant after 365 days without a signed write, and leaves suppressed entities out of the directory", async () => {
    const { kp } = await adopted("Sleepy");
    expect((await call("GET", `/entities/${kp.did}`)).body.dormant).toBe(false);
    await E.db.run("UPDATE entities SET updated = $1 WHERE eid = $2", [new Date(Date.now() - 366 * 86400_000).toISOString().replace(/\.\d+Z$/, "Z"), kp.did]);
    expect((await call("GET", `/entities/${kp.did}`)).body.dormant).toBe(true);
    expect((await call("GET", "/entities?level=L0&q=Sleepy")).body.entities).toHaveLength(1);
    await E.db.run("UPDATE entities SET suppressed = 1 WHERE eid = $1", [kp.did]);
    expect((await call("GET", "/entities?level=L0&q=Sleepy")).body.entities).toHaveLength(0);
    expect((await call("GET", `/entities/${kp.did}`)).body.suppressed).toBe(true);
  });

  it("serves at most 1,000 log entries per call (spec 10.2)", async () => {
    // Rows far past the real tree, so no other test in this file sees them.
    await E.db.run("INSERT INTO log_leaves (idx, leaf_hash, type, eid, object_sha256, received_at) SELECT g, 'h', 'Alias', 'e', 'o', 't' FROM generate_series(1000000, 1001100) AS g");
    const r = await call("GET", "/log/entries?start=1000000&end=1100000");
    expect([r.status, r.body.entries.length]).toEqual([200, 1000]);
  });
});
