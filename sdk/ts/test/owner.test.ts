import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { createHash } from "node:crypto";
import * as oe from "../src/index.ts";
import { PAIR_SAS_WORDS } from "../src/pair.ts";
import { buildOwnerVectors } from "../scripts/gen-owner-vectors.ts";
import { serialize } from "../scripts/gen-vectors.ts";

const dir = new URL("../../../test-vectors/", import.meta.url);
const json = (p: string) => JSON.parse(readFileSync(new URL(p, dir), "utf8"));
const sha256hex = (s: string) => createHash("sha256").update(s).digest("hex");
const keylogCases = readdirSync(new URL("keylog-1/", dir)).filter((f) => f.endsWith(".json") && f !== "keys.json");
const A = json("approval-2.0/vectors.json");

describe("owner vectors (approval-2.0, keylog-1, pair-sas-1)", () => {
  it("committed files equal a fresh deterministic generation", () => {
    const fresh = buildOwnerVectors();
    for (const sub of ["approval-2.0", "keylog-1", "pair-sas-1"]) {
      const files = readdirSync(new URL(`${sub}/`, dir)).filter((f) => f.endsWith(".json")).map((f) => `${sub}/${f}`);
      expect(files.sort()).toEqual(Object.keys(fresh).filter((k) => k.startsWith(`${sub}/`)).sort());
    }
    for (const [path, v] of Object.entries(fresh)) expect(readFileSync(new URL(path, dir), "utf8"), path).toBe(serialize(v));
  });
});

describe("owner key log (keylog-1)", () => {
  // Every rule of PLAN 3.2 has a case; removing its guard turns that case's result into a mismatch.
  for (const f of keylogCases)
    it(f, () => {
      const v = json(`keylog-1/${f}`);
      const r = oe.verifyKeyLog(v.did, v.log, v.first_seen_at, { now: v.now, origins: v.origins, serviceKeys: v.service_keys });
      const got = r.ok
        ? { ok: true, state: { ...r.state, root: r.state.root.kid, approvers: r.state.approvers.map((c) => c.kid) } }
        : { ok: false, error: r.error, seq: r.seq };
      expect(got, r.ok ? "" : r.message).toEqual(v.expect);
    });
  it("each line hashes to the next prev, and the DID is base32 of the genesis hash", () => {
    const v = json("keylog-1/recover-cancelled-by-revoked-approver.json");
    v.log.forEach((line: string, i: number) => i && expect(JSON.parse(line).prev).toBe(sha256hex(v.log[i - 1])));
    const b32 = (h: Buffer) => [...h].map((x) => x.toString(2).padStart(8, "0")).join("").match(/.{1,5}/g)!.map((g) => "abcdefghijklmnopqrstuvwxyz234567"[parseInt(g.padEnd(5, "0"), 2)]).join("");
    expect(v.did).toBe(`did:web:account.openentity.org:o:${b32(createHash("sha256").update(v.log[0]).digest())}`);
  });
  it("rejects bad input as input, not as a log failure", () => {
    const v = json("keylog-1/genesis-device.json");
    expect(oe.verifyKeyLog(v.did, v.log, [], { now: v.now }).ok).toBe(false);
    expect(() => oe.verifyKeyLog(v.did, v.log, v.first_seen_at, { serviceKeys: [{ kty: "EC", crv: "P-256", x: "AA", y: "AA" }] })).toThrow(oe.OpenEntityError);
    expect(oe.verifyKeyLog(v.did, v.log, v.first_seen_at, { now: v.first_seen_at[0] - 1 })).toMatchObject({ ok: false, error: "bad_first_seen" });
  });
});

describe("approval/2.0", () => {
  it("digests: preimage and SHA-256 for both decisions", () => {
    expect(A.digests.map((d: { fields: { decision: string } }) => d.fields.decision)).toEqual(["approve", "deny"]);
    for (const d of A.digests) {
      expect(d.preimage).toBe(["approval/2.0", d.fields.verifier_did, d.fields.owner_did, d.fields.request_id, d.fields.payload_digest, d.fields.decision, d.fields.expires_at].join("|"));
      expect(sha256hex(d.preimage)).toBe(d.digest);
      expect(Buffer.from(oe.approvalDigest(d.fields)).toString("hex")).toBe(d.digest);
    }
    expect(() => oe.approvalDigest({ ...A.digests[0].fields, request_id: "a|b" })).toThrow(oe.OpenEntityError);
    expect(() => oe.approvalDigest({ ...A.digests[0].fields, owner_did: "did:web:x|y" })).toThrow(oe.OpenEntityError);
  });
  it("payload digests are SHA-256 of RFC 8785 JSON; floats and integers past 2^53 are refused", () => {
    for (const p of A.payloads) {
      expect(oe.canonicalize(p.summary)).toBe(p.canonical);
      expect(oe.payloadDigest(p.summary)).toBe(p.digest);
    }
    for (const p of A.payloads_invalid) expect(() => oe.payloadDigest(p.summary), p.reason).toThrow(oe.OpenEntityError);
  });
  for (const c of A.cases)
    it(`${c.name}: ${c.description}`, () => {
      const x = c.context;
      const r = oe.verifyApproval(c.approval, {
        keyLog: A.key_states[x.key_state], verifierDid: x.verifier_did, ownerDid: x.owner_did, requestId: x.request_id,
        payloadDigest: x.payload_digest, now: x.now, decisions: x.decisions, origins: x.origins, counter: x.counter,
      });
      expect(r.ok ? { ok: true, kid: r.kid, counter: r.counter } : { ok: false, error: r.error }, r.ok ? "" : r.message).toEqual(c.expect);
    });
  it("each key state is what verifyKeyLog derives from its key log", () => {
    const keys = json("approval-2.0/keys.json");
    for (const [name, l] of Object.entries(A.key_logs) as [string, { did: string; log: string[]; first_seen_at: number[] }][]) {
      const r = oe.verifyKeyLog(l.did, l.log, l.first_seen_at, { now: A.cases[0].context.now, origins: A.cases[0].context.origins, serviceKeys: [keys.keys.service.jwk] });
      if (!r.ok) throw new Error(`${name}: ${r.message}`);
      expect({ did: r.state.did, approvers: r.state.approvers, closed: r.state.closed }, name).toEqual(A.key_states[name]);
    }
  });
});

describe("pair-sas/1", () => {
  it("the list has 256 distinct entries and matches words.json", () => {
    const w = json("pair-sas-1/words.json");
    expect(w.words).toEqual([...PAIR_SAS_WORDS]);
    expect(new Set(w.words).size).toBe(256);
    expect(w.words.every((x: string) => /^[a-z]+ [a-z]+$/.test(x))).toBe(true);
    expect(w.words.map((_: string, i: number) => `${w.colors[i >> 4]} ${w.nouns[i & 15]}`)).toEqual(w.words);
  });
  it("derives the vectors' items", () => {
    for (const c of json("pair-sas-1/vectors.json").cases) {
      expect(sha256hex(c.preimage)).toBe(c.sha256);
      expect(oe.pairSas(c.code, c.agent_did)).toEqual(c.items);
      expect(c.items).toEqual([0, 1, 2, 3].map((i) => PAIR_SAS_WORDS[parseInt(c.sha256.slice(2 * i, 2 * i + 2), 16)]));
    }
    expect(() => oe.pairSas("OE-123", "did:key:z6Mk")).toThrow(oe.OpenEntityError);
    expect(() => oe.pairSas("OE-1234-5678", "not a did")).toThrow(oe.OpenEntityError);
  });
});
