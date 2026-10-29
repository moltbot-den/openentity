import { describe, expect, it } from "vitest";
import { E, adopted, call } from "./helpers.ts";

const N = 1005;

describe("record and attestation reads page past 1000 rows", () => {
  it("record: `next` is the last seq of a full page, then null; ?after= walks every entry", async () => {
    const { kp } = await adopted();
    await E.db.run("INSERT INTO record_entries (eid, seq, kind, json, sha256, received_at) SELECT $1, g, 'stance', '{\"seq\":' || g || '}', 'h' || g, 'x' FROM generate_series(1, $2::int) g", [kp.did, N]);
    const p1 = (await call("GET", `/entities/${kp.did}/record`)).body;
    expect(p1.entries).toHaveLength(1000);
    expect(p1.next).toBe(1000);
    const p2 = (await call("GET", `/entities/${kp.did}/record?after=${p1.next}`)).body;
    expect(p2.entries.map((e: any) => e.seq)).toEqual([1001, 1002, 1003, 1004, 1005]);
    expect(p2.next).toBeNull();
  });

  it("attestations: `next` is the offset of the following page, then null", async () => {
    const { kp } = await adopted();
    await E.db.run("INSERT INTO attestations (sha256, issuer, subject, claim_type, json, created, expires) SELECT 'a' || g || $1, 'did:key:i', $1, 't', '{\"issuer\":\"did:key:i\",\"created\":\"2026-01-01T00:00:00Z\"}', '2026-01-01T00:00:00Z', '2999-01-01T00:00:00Z' FROM generate_series(1, $2::int) g", [kp.did, N]);
    const p1 = (await call("GET", `/entities/${kp.did}/attestations`)).body;
    expect(p1.attestations).toHaveLength(1000);
    expect(p1.next).toBe(1000);
    const p2 = (await call("GET", `/entities/${kp.did}/attestations?offset=${p1.next}`)).body;
    expect(p2.attestations).toHaveLength(5);
    expect(p2.next).toBeNull();
    const seen = new Set([...p1.attestations, ...p2.attestations].map((a: any) => a.sha256));
    expect(seen.size).toBe(N);
  });
});
