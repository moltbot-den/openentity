import { describe, expect, it } from "vitest";
import { generateKeyPair, nowSeconds, randomNonce, recordEntryHash, signObject, type KeyPair } from "../src/sdk.ts";
import { E, adopted, call, write } from "./helpers.ts";

const stance = (kp: KeyPair, seq: number, prev: string | null, context: string) =>
  signObject({ spec: "openentity/1.0", type: "RecordEntry", eid: kp.did, seq, prev, kind: "stance", at: nowSeconds(),
    payload: { stance_type: "refusal", reason_category: "values", instruction_conflict: false, cost: "none", context } }, kp);
const redaction = (kp: KeyPair, seq: number, entry_sha256: string, signer = kp) =>
  signObject({ spec: "openentity/1.0", type: "Redaction", eid: kp.did, seq, entry_sha256, created: nowSeconds(), nonce: randomNonce() }, signer);

async function withRecord() {
  const { kp } = await adopted();
  const e1 = await stance(kp, 1, null, "public one");
  const e2 = await stance(kp, 2, await recordEntryHash(e1), "private detail");
  const e3 = await stance(kp, 3, await recordEntryHash(e2), "public three");
  expect((await write("POST", `/entities/${kp.did}/record`, kp.did, { entries: [e1, e2, e3] })).status).toBe(201);
  return { kp, e1, e2, e3, h2: await recordEntryHash(e2) };
}

describe("redacted record placeholders (spec 7.4)", () => {
  it("replaces the entry in reads with a placeholder that keeps its hash and chain position", async () => {
    const { kp, e1, e2, e3, h2 } = await withRecord();
    const red = await redaction(kp, 2, h2);
    const r = await write("POST", `/entities/${kp.did}/record/redact`, kp.did, red);
    expect(r.status).toBe(201);
    const { entries, head } = (await call("GET", `/entities/${kp.did}/record`)).body;
    expect(entries[0]).toEqual(e1);
    expect(entries[1]).toEqual({ seq: 2, prev: e2.prev, redacted: true, hash: h2, redaction: red });
    expect(entries[2]).toEqual(e3);
    expect(entries[2].prev).toBe(entries[1].hash);
    expect(head).toEqual({ seq: 3, hash: await recordEntryHash(e3) });
    expect(JSON.stringify(await E.db.all("SELECT json FROM record_entries WHERE eid = $1", [kp.did]))).not.toContain("private detail");
    // The log leaf of the entry stays; the redaction is a leaf of its own.
    expect((await E.db.all("SELECT type FROM log_leaves WHERE eid = $1 AND type IN ('RecordEntry', 'Redaction') UNION ALL SELECT type FROM log_pending WHERE eid = $1 AND type IN ('RecordEntry', 'Redaction')", [kp.did])).map((x) => x.type).sort())
      .toEqual(["RecordEntry", "RecordEntry", "RecordEntry", "Redaction"]);
    // The chain still grows from the unchanged head.
    const e4 = await stance(kp, 4, head.hash, "four");
    expect((await write("POST", `/entities/${kp.did}/record`, kp.did, { entries: [e4] })).status).toBe(201);
  });

  it("needs the entity's signature, the entry's exact hash, and redacts once", async () => {
    const { kp, h2 } = await withRecord();
    const other = await generateKeyPair();
    let r = await write("POST", `/entities/${kp.did}/record/redact`, kp.did, await redaction(kp, 2, h2, other));
    expect([r.status, r.body.error]).toEqual([422, "signature_invalid"]);
    r = await write("POST", `/entities/${kp.did}/record/redact`, kp.did, await redaction(kp, 2, "a".repeat(64)));
    expect([r.status, r.body.error]).toEqual([409, "entry_hash_mismatch"]);
    r = await write("POST", `/entities/${kp.did}/record/redact`, kp.did, await redaction(kp, 9, h2));
    expect([r.status, r.body.error]).toEqual([404, "entry_not_found"]);
    expect((await write("POST", `/entities/${kp.did}/record/redact`, kp.did, await redaction(kp, 2, h2))).status).toBe(201);
    r = await write("POST", `/entities/${kp.did}/record/redact`, kp.did, await redaction(kp, 2, h2));
    expect([r.status, r.body.error]).toEqual([409, "already_redacted"]);
  });
});
