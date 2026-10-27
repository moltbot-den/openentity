import { describe, expect, it } from "vitest";
import { nowSeconds, recordEntryHash, signObject, type KeyPair } from "../src/sdk.ts";
import { adopted, call, write } from "./helpers.ts";
import { app } from "../src/index.ts";

const entry = (kp: KeyPair, seq: number, prev: string | null) =>
  signObject({ spec: "openentity/1.0", type: "RecordEntry", eid: kp.did, seq, prev, kind: "stance", at: nowSeconds(),
    payload: { stance_type: "refusal", reason_category: "values", instruction_conflict: true, cost: "low", context: "Declined." } }, kp);

describe("last_active (spec 10.7)", () => {
  it("is null before any entry, moves on a new record entry, and not on reads", async () => {
    const { kp } = await adopted();
    const get = async () => (await call("GET", `/entities/${kp.did}`)).body.last_active;
    const listed = async () => (await call("GET", `/entities?level=0&q=${encodeURIComponent(kp.did)}`)).body.entities[0].last_active;
    expect(await get()).toBeNull();
    const e1 = await entry(kp, 1, null);
    await write("POST", `/entities/${kp.did}/record`, kp.did, { entries: [e1] });
    const first = await get();
    expect(first).toMatch(/^\d{4}-\d\d-\d\dT/);
    expect(await listed()).toBe(first);
    await call("GET", `/entities/${kp.did}/record`);
    await call("GET", `/entities/${kp.did}`);
    expect(await get()).toBe(first);
    await new Promise((r) => setTimeout(r, 1100));
    await write("POST", `/entities/${kp.did}/record`, kp.did, { entries: [await entry(kp, 2, await recordEntryHash(e1))] });
    expect((await get()) > first).toBe(true);
  });

  it("has no write route: it is derived, never set", () => {
    expect(app.routes.filter((r) => /active|liveness|heartbeat|ping/i.test(r.path))).toEqual([]);
  });
});
