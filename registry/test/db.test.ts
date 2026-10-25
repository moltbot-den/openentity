import { describe, expect, it } from "vitest";
import { pgliteDb, retryThrottled } from "../src/db.ts";

describe("Db", () => {
  it("tx commits on success and rolls back on throw", async () => {
    const db = await pgliteDb();
    await db.tx((t) => t.run("INSERT INTO observers (did, accredited_at) VALUES ($1, $2)", ["did:web:a.example", "x"]));
    await expect(db.tx(async (t) => {
      await t.run("INSERT INTO observers (did, accredited_at) VALUES ($1, $2)", ["did:web:b.example", "x"]);
      throw new Error("boom");
    })).rejects.toThrow("boom");
    expect((await db.all("SELECT did FROM observers")).map((r) => r.did)).toEqual(["did:web:a.example"]);
    expect(await db.run("UPDATE observers SET name = $1", ["A"])).toEqual({ changes: 1 });
  });
});

describe("retryThrottled", () => {
  it("retries Aurora throttles, then gives up; never retries other errors", async () => {
    const noSleep = async () => {};
    let n = 0;
    const flaky = async () => { if (++n < 3) throw new Error("The request was throttled because of insufficient resources on the database."); return "ok"; };
    expect(await retryThrottled(flaky, noSleep)).toBe("ok");
    expect(n).toBe(3);
    n = 0;
    await expect(retryThrottled(async () => { n++; throw new Error("throttled because of insufficient resources"); }, noSleep)).rejects.toThrow();
    expect(n).toBe(6);
    n = 0;
    await expect(retryThrottled(async () => { n++; throw new Error("duplicate key value"); }, noSleep)).rejects.toThrow("duplicate");
    expect(n).toBe(1);
  });
});
