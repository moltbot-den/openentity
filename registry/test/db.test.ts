import { describe, expect, it } from "vitest";
import { pgliteDb } from "../src/db.ts";

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
