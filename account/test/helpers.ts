import { readFile } from "node:fs/promises";
import { type Db, splitSql } from "../src/db.ts";

/** Tests only: an in-memory Postgres with account/schema.sql applied statement by statement, as the migration does. */
export async function pgliteDb(): Promise<Db> {
  const { PGlite } = await import("@electric-sql/pglite");
  const pg = new PGlite();
  for (const s of splitSql(await readFile(new URL("../schema.sql", import.meta.url), "utf8"))) await pg.exec(s);
  type Q = Pick<InstanceType<typeof PGlite>, "query">;
  const make = (q: Q, inTx: boolean): Db => ({
    all: async (sql, params) => (await q.query<any>(sql, params)).rows,
    first: async (sql, params) => (await q.query<any>(sql, params)).rows[0] ?? null,
    run: async (sql, params) => ({ changes: (await q.query(sql, params)).affectedRows ?? 0 }),
    tx(fn) { return inTx ? fn(this) : pg.transaction((t) => fn(make(t, true))); },
  });
  return make(pg, false);
}

/** An account row to hang sessions on. */
export async function account(db: Db, id = `acct_${Math.random().toString(36).slice(2, 12)}`): Promise<string> {
  await db.run("INSERT INTO accounts (id, app_account_token, created_at) VALUES ($1, $2, $3)", [id, crypto.randomUUID(), 1]);
  return id;
}
