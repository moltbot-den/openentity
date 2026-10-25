// Postgres access: the RDS Data API in production, PGlite in tests. SQL uses $1, $2 placeholders.
import { BeginTransactionCommand, CommitTransactionCommand, ExecuteStatementCommand, RDSDataClient, RollbackTransactionCommand, type SqlParameter } from "@aws-sdk/client-rds-data";

export interface Db {
  all<T = any>(sql: string, params?: unknown[]): Promise<T[]>;
  first<T = any>(sql: string, params?: unknown[]): Promise<T | null>;
  run(sql: string, params?: unknown[]): Promise<{ changes: number }>;
  tx<T>(fn: (db: Db) => Promise<T>): Promise<T>; // BEGIN/COMMIT, ROLLBACK on throw
}

const param = (v: unknown, i: number): SqlParameter => {
  const name = `p${i + 1}`;
  if (v === null || v === undefined) return { name, value: { isNull: true } };
  if (typeof v === "boolean") return { name, value: { booleanValue: v } };
  if (typeof v === "number") return { name, value: Number.isInteger(v) ? { longValue: v } : { doubleValue: v } };
  return { name, value: { stringValue: String(v) } };
};

export function dataApiDb(o: { resourceArn: string; secretArn: string; database: string }): Db {
  const client = new RDSDataClient({});
  const base = { resourceArn: o.resourceArn, secretArn: o.secretArn, database: o.database };
  const make = (transactionId?: string): Db => {
    const exec = (sql: string, params: unknown[] = []) =>
      client.send(new ExecuteStatementCommand({
        ...base, transactionId, formatRecordsAs: "JSON",
        sql: sql.replace(/\$(\d+)/g, ":p$1"), parameters: params.map(param),
      }));
    const all = async (sql: string, params?: unknown[]) => JSON.parse((await exec(sql, params)).formattedRecords ?? "[]");
    return {
      all,
      first: async (sql, params) => (await all(sql, params))[0] ?? null,
      run: async (sql, params) => ({ changes: (await exec(sql, params)).numberOfRecordsUpdated ?? 0 }),
      async tx(fn) {
        if (transactionId) return fn(this);
        const { transactionId: id } = await client.send(new BeginTransactionCommand(base));
        try {
          const out = await fn(make(id));
          await client.send(new CommitTransactionCommand({ resourceArn: o.resourceArn, secretArn: o.secretArn, transactionId: id }));
          return out;
        } catch (e) {
          await client.send(new RollbackTransactionCommand({ resourceArn: o.resourceArn, secretArn: o.secretArn, transactionId: id })).catch(() => {});
          throw e;
        }
      },
    };
  };
  return make();
}

/** Tests only: an in-memory Postgres with schema.sql applied. */
export async function pgliteDb(): Promise<Db> {
  const { PGlite } = await import("@electric-sql/pglite");
  const { readFile } = await import("node:fs/promises");
  const pg = new PGlite();
  await pg.exec(await readFile(new URL("../schema.sql", import.meta.url), "utf8"));
  type Q = Pick<InstanceType<typeof PGlite>, "query">;
  const make = (q: Q, inTx: boolean): Db => ({
    all: async (sql, params) => (await q.query<any>(sql, params)).rows,
    first: async (sql, params) => (await q.query<any>(sql, params)).rows[0] ?? null,
    run: async (sql, params) => ({ changes: (await q.query(sql, params)).affectedRows ?? 0 }),
    tx(fn) { return inTx ? fn(this) : pg.transaction((t) => fn(make(t, true))); },
  });
  return make(pg, false);
}
