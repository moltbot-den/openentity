// Postgres through the RDS Data API, the same access layer the registry uses (no VPC on the Lambda).
import { randomBytes } from "node:crypto";
export { type Db, dataApiDb, splitSql } from "../../registry/src/db.ts";
import type { Db } from "../../registry/src/db.ts";

export const now = () => Math.floor(Date.now() / 1000);

/** prefix + 26 lowercase base-32 characters (130 random bits). */
export const newId = (prefix: string) => `${prefix}_${(BigInt(`0x${randomBytes(17).toString("hex")}`) >> 6n).toString(32).padStart(26, "0")}`;

/**
 * A paused staging cluster answers DatabaseResumingException for about 15 s (30 s or more after a long pause) while a
 * Data API call wakes it. Retry until it is up, within the 30 s Lambda limit. Production never pauses (0.5 ACU minimum).
 */
export function awake(db: Db, sleep = (ms: number) => new Promise((r) => setTimeout(r, ms)), budgetMs = 24_000): Db {
  const retry = async <T>(fn: () => Promise<T>): Promise<T> => {
    for (let waited = 0; ; waited += 2000) {
      try {
        return await fn();
      } catch (e) {
        if (waited >= budgetMs || !/DatabaseResuming/.test(`${(e as Error).name} ${(e as Error).message}`)) throw e;
        await sleep(2000);
      }
    }
  };
  return {
    all: (sql, p) => retry(() => db.all(sql, p)),
    first: (sql, p) => retry(() => db.first(sql, p)),
    run: (sql, p) => retry(() => db.run(sql, p)),
    tx: (fn) => retry(() => db.tx(fn)), // the error comes from BeginTransaction, before any statement ran
  };
}

/** Adds one to a fixed-window counter and returns the new count. */
export async function bump(db: Db, key: string, window: string): Promise<number> {
  const row = await db.first<{ count: number }>(
    "INSERT INTO rate_events (key, window_start, count) VALUES ($1, $2, 1) ON CONFLICT (key, window_start) DO UPDATE SET count = rate_events.count + 1 RETURNING count",
    [key, window],
  );
  return Number(row!.count);
}
