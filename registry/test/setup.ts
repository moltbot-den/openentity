import { env } from "cloudflare:test";
import type { Env } from "../src/env.ts";

const e = env as unknown as Env & { SCHEMA_SQL: string };
const sql = e.SCHEMA_SQL.replace(/--.*$/gm, "");
await e.DB.batch(sql.split(/;\s*$/m).map((s) => s.trim()).filter(Boolean).map((s) => e.DB.prepare(s)));
