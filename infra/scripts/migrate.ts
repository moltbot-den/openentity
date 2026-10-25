// Applies registry/schema.sql (idempotent: CREATE ... IF NOT EXISTS) to Aurora through the Data API.
//   tsx scripts/migrate.ts [extra.sql]   # an optional second file runs after the schema, e.g. a data import
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dataApiDb } from "../../registry/src/db.ts";

const profile = process.env.GITHUB_ACTIONS ? [] : ["--profile", "openentity"];
const stack = JSON.parse(
  execFileSync("aws", ["cloudformation", "describe-stacks", "--stack-name", "OpenEntity", "--region", "us-east-1", "--output", "json", ...profile], { encoding: "utf8" }),
).Stacks[0];
const out = (k: string) => stack.Outputs.find((o: any) => o.OutputKey === k).OutputValue;
if (!process.env.GITHUB_ACTIONS) process.env.AWS_PROFILE = "openentity";
process.env.AWS_REGION ??= "us-east-1";

const db = dataApiDb({ resourceArn: out("DbClusterArn"), secretArn: out("DbSecretArn"), database: "openentity" });
const files = [fileURLToPath(new URL("../../registry/schema.sql", import.meta.url)), ...process.argv.slice(2)];
for (const f of files) {
  const statements = readFileSync(f, "utf8").replace(/^\s*--.*$/gm, "").split(/;\s*$/m).map((s) => s.trim()).filter(Boolean);
  await db.tx(async (t) => {
    for (const s of statements) await t.run(s);
  });
  console.log(`applied ${statements.length} statements from ${f}`);
}
