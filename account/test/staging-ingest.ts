// Live proof against staging, not part of the suite: product events ingest as Secure My Agent's staging test product
// (did:web:staging.account.openentity.org:test-products:sma; its seed is the SSM SecureString
// test_product_sma_seed_staging). One signed batch of two events, then the same batch again with a new signature.
// It checks the 202 answers, that event_ids holds each insert_id once, and what the forwarder did with the batch. It
// deletes its event_ids rows at the end.
//   AWS_PROFILE=openentity npx tsx account/test/staging-ingest.ts
import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { GetParameterCommand, SSMClient } from "@aws-sdk/client-ssm";
import { keyPairFromSeed, signRequest } from "@openentity/sdk";
import { dataApiDb } from "../src/db.ts";

const HOST = "staging.account.openentity.org", INGEST = `https://${HOST}/v1/events/ingest`, SMA = "did:web:securemyagent.ai";
const aws = (...args: string[]) => JSON.parse(execFileSync("aws", [...args, "--region", "us-east-1", "--output", "json"], { encoding: "utf8" }));
const outputs = aws("cloudformation", "describe-stacks", "--stack-name", "OpenEntityAccountStaging").Stacks[0].Outputs;
const out = (k: string) => outputs.find((o: any) => o.OutputKey === k).OutputValue;
const db = dataApiDb({ resourceArn: out("DbClusterArn"), secretArn: out("DbSecretArn"), database: "account" });
const seed = (await new SSMClient({ region: "us-east-1" }).send(new GetParameterCommand({ Name: "/openentity/account/test_product_sma_seed_staging", WithDecryption: true }))).Parameter!.Value!;
const kp = await keyPairFromSeed(new Uint8Array(Buffer.from(seed, "base64url")));
const forwarder = aws("lambda", "list-functions").Functions.map((f: any) => f.FunctionName).find((n: string) => n.startsWith("OpenEntityAccountStaging-AnalyticsFn"));
const step = (what: string) => console.log(`ok  ${what}`);
const wait = (s: number) => new Promise((r) => setTimeout(r, s * 1000));
/** The forwarder's log lines since `from` (ms), START/END/REPORT included: one START per invocation. */
const forwarderLog = (from: number): string[] =>
  aws("logs", "filter-log-events", "--log-group-name", `/aws/lambda/${forwarder}`, "--start-time", String(from)).events.map((e: any) => e.message.trim());

const owner = `did:web:${HOST}:o:${"a".repeat(52)}`;
const ids = [randomUUID(), randomUUID()];
const body = JSON.stringify({ events: ids.map((insert_id, i) => ({ name: "checkup_completed", time: Date.now(), insert_id, owner_did: owner, properties: { score_band: i ? "low" : "high", judged: true } })) });
const send = async () => {
  const headers = await signRequest({ method: "POST", url: INGEST, body: new TextEncoder().encode(body), privateKey: kp, did: `did:web:${HOST}:test-products:sma#key-1` });
  const r = await fetch(INGEST, { method: "POST", headers: { "content-type": "application/json", ...headers }, body });
  return { status: r.status, body: await r.json() };
};
const keys = ids.map((id) => `${SMA}|${id}`);
try {
  const t0 = Date.now();
  const first = await send();
  if (first.status !== 202 || first.body.accepted !== 2) throw new Error(`first send -> ${first.status} ${JSON.stringify(first.body)}`);
  step(`202 ${JSON.stringify(first.body)} for a batch signed as the test product sma (stands in for ${SMA})`);
  await wait(20);
  const afterFirst = forwarderLog(t0);
  const t1 = Date.now();
  const again = await send();
  if (again.status !== 202 || again.body.accepted !== 2) throw new Error(`resend -> ${again.status} ${JSON.stringify(again.body)}`);
  await wait(20);
  const afterResend = forwarderLog(t1);
  const rows = await db.all<{ key: string }>("SELECT key FROM event_ids WHERE key IN ($1, $2)", keys);
  if (rows.length !== 2) throw new Error(`event_ids holds ${rows.length} of the 2 insert_ids`);
  step(`resend: 202 ${JSON.stringify(again.body)}; event_ids holds each insert_id once`);
  const runs = (l: string[]) => l.filter((m) => m.startsWith("START")).length;
  console.log(`    forwarder after the first send: ${runs(afterFirst)} invocation(s); ${afterFirst.filter((m) => !/^(START|END|REPORT|INIT_START)/.test(m)).join(" | ") || "no log lines"}`);
  console.log(`    forwarder after the resend: ${runs(afterResend)} invocation(s); ${afterResend.filter((m) => !/^(START|END|REPORT|INIT_START)/.test(m)).join(" | ") || "no log lines"}`);
  if (runs(afterResend) !== 0) console.log("    (another staging client may have sent events in the window)");
  const ga4 = afterFirst.find((m) => /skipped for \d+ events: .*ga4|ga4: /.test(m));
  step(ga4 ? `GA4 not reached: ${ga4.split("\t").pop()}` : "GA4: the forwarder posted the batch to the Measurement Protocol without an error");
} catch (e) {
  console.error(`FAILED: ${(e as Error).message}`);
  process.exitCode = 1;
} finally {
  await db.run("DELETE FROM event_ids WHERE key IN ($1, $2)", keys).catch((e) => console.error(`cleanup: ${(e as Error).message}`));
}
