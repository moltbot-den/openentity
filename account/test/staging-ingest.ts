// Live proof against staging, not part of the suite: product events ingest as Secure My Agent's staging test product
// (did:web:staging.account.openentity.org:test-products:sma; its seed is the SSM SecureString
// test_product_sma_seed_staging). One signed batch of two events, then the same batch again with a new signature.
// Checks: 202 both times; event_ids holds each insert_id once, so the resend is not queued again; the batch reaches the
// queue and the forwarder consumes it without an error, logging the tools it skipped for missing credentials, while the
// dead-letter queue does not grow. It deletes its event_ids rows at the end.
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
const dlq = aws("sqs", "list-queues", "--queue-name-prefix", "OpenEntityAccountStaging-AnalyticsDlq").QueueUrls[0];
const dlqDepth = () => Number(aws("sqs", "get-queue-attributes", "--queue-url", dlq, "--attribute-names", "ApproximateNumberOfMessages").Attributes.ApproximateNumberOfMessages);
const step = (what: string) => console.log(`ok  ${what}`);
const wait = (s: number) => new Promise((r) => setTimeout(r, s * 1000));
/** The forwarder's log lines since `from` (ms), START/END/REPORT included: one START per invocation. */
const forwarderLog = (from: number): string[] =>
  aws("logs", "filter-log-events", "--log-group-name", `/aws/lambda/${forwarder}`, "--start-time", String(from)).events.map((e: any) => e.message.trim());
/** Events the forwarder's runs in `lines` skipped every unconfigured tool for. */
const skippedEvents = (lines: string[]) => lines.reduce((n, m) => n + Number(/not configured, skipped for (\d+) events/.exec(m)?.[1] ?? 0), 0);
/** Waits until `want` events show in the forwarder's log since `from` (ingestion takes up to a minute on a new stream). */
async function forwarderRuns(from: number, seconds: number, want: number): Promise<string[]> {
  let lines: string[] = [];
  for (let t = 0; t < seconds; t += 10) {
    await wait(10);
    lines = forwarderLog(from);
    if (want && skippedEvents(lines) >= want) return lines;
  }
  return lines;
}

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
  const t0 = Date.now(), dlqBefore = dlqDepth();
  const first = await send();
  if (first.status !== 202 || first.body.accepted !== 2) throw new Error(`first send -> ${first.status} ${JSON.stringify(first.body)}`);
  step(`202 ${JSON.stringify(first.body)} for a batch signed as the test product sma (stands in for ${SMA})`);
  const afterFirst = await forwarderRuns(t0, 90, 2);
  const t1 = Date.now();
  const again = await send();
  if (again.status !== 202 || again.body.accepted !== 2) throw new Error(`resend -> ${again.status} ${JSON.stringify(again.body)}`);
  const afterResend = await forwarderRuns(t1, 40, 0);
  const rows = await db.all<{ key: string }>("SELECT key FROM event_ids WHERE key IN ($1, $2)", keys);
  if (rows.length !== 2) throw new Error(`event_ids holds ${rows.length} of the 2 insert_ids`);
  step(`resend: 202 ${JSON.stringify(again.body)}; event_ids holds each insert_id once`);
  const runs = (l: string[]) => l.filter((m) => m.startsWith("START")).length;
  const said = (l: string[]) => l.filter((m) => !/^(START|END|REPORT|INIT_START)/.test(m)).map((m) => m.split("\t").pop());
  if (!runs(afterFirst)) throw new Error("the forwarder never ran: the batch did not reach the queue");
  if (afterFirst.some((m) => /Invoke Error|Task timed out/.test(m))) throw new Error(`the forwarder failed: ${said(afterFirst).join(" | ")}`);
  const skipped = said(afterFirst).find((m) => /^not configured, skipped for \d+ events: /.test(m!));
  step(`queued and consumed: ${runs(afterFirst)} forwarder run(s) took ${skippedEvents(afterFirst)} event(s), no error${skipped ? `; "${skipped}"` : "; every tool configured"}`);
  console.log(`    forwarder after the resend: ${runs(afterResend)} run(s)${runs(afterResend) ? ` (other staging traffic in the window: ${said(afterResend).join(" | ")})` : ""}`);
  const dlqAfter = dlqDepth();
  if (dlqAfter > dlqBefore) throw new Error(`the dead-letter queue grew from ${dlqBefore} to ${dlqAfter}`);
  step(`dead-letter queue: ${dlqBefore} before, ${dlqAfter} after`);
} catch (e) {
  console.error(`FAILED: ${(e as Error).message}`);
  process.exitCode = 1;
} finally {
  await db.run("DELETE FROM event_ids WHERE key IN ($1, $2)", keys).catch((e) => console.error(`cleanup: ${(e as Error).message}`));
}
