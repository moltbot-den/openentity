// Scheduled uptime probe (replaces CloudWatch Synthetics canaries, which are billed per run).
// EventBridge runs it every 5 minutes; it writes OpenEntity/Uptime Up (1 or 0) per target and the alarms read that metric.
import { CloudWatchClient, PutMetricDataCommand } from "@aws-sdk/client-cloudwatch";

export type Target = { name: string; url: string; /** exact status, or "lt500" for endpoints that answer 4xx without the right headers */ expect: number | "lt500" };

export async function probe(f: typeof fetch, t: Target): Promise<0 | 1> {
  try {
    const r = await f(t.url, { redirect: "manual", signal: AbortSignal.timeout(8000), headers: { "user-agent": "openentity-uptime-probe" } });
    await r.body?.cancel();
    return (t.expect === "lt500" ? r.status < 500 : r.status === t.expect) ? 1 : 0;
  } catch {
    return 0; // timeout, DNS or TLS failure
  }
}

const cw = new CloudWatchClient({});
export async function handler(): Promise<void> {
  const targets = JSON.parse(process.env.TARGETS!) as Target[];
  const ups = await Promise.all(targets.map((t) => probe(fetch, t)));
  await cw.send(new PutMetricDataCommand({
    Namespace: "OpenEntity/Uptime",
    MetricData: targets.map((t, i) => ({ MetricName: "Up", Dimensions: [{ Name: "Target", Value: t.name }], Value: ups[i], Unit: "None" })),
  }));
}
