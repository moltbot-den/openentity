import { App, Stack } from "aws-cdk-lib";
import { Match, Template } from "aws-cdk-lib/assertions";
import { describe, expect, it, vi } from "vitest";
import { FRAMEWORKS, METHODS, metricLines } from "../forwarder/emf.ts";
import { makeHandler } from "../forwarder/handler.ts";
import { OperationsDashboard } from "../monitoring/dashboard.ts";
import { SignalAlarms } from "../monitoring/signals.ts";
import type { QueuedEvent } from "../src/validate.ts";

const ev = (event: string, props: Record<string, string | number | boolean> = {}, i = 0): QueuedEvent => ({ event: event as never, props, event_id: `00000000-0000-4000-8000-${String(i).padStart(12, "0")}`, ts_ms: 1790000000000, user_id: "u1", platform: "server" });
const stack = () => new Stack(new App(), "T", { env: { account: "099705791378", region: "us-east-1" } });

describe("EMF lines", () => {
  it("counts the events the alarms read, by method and framework, and keeps the longest pause", () => {
    const lines = metricLines("production", [
      ev("sign_in_failed", { method: "apple", reason: "x" }), ev("sign_in_failed", { method: "apple", reason: "y" }), ev("sign_in_completed", { method: "passkey", new_account: false }),
      ev("pair_failed", { reason: "x", framework: "crewai" }), ev("pair_failed", { reason: "x", framework: "weird-one" }), ev("pair_confirmed", { permissions_count: 1, seconds_from_code: 3 }),
      ev("approval_expired"), ev("agent_pause_enforced", { product: "securemyagent", seconds: 12 }), ev("agent_pause_enforced", { product: "securemyagent", seconds: 75 }),
      ev("app_opened"), // not read by any alarm: no metric
    ], 1);
    const by = (m: string, dim: string, v: string) => lines.find((l) => l[m] !== undefined && l[dim] === v) as Record<string, unknown>;
    expect(by("Count", "Method", "apple")).toMatchObject({ Event: "sign_in_failed", Count: 2, Stage: "production" });
    expect(by("Count", "Method", "passkey")).toMatchObject({ Event: "sign_in_completed", Count: 1 });
    expect(by("Count", "Framework", "crewai")).toMatchObject({ Event: "pair_failed", Count: 1 });
    expect(by("Count", "Framework", "other")).toMatchObject({ Event: "pair_failed", Count: 1 }); // unknown frameworks collapse: bounded metric count
    expect(by("Count", "Framework", "unknown")).toMatchObject({ Event: "pair_confirmed" });
    expect(lines.find((l) => l.PauseSeconds !== undefined)).toMatchObject({ PauseSeconds: 75 });
    expect(lines.some((l) => l.Event === "app_opened")).toBe(false);
    for (const l of lines) expect((l._aws as { CloudWatchMetrics: { Namespace: string }[] }).CloudWatchMetrics[0].Namespace).toBe("OpenEntity/Events");
  });
  it("the forwarder emits metrics only for records that reached every tool", async () => {
    const emit = vi.fn();
    const keys = { amplitudeApiKey: "a", posthogKey: "p", ga4MeasurementId: "g", ga4ApiSecret: "s" };
    const f = vi.fn(async (u: unknown, _i?: RequestInit) => new Response("", { status: String(u).includes("posthog") ? 500 : 200 }));
    const body = (i: number) => JSON.stringify({ event: "approval_expired", props: {}, event_id: `00000000-0000-4000-8000-${String(i).padStart(12, "0")}`, ts_ms: 1, install_id: "i", platform: "server" });
    const r = await makeHandler({ getKeys: async () => keys, fetch: f as unknown as typeof fetch, log: () => {}, stage: "production", emit })({ Records: [{ messageId: "m0", body: body(1) }] } as never);
    expect(r.batchItemFailures).toHaveLength(1);
    expect(emit).not.toHaveBeenCalled(); // retried later: counted once
  });
});

describe("SignalAlarms", () => {
  const t = () => { const s = stack(); new SignalAlarms(s, "S", { stage: "production" }); return Template.fromStack(s); };
  const alarms = (tpl: Template) => Object.values(tpl.findResources("AWS::CloudWatch::Alarm")) as { Properties: Record<string, any> }[];

  it("covers every PLAN 13.3 metric alert with the planned threshold and window", () => {
    const a = alarms(t());
    const named = (re: RegExp) => a.filter((x) => re.test(x.Properties.AlarmDescription ?? ""));
    expect(named(/Sign-in failures above 5%/)).toHaveLength(METHODS.length + 1); // each method, plus "other"
    for (const x of named(/Sign-in failures/)) expect(x.Properties).toMatchObject({ Threshold: 5, EvaluationPeriods: 1 });
    expect(named(/Push delivery failures above 2%/)[0].Properties.Threshold).toBe(2);
    expect(named(/pair_failed above 10%/)).toHaveLength(FRAMEWORKS.length + 2); // each framework, other, unknown
    expect(named(/pair_failed/)[0].Properties.Threshold).toBe(10);
    expect(named(/Verifier rejections above 1%/)[0].Properties.Threshold).toBe(1);
    expect(named(/Approval expiry above 30%/)[0].Properties.Metrics.some((m: any) => m.MetricStat?.Period === 86400)).toBe(true);
    expect(named(/more than 60 seconds/)[0].Properties).toMatchObject({ Threshold: 60, Statistic: "Maximum" });
    expect(named(/More than 3 recoveries/)[0].Properties.Threshold).toBe(3);
    expect(named(/legacy/)[0].Properties.Threshold).toBe(0);
  });
  it("rate alarms ignore windows with too few events", () => {
    for (const x of alarms(t()).filter((y) => /Sign-in failures|Push|pair_failed|Verifier|expiry/.test(y.Properties.AlarmDescription)))
      expect(JSON.stringify(x.Properties.Metrics)).toMatch(/IF\(.* >= (10|20), 100 \* b/);
  });
  it("the legacy approval alarm sends nothing until switched on", () => {
    const s = stack(); new SignalAlarms(s, "S", { stage: "production" });
    Template.fromStack(s).hasResourceProperties("AWS::CloudWatch::Alarm", { AlarmDescription: Match.stringLikeRegexp("legacy"), ActionsEnabled: false });
    const s2 = stack(); new SignalAlarms(s2, "S", { stage: "production", legacyApprovalActionsEnabled: true });
    Template.fromStack(s2).hasResourceProperties("AWS::CloudWatch::Alarm", { AlarmDescription: Match.stringLikeRegexp("legacy"), ActionsEnabled: true });
  });
});

describe("OperationsDashboard", () => {
  it("shows p95, 5xx, uptime, WebSocket connections, SQS and DLQ depth for the registry and the account service", () => {
    const s = stack();
    new OperationsDashboard(s, "D", { name: "OpenEntity-production", registryFunctionName: "fn", distributionIds: ["D1"], probeTargets: [{ name: "t", url: "https://x", expect: 200 }] });
    const body = JSON.stringify(Template.fromStack(s).findResources("AWS::CloudWatch::Dashboard"));
    for (const needle of ["p95", "5xx", "Uptime", "ConnectCount", "ApproximateNumberOfMessagesVisible", "Dlq", "OpenEntityAccount", "AWS/Lambda", "AWS/CloudFront"]) expect(body, needle).toContain(needle);
  });
});
