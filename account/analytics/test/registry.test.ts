import { App, Stack } from "aws-cdk-lib";
import { Template } from "aws-cdk-lib/assertions";
import { describe, expect, it, vi } from "vitest";
import { probe } from "../monitoring/probe.ts";
import { RegistryMonitoring } from "../monitoring/registry.ts";

const t = (n: number) => ({ name: `t${n}`, url: `https://example.com/${n}`, expect: 200 as const });
const build = () => {
  const stack = new Stack(new App({ context: { "aws:cdk:bundling-stacks": [] } }), "T", { env: { account: "099705791378", region: "us-east-1" } });
  new RegistryMonitoring(stack, "R", { alertEmail: "ops@example.com", stage: "production", functionName: "fn", distributionIds: ["D1", "D2"], probeTargets: [t(1), t(2), { ...t(3), expect: "lt500" }] });
  return Template.fromStack(stack);
};

describe("RegistryMonitoring", () => {
  it("alarms on edge 5xx over 1% for 5 minutes, p95 over 800 ms, Lambda errors and every probe target, all to one topic", () => {
    const tpl = build();
    tpl.hasResourceProperties("AWS::CloudWatch::Alarm", { Namespace: "AWS/CloudFront", MetricName: "5xxErrorRate", Threshold: 1, EvaluationPeriods: 5 });
    tpl.hasResourceProperties("AWS::CloudWatch::Alarm", { MetricName: "Duration", ExtendedStatistic: "p95", Threshold: 800 });
    tpl.hasResourceProperties("AWS::CloudWatch::Alarm", { Namespace: "OpenEntity/Uptime", MetricName: "Up", TreatMissingData: "breaching" });
    const alarms = Object.values(tpl.findResources("AWS::CloudWatch::Alarm")) as { Properties: { AlarmActions?: unknown[]; Namespace?: string } }[];
    expect(alarms.filter((a) => a.Properties.Namespace === "OpenEntity/Uptime")).toHaveLength(3);
    for (const a of alarms) expect(a.Properties.AlarmActions).toHaveLength(1);
  });
  it("runs the probe every 5 minutes and creates no Synthetics canary", () => {
    const tpl = build();
    tpl.hasResourceProperties("AWS::Events::Rule", { ScheduleExpression: "rate(5 minutes)" });
    tpl.resourceCountIs("AWS::Synthetics::Canary", 0);
  });
});

describe("probe", () => {
  const f = (status: number) => vi.fn(async () => new Response("", { status })) as unknown as typeof fetch;
  it("is up on the expected status only", async () => {
    expect(await probe(f(200), t(1))).toBe(1);
    expect(await probe(f(503), t(1))).toBe(0);
    expect(await probe(f(404), t(1))).toBe(0);
  });
  it("accepts any status below 500 when asked, and treats a network failure as down", async () => {
    expect(await probe(f(406), { ...t(1), expect: "lt500" })).toBe(1);
    expect(await probe(f(502), { ...t(1), expect: "lt500" })).toBe(0);
    expect(await probe((async () => { throw new Error("dns"); }) as unknown as typeof fetch, t(1))).toBe(0);
  });
});
