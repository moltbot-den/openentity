import { App, Stack } from "aws-cdk-lib";
import { Match, Template } from "aws-cdk-lib/assertions";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as sqs from "aws-cdk-lib/aws-sqs";
import { describe, expect, it } from "vitest";
import { AccountServiceMonitoring } from "../monitoring/aws.ts";

const build = (httpApiId?: string) => {
  const stack = new Stack(new App(), "T");
  const fn = new lambda.Function(stack, "F", { runtime: lambda.Runtime.NODEJS_22_X, handler: "i.h", code: lambda.Code.fromInline("exports.h=1") });
  new AccountServiceMonitoring(stack, "M", { alertEmail: "ops@example.com", functions: [fn], httpApiId, dlqs: [new sqs.Queue(stack, "Q")] });
  return Template.fromStack(stack);
};

describe("AccountServiceMonitoring", () => {
  it("alarms on errors, throttles, p95 over 800 ms, 5xx over 1% for 5 minutes and the DLQ, to an email topic", () => {
    const t = build("abc123");
    t.hasResourceProperties("AWS::SNS::Subscription", { Protocol: "email", Endpoint: "ops@example.com" });
    t.hasResourceProperties("AWS::CloudWatch::Alarm", { MetricName: "Errors" });
    t.hasResourceProperties("AWS::CloudWatch::Alarm", { MetricName: "Throttles" });
    t.hasResourceProperties("AWS::CloudWatch::Alarm", { MetricName: "Latency", ExtendedStatistic: "p95", Threshold: 800 });
    t.hasResourceProperties("AWS::CloudWatch::Alarm", { Threshold: 1, EvaluationPeriods: 5, Metrics: Match.anyValue() });
    t.hasResourceProperties("AWS::CloudWatch::Alarm", { MetricName: "ApproximateNumberOfMessagesVisible" });
    expect(Object.keys(t.findResources("AWS::CloudWatch::Alarm")).length).toBe(5);
    for (const a of Object.values(t.findResources("AWS::CloudWatch::Alarm")) as { Properties: { AlarmActions: unknown[] } }[]) expect(a.Properties.AlarmActions).toHaveLength(1);
  });
  it("falls back to Lambda metrics without an HTTP API id and creates no canaries", () => {
    const t = build();
    t.resourceCountIs("AWS::Synthetics::Canary", 0);
    t.hasResourceProperties("AWS::CloudWatch::Alarm", { MetricName: "Duration", ExtendedStatistic: "p95", Threshold: 800 });
  });
});
