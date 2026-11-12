import { App, Stack } from "aws-cdk-lib";
import { Match, Template } from "aws-cdk-lib/assertions";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as sqs from "aws-cdk-lib/aws-sqs";
import { describe, expect, it } from "vitest";
import { AccountServiceMonitoring } from "../monitoring/aws.ts";

const build = (httpApiId?: string) => {
  const stack = new Stack(new App({ context: { "aws:cdk:bundling-stacks": [] } }), "T", { env: { account: "099705791378", region: "us-east-1" } });
  const fn = new lambda.Function(stack, "F", { runtime: lambda.Runtime.NODEJS_22_X, handler: "i.h", code: lambda.Code.fromInline("exports.h=1") });
  new AccountServiceMonitoring(stack, "M", { alertEmail: "ops@example.com", stage: "staging", functions: [fn], httpApiId, dlqs: [new sqs.Queue(stack, "Q")] });
  return Template.fromStack(stack);
};

describe("AccountServiceMonitoring", () => {
  it("alarms on errors, throttles, p95 over 800 ms, 5xx over 1% for 5 minutes and the DLQ, to an email topic", () => {
    const t = build("abc123");
    t.hasResourceProperties("AWS::SNS::Subscription", { Protocol: "lambda" });
    t.resourceCountIs("AWS::SNS::Subscription", 1); // never an email subscription: it needs a confirmation click
    t.hasResourceProperties("AWS::CloudWatch::Alarm", { MetricName: "Errors" });
    t.hasResourceProperties("AWS::CloudWatch::Alarm", { MetricName: "Throttles" });
    t.hasResourceProperties("AWS::CloudWatch::Alarm", { MetricName: "Latency", ExtendedStatistic: "p95", Threshold: 800 });
    t.hasResourceProperties("AWS::CloudWatch::Alarm", { Threshold: 1, EvaluationPeriods: 5, Metrics: Match.anyValue() });
    t.hasResourceProperties("AWS::CloudWatch::Alarm", { MetricName: "ApproximateNumberOfMessagesVisible" });
    expect(Object.keys(t.findResources("AWS::CloudWatch::Alarm")).length).toBe(5);
    for (const a of Object.values(t.findResources("AWS::CloudWatch::Alarm")) as { Properties: { AlarmActions: unknown[]; OKActions: unknown[] } }[]) { expect(a.Properties.AlarmActions).toHaveLength(1); expect(a.Properties.OKActions).toHaveLength(1); }
  });
  it.each([["staging", "_prod"], ["production", "_staging"]] as const)("%s relay reads only the account Customer.io key for its own stage", (stage, other) => {
    const stack = new Stack(new App({ context: { "aws:cdk:bundling-stacks": [] } }), "T", { env: { account: "099705791378", region: "us-east-1" } });
    new AccountServiceMonitoring(stack, "M", { alertEmail: "ops@example.com", stage, functions: [] });
    const t = Template.fromStack(stack);
    const stmts = (Object.values(t.findResources("AWS::IAM::Policy")) as { Properties: { PolicyDocument: { Statement: { Action: string | string[]; Resource: unknown; Condition?: unknown }[] } } }[]).flatMap((p) => p.Properties.PolicyDocument.Statement);
    const ssm = stmts.filter((s) => [s.Action].flat().some((x) => x.startsWith("ssm:")));
    expect(ssm.flatMap((s) => [s.Action].flat())).toEqual(["ssm:GetParameters"]);
    const res = ssm.flatMap((s) => [s.Resource].flat()).map((r) => (typeof r === "string" ? r : (r as { "Fn::Join": [string, unknown[]] })["Fn::Join"][1].map((x) => (typeof x === "string" ? x : "aws")).join("")));
    const own = stage === "production" ? "_prod" : "_staging";
    expect(res.sort()).toEqual([`arn:aws:ssm:us-east-1:099705791378:parameter/openentity/account/cio_app_api_key`, `arn:aws:ssm:us-east-1:099705791378:parameter/openentity/account/cio_app_api_key${own}`].sort());
    const all = JSON.stringify(stmts);
    expect(all).not.toContain("openentity/app"); // the account service never reads the registry's secret
    expect(all).not.toContain(`cio_app_api_key${other}`);
    expect(all).not.toContain("*");
    expect(stmts.find((s) => [s.Action].flat().includes("kms:Decrypt"))).toMatchObject({ Condition: { StringEquals: { "kms:ViaService": "ssm.us-east-1.amazonaws.com" } } });
  });
  it("lets CloudWatch publish to the topic (the SSL-only policy has no Allow by itself)", () => {
    build("abc123").hasResourceProperties("AWS::SNS::TopicPolicy", { PolicyDocument: { Statement: Match.arrayWith([Match.objectLike({ Effect: "Allow", Principal: { Service: "cloudwatch.amazonaws.com" }, Action: "sns:Publish" })]) } });
  });
  it("falls back to Lambda metrics without an HTTP API id and creates no canaries", () => {
    const t = build();
    t.resourceCountIs("AWS::Synthetics::Canary", 0);
    t.hasResourceProperties("AWS::CloudWatch::Alarm", { MetricName: "Duration", ExtendedStatistic: "p95", Threshold: 800 });
  });
});
