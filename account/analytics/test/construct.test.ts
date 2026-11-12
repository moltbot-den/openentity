import { App, Stack } from "aws-cdk-lib";
import { Template } from "aws-cdk-lib/assertions";
import { describe, expect, it } from "vitest";
import { AnalyticsForwarder } from "../forwarder/construct.ts";

const build = (environment: "production" | "staging") => {
  const stack = new Stack(new App(), "T", { env: { account: "099705791378", region: "us-east-1" } });
  new AnalyticsForwarder(stack, "A", { environment });
  return Template.fromStack(stack);
};
const statements = (t: Template) =>
  (Object.values(t.findResources("AWS::IAM::Policy")) as { Properties: { PolicyDocument: { Statement: { Action: string | string[]; Resource: unknown; Effect: string }[] } } }[]).flatMap((p) => p.Properties.PolicyDocument.Statement);
// Resources may be Fn::Join with a partition Ref: flatten to the aws partition.
const flat = (r: unknown): string => (typeof r === "string" ? r : (r as { "Fn::Join": [string, unknown[]] })["Fn::Join"][1].map((p) => (typeof p === "string" ? p : "aws")).join(""));
const arr = (x: unknown): any[] => (Array.isArray(x) ? x : [x]);

describe("AnalyticsForwarder construct", () => {
  it("has a DLQ with maxReceiveCount 5, partial batch responses and a DLQ alarm", () => {
    const t = build("staging");
    t.hasResourceProperties("AWS::SQS::Queue", { RedrivePolicy: { maxReceiveCount: 5 } });
    t.hasResourceProperties("AWS::Lambda::EventSourceMapping", { FunctionResponseTypes: ["ReportBatchItemFailures"] });
    t.resourceCountIs("AWS::CloudWatch::Alarm", 1);
  });

  it.each([["staging", "_prod"], ["production", "_staging"]] as const)("%s role can read only its own analytics parameters, nothing else", (env, other) => {
    const t = build(env);
    const ssm = statements(t).filter((s) => arr(s.Action).some((a) => a.startsWith("ssm:")));
    // Never a path read, never a wildcard.
    expect(ssm.flatMap((s) => arr(s.Action))).toEqual(["ssm:GetParameters"]);
    const res = ssm.flatMap((s) => arr(s.Resource)).map(flat);
    expect(res.length).toBe(6);
    for (const r of res) {
      expect(r).toMatch(/^arn:aws:ssm:us-east-1:099705791378:parameter\/openentity\/account\/analytics_[a-z0-9_]+$/);
      expect(r).not.toContain("*");
      expect(r).not.toContain(other === "_prod" ? "_prod" : "_staging");
    }
    for (const secret of ["code_pepper", "origin_verify", "customerio", "apple"]) expect(res.join()).not.toContain(secret);
    // KMS decrypt only through SSM.
    const kms = statements(t).find((s) => arr(s.Action).includes("kms:Decrypt"));
    expect(kms).toMatchObject({ Condition: { StringEquals: { "kms:ViaService": "ssm.us-east-1.amazonaws.com" } } });
  });
});
