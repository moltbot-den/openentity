import { App, Stack } from "aws-cdk-lib";
import { Match, Template } from "aws-cdk-lib/assertions";
import { describe, expect, it } from "vitest";
import { AnalyticsForwarder } from "../forwarder/construct.ts";

describe("AnalyticsForwarder construct", () => {
  it("has a DLQ with maxReceiveCount 5, partial batch responses and a DLQ alarm", () => {
    const stack = new Stack(new App(), "T");
    new AnalyticsForwarder(stack, "A", { environment: "staging" });
    const t = Template.fromStack(stack);
    t.hasResourceProperties("AWS::SQS::Queue", { RedrivePolicy: { maxReceiveCount: 5 } });
    t.hasResourceProperties("AWS::Lambda::EventSourceMapping", { FunctionResponseTypes: ["ReportBatchItemFailures"] });
    t.hasResourceProperties("AWS::IAM::Policy", { PolicyDocument: { Statement: Match.arrayWith([Match.objectLike({ Action: "ssm:GetParametersByPath", Effect: "Allow" })]) } });
    t.resourceCountIs("AWS::CloudWatch::Alarm", 1);
  });
});
