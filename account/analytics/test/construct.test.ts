import { App, Stack } from "aws-cdk-lib";
import { Template } from "aws-cdk-lib/assertions";
import * as secretsmanager from "aws-cdk-lib/aws-secretsmanager";
import { describe, expect, it } from "vitest";
import { AnalyticsForwarder } from "../forwarder/construct.ts";

describe("AnalyticsForwarder construct", () => {
  it("has a DLQ with maxReceiveCount 5, partial batch responses and a DLQ alarm", () => {
    const stack = new Stack(new App(), "T");
    new AnalyticsForwarder(stack, "A", { environment: "staging", accountSecret: secretsmanager.Secret.fromSecretNameV2(stack, "S", "openentity/account") });
    const t = Template.fromStack(stack);
    t.hasResourceProperties("AWS::SQS::Queue", { RedrivePolicy: { maxReceiveCount: 5 } });
    t.hasResourceProperties("AWS::Lambda::EventSourceMapping", { FunctionResponseTypes: ["ReportBatchItemFailures"] });
    t.resourceCountIs("AWS::CloudWatch::Alarm", 1);
  });
});
