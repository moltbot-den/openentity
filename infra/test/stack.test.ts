import { App } from "aws-cdk-lib";
import { Match, Template } from "aws-cdk-lib/assertions";
import { expect, test } from "vitest";
import { OpenEntityStack } from "../lib/stack.ts";

// Skip asset bundling: these tests read the template, not the Lambda zip.
const app = new App({ context: { "aws:cdk:bundling-stacks": [] } });
const t = Template.fromStack(new OpenEntityStack(app, "T", { env: { account: "099705791378", region: "us-east-1" } }));

test("Lambda runs outside any VPC and talks to Postgres through the Data API", () => {
  const fns = t.findResources("AWS::Lambda::Function", { Properties: { Runtime: "nodejs22.x" } });
  const app = Object.values(fns).find((f: any) => f.Properties.Environment?.Variables?.DB_CLUSTER_ARN) as any;
  expect(app.Properties.VpcConfig).toBeUndefined();
  expect(app.Properties.Environment.Variables).toMatchObject({ REGISTRY_HOST: "openentity.org", STAMP_BITS: "20", SUBSCRIBE_ENABLED: "false" });
  t.hasResourceProperties("AWS::RDS::DBCluster", { Engine: "aurora-postgresql", EnableHttpEndpoint: true, DeletionProtection: true });
});

test("snapshots sit under a one-year Object Lock in compliance mode", () => {
  t.hasResourceProperties("AWS::S3::Bucket", {
    ObjectLockEnabled: true,
    ObjectLockConfiguration: { ObjectLockEnabled: "Enabled", Rule: { DefaultRetention: { Mode: "COMPLIANCE", Days: 365 } } },
  });
});

test("the cron fires every minute", () => {
  t.hasResourceProperties("AWS::Scheduler::Schedule", { ScheduleExpression: "rate(1 minute)" });
});

test("CloudFront serves openentity.org, forwards the viewer address and the stamp header, and never caches dynamic paths", () => {
  t.hasResourceProperties("AWS::CloudFront::Distribution", {
    DistributionConfig: Match.objectLike({ Aliases: ["openentity.org"], DefaultCacheBehavior: Match.objectLike({ CachePolicyId: "4135ea2d-6df8-44a3-9df3-4b5a84be39ad" }) }),
  });
  t.hasResourceProperties("AWS::CloudFront::OriginRequestPolicy", {
    OriginRequestPolicyConfig: Match.objectLike({
      HeadersConfig: { HeaderBehavior: "whitelist", Headers: Match.arrayWith(["X-OE-Stamp", "CloudFront-Viewer-Address"]) },
    }),
  });
});

test("CI can deploy only from main of the public repo", () => {
  t.hasResourceProperties("AWS::IAM::Role", {
    AssumeRolePolicyDocument: Match.objectLike({
      Statement: [Match.objectLike({ Condition: Match.objectLike({ StringLike: { "token.actions.githubusercontent.com:sub": "repo:moltbot-den/openentity:ref:refs/heads/main" } }) })],
    }),
  });
});
