import { App } from "aws-cdk-lib";
import { Match, Template } from "aws-cdk-lib/assertions";
import { expect, test } from "vitest";
import { OpenEntityAccountStack, type AccountStage } from "../lib/account-stack.ts";

// Skip asset bundling: these tests read the templates, not the Lambda zip. Synthesized at load (see stack.test.ts).
const synth = (stage: AccountStage) => Template.fromStack(new OpenEntityAccountStack(new App({ context: { "aws:cdk:bundling-stacks": [] } }), `A${stage}`, { env: { account: "099705791378", region: "us-east-1" }, stage }));
const prod = synth("production"), staging = synth("staging");
const all = (t: Template, type: string) => Object.values(t.findResources(type)) as any[];
const appFn = (t: Template) => all(t, "AWS::Lambda::Function").find((f) => f.Properties.Environment?.Variables?.HOST);

test("production Aurora: a writer and a reader in two Availability Zones at 0.5 ACU minimum, Data API on, protected", () => {
  prod.hasResourceProperties("AWS::RDS::DBCluster", {
    Engine: "aurora-postgresql", EnableHttpEndpoint: true, DeletionProtection: true, StorageEncrypted: true,
    ServerlessV2ScalingConfiguration: { MinCapacity: 0.5, MaxCapacity: 4 },
  });
  const instances = all(prod, "AWS::RDS::DBInstance");
  expect(instances).toHaveLength(2);
  expect(new Set(instances.map((i) => JSON.stringify(i.Properties.AvailabilityZone))).size).toBe(2);
});

test("staging Aurora: one writer that pauses when idle (0 ACU)", () => {
  staging.hasResourceProperties("AWS::RDS::DBCluster", {
    EnableHttpEndpoint: true, ServerlessV2ScalingConfiguration: { MinCapacity: 0, MaxCapacity: 2, SecondsUntilAutoPause: 300 },
  });
  expect(all(staging, "AWS::RDS::DBInstance")).toHaveLength(1);
});

test("four KMS keys per stage: P-256 for tokens, P-256 for key log close entries, Ed25519 for the DID, a rotating data key", () => {
  for (const t of [prod, staging]) {
    const keys = all(t, "AWS::KMS::Key").map((k) => k.Properties);
    expect(keys).toHaveLength(4);
    expect(keys.filter((k) => k.KeySpec === "ECC_NIST_P256" && k.KeyUsage === "SIGN_VERIFY")).toHaveLength(2);
    expect(keys.filter((k) => k.KeySpec === "ECC_NIST_EDWARDS25519" && k.KeyUsage === "SIGN_VERIFY")).toHaveLength(1);
    expect(keys.filter((k) => !k.KeySpec && k.EnableKeyRotation === true)).toHaveLength(1);
  }
});

test("the function runs outside any VPC; production sign-in stays closed, staging is open", () => {
  for (const t of [prod, staging]) expect(appFn(t).Properties.VpcConfig).toBeUndefined();
  expect(appFn(prod).Properties.Environment.Variables).toMatchObject({ STAGE: "production", HOST: "account.openentity.org", SIGNIN_OPEN: "0", PARAM_SUFFIX: "prod" });
  expect(appFn(staging).Properties.Environment.Variables).toMatchObject({ STAGE: "staging", HOST: "staging.account.openentity.org", SIGNIN_OPEN: "1", PARAM_SUFFIX: "staging" });
});

test("isolation: the role reads only /openentity/account/ parameters, never the registry's /openentity/app or the other stage's values", () => {
  // The app function's own role. The analytics forwarder has its own, held to its stage's analytics names (below).
  const statements = (t: Template) => {
    const role = appFn(t).Properties.Role["Fn::GetAtt"][0];
    return all(t, "AWS::IAM::Policy").filter((p) => JSON.stringify(p.Properties.Roles) === JSON.stringify([{ Ref: role }])).flatMap((p) => p.Properties.PolicyDocument.Statement);
  };
  for (const [t, other] of [[prod, "staging"], [staging, "prod"]] as const) {
    const text = JSON.stringify(statements(t));
    expect(text).not.toContain("parameter/openentity/app");
    const ssmAllow = statements(t).filter((s) => s.Effect === "Allow" && JSON.stringify(s.Action).includes("ssm:"));
    expect(ssmAllow.map((s) => s.Action)).toEqual(["ssm:GetParameters"]);
    expect(JSON.stringify(ssmAllow[0].Resource)).toContain("parameter/openentity/account/*");
    const deny = statements(t).find((s) => s.Effect === "Deny");
    expect(JSON.stringify(deny.Resource)).toContain(`parameter/openentity/account/*_${other}`);
  }
});

test("CloudFront serves the account host, forwards every viewer header but Host, never caches, and adds the origin secret", () => {
  prod.hasResourceProperties("AWS::CloudFront::Distribution", {
    DistributionConfig: Match.objectLike({
      Aliases: ["account.openentity.org"],
      DefaultCacheBehavior: Match.objectLike({
        CachePolicyId: "4135ea2d-6df8-44a3-9df3-4b5a84be39ad", // CachingDisabled
        OriginRequestPolicyId: "b689b0a8-53d0-40ab-baf2-68738e2966ac", // AllViewerExceptHostHeader
      }),
    }),
  });
  const origin = all(prod, "AWS::CloudFront::Distribution")[0].Properties.DistributionConfig.Origins[0];
  expect(origin.OriginCustomHeaders.map((h: any) => h.HeaderName)).toEqual(["x-origin-verify"]);
  prod.hasResourceProperties("AWS::CertificateManager::Certificate", { DomainName: "account.openentity.org", ValidationMethod: "DNS" });
  staging.hasResourceProperties("AWS::CloudFront::Distribution", { DistributionConfig: Match.objectLike({ Aliases: ["staging.account.openentity.org"] }) });
});

test("agent WebSocket: action routing, a MOCK heartbeat with a route response, the agents host on stage v1", () => {
  prod.hasResourceProperties("AWS::ApiGatewayV2::Api", { ProtocolType: "WEBSOCKET", RouteSelectionExpression: "$request.body.action" });
  for (const key of ["$connect", "$disconnect", "$default", "sync", "ack", "heartbeat"]) prod.hasResourceProperties("AWS::ApiGatewayV2::Route", { RouteKey: key });
  prod.hasResourceProperties("AWS::ApiGatewayV2::Integration", { IntegrationType: "MOCK" });
  prod.hasResourceProperties("AWS::ApiGatewayV2::IntegrationResponse", { ResponseTemplates: { $default: '{"type":"heartbeat"}' } });
  prod.hasResourceProperties("AWS::ApiGatewayV2::RouteResponse", { RouteResponseKey: "$default" });
  prod.hasResourceProperties("AWS::ApiGatewayV2::DomainName", { DomainName: "agents.account.openentity.org" });
  prod.hasResourceProperties("AWS::ApiGatewayV2::Stage", { StageName: "v1", AutoDeploy: true });
  staging.hasResourceProperties("AWS::ApiGatewayV2::DomainName", { DomainName: "agents.staging.account.openentity.org" });
});

test("the analytics forwarder reads only its own stage's analytics parameters, by name", () => {
  for (const [t, suffix, other] of [[prod, "prod", "staging"], [staging, "staging", "prod"]] as const) {
    const app = appFn(t).Properties.Role["Fn::GetAtt"][0];
    const ssm = all(t, "AWS::IAM::Policy").filter((p) => JSON.stringify(p.Properties.Roles) !== JSON.stringify([{ Ref: app }]))
      .flatMap((p) => p.Properties.PolicyDocument.Statement).filter((st: any) => JSON.stringify(st.Action).includes("ssm:"));
    const text = JSON.stringify(ssm);
    expect(text).not.toContain("GetParametersByPath");
    expect(text).toContain(`analytics_`);
    expect(text).not.toContain(`_${other}`);
    expect(text).not.toMatch(/parameter\/openentity\/account\/\*/);
    expect(text).toContain(`_${suffix}`);
  }
});

test("events go to the analytics forwarder's queue (dead-letter queue, alarm), and only the app function may send to it", () => {
  for (const t of [prod, staging]) {
    const queues = Object.entries(t.findResources("AWS::SQS::Queue"));
    expect(queues).toHaveLength(2); // the forwarder's queue and its DLQ; no second events queue
    const [queueId] = queues.find(([, q]: any) => q.Properties.RedrivePolicy?.maxReceiveCount === 5)!;
    expect(appFn(t).Properties.Environment.Variables.EVENTS_QUEUE_URL).toEqual({ Ref: queueId });
    t.hasResourceProperties("AWS::Lambda::EventSourceMapping", { FunctionResponseTypes: ["ReportBatchItemFailures"] });
    t.hasResourceProperties("AWS::CloudWatch::Alarm", { AlarmDescription: Match.stringLikeRegexp("dead-letter") });
  }
});

test("jobs tick: every minute in production, every 6 hours in staging, no retries of a missed tick", () => {
  prod.hasResourceProperties("AWS::Events::Rule", { ScheduleExpression: "rate(1 minute)", Targets: [Match.objectLike({ RetryPolicy: { MaximumRetryAttempts: 0, MaximumEventAgeInSeconds: 60 } })] });
  staging.hasResourceProperties("AWS::Events::Rule", { ScheduleExpression: "rate(6 hours)" });
});

test("attachments: a private bucket (all public access blocked, SSE, TLS only, 90-day expiry), the app reads and writes uploads/ only", () => {
  for (const t of [prod, staging]) {
    t.hasResourceProperties("AWS::S3::Bucket", {
      PublicAccessBlockConfiguration: { BlockPublicAcls: true, BlockPublicPolicy: true, IgnorePublicAcls: true, RestrictPublicBuckets: true },
      BucketEncryption: Match.objectLike({ ServerSideEncryptionConfiguration: [Match.objectLike({ ServerSideEncryptionByDefault: { SSEAlgorithm: "AES256" } })] }),
      LifecycleConfiguration: { Rules: Match.arrayWith([Match.objectLike({ ExpirationInDays: 90 })]) },
    });
    t.hasResourceProperties("AWS::S3::BucketPolicy", { PolicyDocument: { Statement: Match.arrayWith([Match.objectLike({ Effect: "Deny", Condition: { Bool: { "aws:SecureTransport": "false" } } })]) } });
    const s3Grants = all(t, "AWS::IAM::Policy").flatMap((p) => p.Properties.PolicyDocument.Statement).filter((st: any) => JSON.stringify(st.Action).includes("s3:"));
    expect(s3Grants.length).toBeGreaterThan(0);
    for (const g of s3Grants) expect(JSON.stringify(g.Resource)).toContain("/uploads/*");
    expect(appFn(t).Properties.Environment.Variables.ATTACHMENTS_BUCKET).toBeDefined();
  }
});

test("the account stacks stand alone: nothing is imported from the registry stack", () => {
  for (const t of [prod, staging]) expect(JSON.stringify(t.toJSON())).not.toContain("Fn::ImportValue");
});

test("each stage's policy on the shared CI role has its own name, so both stages can attach one", () => {
  const name = (t: Template) => all(t, "AWS::IAM::Policy").find((p) => JSON.stringify(p.Properties.Roles) === '["openentity-github-deploy"]').Properties.PolicyName;
  expect(name(prod)).not.toBe(name(staging));
});

test("the close key is never deleted: retained by CloudFormation in both stages, and its policy denies scheduling deletion", () => {
  for (const t of [prod, staging]) {
    const close = Object.values(t.findResources("AWS::KMS::Key")).find((k: any) => String(k.Properties.Description).includes("close entries")) as any;
    expect(close.DeletionPolicy).toBe("Retain");
    const deny = close.Properties.KeyPolicy.Statement.find((st: any) => st.Effect === "Deny");
    expect(deny.Action).toEqual(["kms:ScheduleKeyDeletion", "kms:DisableKey"]);
    expect(deny.Principal).toEqual({ AWS: "*" });
  }
});

test("App Review: an alarm when APP_REVIEW_OPEN stays on for 21 days, per stage", () => {
  for (const [t, stage] of [[prod, "production"], [staging, "staging"]] as const) {
    t.hasResourceProperties("AWS::CloudWatch::Alarm", {
      Namespace: "OpenEntity/Account", MetricName: "AppReviewOpenDays", Dimensions: [{ Name: "Stage", Value: stage }],
      Threshold: 21, ComparisonOperator: "GreaterThanOrEqualToThreshold", Statistic: "Maximum", TreatMissingData: "notBreaching",
    });
  }
});
