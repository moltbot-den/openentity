import { App } from "aws-cdk-lib";
import { Match, Template } from "aws-cdk-lib/assertions";
import { expect, test } from "vitest";
import { CSP, OpenEntityStack } from "../lib/stack.ts";

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

test("every response forbids framing and carries a CSP limited to what the pages load", () => {
  t.hasResourceProperties("AWS::CloudFront::ResponseHeadersPolicy", {
    ResponseHeadersPolicyConfig: Match.objectLike({
      SecurityHeadersConfig: Match.objectLike({
        FrameOptions: { FrameOption: "DENY", Override: true },
        ContentSecurityPolicy: { ContentSecurityPolicy: CSP, Override: true },
      }),
    }),
  });
  expect(CSP).toContain("frame-ancestors 'none'");
  expect(CSP).toContain("object-src 'none'");
  expect(CSP).not.toMatch(/\*|'unsafe-eval'/);
  expect(CSP.split('; ').find((d) => d.startsWith('script-src'))).not.toContain("'unsafe-inline'");
});

test("mcp.openentity.org is its own distribution and certificate on the same function URL, tagged with x-oe-site, never cached", () => {
  t.hasResourceProperties("AWS::CertificateManager::Certificate", { DomainName: "mcp.openentity.org", ValidationMethod: "DNS" });
  t.hasResourceProperties("AWS::CertificateManager::Certificate", { DomainName: "openentity.org" });
  const dists = Object.values(t.findResources("AWS::CloudFront::Distribution")) as any[];
  const mcp = dists.find((d) => d.Properties.DistributionConfig.Aliases?.[0] === "mcp.openentity.org");
  const main = dists.find((d) => d.Properties.DistributionConfig.Aliases?.[0] === "openentity.org");
  const header = (d: any) => d.Properties.DistributionConfig.Origins[0].OriginCustomHeaders.map((h: any) => h.HeaderName);
  expect(header(mcp)).toEqual(expect.arrayContaining(["x-origin-verify", "x-oe-site"]));
  expect(header(main)).not.toContain("x-oe-site");
  expect(mcp.Properties.DistributionConfig.DefaultCacheBehavior.CachePolicyId).toBe("4135ea2d-6df8-44a3-9df3-4b5a84be39ad");
  expect(Object.keys(t.findOutputs("McpDistributionDomain"))).toEqual(["McpDistributionDomain"]);
});

test("CI can deploy only from main of the public repo", () => {
  t.hasResourceProperties("AWS::IAM::Role", {
    AssumeRolePolicyDocument: Match.objectLike({
      Statement: [Match.objectLike({ Condition: { StringEquals: { "token.actions.githubusercontent.com:aud": "sts.amazonaws.com", "token.actions.githubusercontent.com:sub": "repo:moltbot-den@263048018/openentity@1432633160:ref:refs/heads/main" } } })],
    }),
  });
});

test("the load copy never signs with the production key, has no Object Lock, no domain and no CI role, and is destroyable", () => {
  const l = Template.fromStack(new OpenEntityStack(new App({ context: { "aws:cdk:bundling-stacks": [] } }), "L", { env: { account: "099705791378", region: "us-east-1" }, load: true }));
  const json = JSON.stringify(l.toJSON());
  expect(json).toContain("openentity/load");
  expect(json).not.toMatch(/"openentity\/app"|secret:openentity\/app/);
  expect(Object.keys(l.findResources("AWS::S3::Bucket", { Properties: { ObjectLockEnabled: true } }))).toEqual([]);
  expect(Object.keys(l.findResources("AWS::CertificateManager::Certificate"))).toEqual([]);
  expect(Object.keys(l.findResources("AWS::IAM::Role", { Properties: { RoleName: "openentity-github-deploy" } }))).toEqual([]);
  l.hasResourceProperties("AWS::RDS::DBCluster", { DeletionProtection: false });
  l.hasResourceProperties("AWS::Lambda::Function", { Environment: { Variables: Match.objectLike({ WRITE_PER_MINUTE: "10000000" }) } });
});

test("production keeps 200 reserved concurrent executions and the load copy is capped at 300", () => {
  const appFn = (tpl: Template) => Object.values(tpl.findResources("AWS::Lambda::Function", { Properties: { Runtime: "nodejs22.x" } })).find((f: any) => f.Properties.Environment?.Variables?.DB_CLUSTER_ARN) as any;
  const l = Template.fromStack(new OpenEntityStack(new App({ context: { "aws:cdk:bundling-stacks": [] } }), "L", { env: { account: "099705791378", region: "us-east-1" }, load: true }));
  expect(appFn(t).Properties.ReservedConcurrentExecutions).toBe(200);
  expect(appFn(l).Properties.ReservedConcurrentExecutions).toBe(300);
});

test("the app role can read and append to the log bucket but never delete from it", () => {
  const json = JSON.stringify(t.findResources("AWS::IAM::Policy"));
  expect(json).toContain("s3:PutObject");
  expect(json).not.toMatch(/s3:DeleteObject/);
});
