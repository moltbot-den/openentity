import { fileURLToPath } from "node:url";
import {
  CfnOutput,
  Duration,
  RemovalPolicy,
  SecretValue,
  Stack,
  type StackProps,
  aws_budgets as budgets,
  aws_certificatemanager as acm,
  aws_cloudfront as cf,
  aws_cloudfront_origins as origins,
  aws_cloudwatch as cw,
  aws_cloudwatch_actions as cwActions,
  aws_ec2 as ec2,
  aws_iam as iam,
  aws_lambda as lambda,
  aws_lambda_nodejs as nodejs,
  aws_logs as logs,
  aws_rds as rds,
  aws_s3 as s3,
  aws_scheduler as scheduler,
  aws_scheduler_targets as targets,
  aws_secretsmanager as sm,
  aws_ses as ses,
  aws_ses_actions as sesActions,
  aws_sns as sns,
  aws_sns_subscriptions as subs,
} from "aws-cdk-lib";
import type { Construct } from "constructs";

export const DOMAIN = "openentity.org";
export const MCP_DOMAIN = "mcp.openentity.org";
export const HUB_DOMAIN = "oeis.dev";
export const ALERT_EMAIL = "will+aws-openentity@onefrequency.ai";
export const GITHUB_SUB = "repo:moltbot-den@263048018/openentity@1432633160:ref:refs/heads/main";
// Created out of band from the GCP Secret Manager copies (moltbot-den project): REGISTRY_KEY_JWK, CUSTODY_KEY, HASH_SALT, TURNSTILE_SECRET, ORIGIN_VERIFY, optional CIO_*.
export const APP_SECRET = "openentity/app";
export const MAIL_PREFIX = "inbound/identity/";

// What the site's pages load: their own files, the Cloudflare Web Analytics beacon, and Turnstile on the
// subscribe form. Pagefind search needs WebAssembly. No page may be framed.
// Scripts: files only. The site build moves every inline script to /_astro (site/astro.config.mjs) and a site
// test fails if one comes back. Styles keep 'unsafe-inline' for Starlight's inline style attributes.
export const CSP = [
  "default-src 'self'",
  "script-src 'self' 'wasm-unsafe-eval' https://static.cloudflareinsights.com https://challenges.cloudflare.com",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self' https://cloudflareinsights.com",
  "frame-src https://challenges.cloudflare.com",
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join("; ");

const root = (p: string) => fileURLToPath(new URL(`../../${p}`, import.meta.url));

export interface OpenEntityProps extends StackProps {
  /** A throwaway copy for the load test: no domain, no Object Lock, no CI role or alarms, its own signing key, destroyable. */
  load?: boolean;
}

export class OpenEntityStack extends Stack {
  constructor(scope: Construct, id: string, props: OpenEntityProps) {
    super(scope, id, props);
    const load = !!props.load;
    // The load stack signs with a throwaway key, so no second log ever carries the production registry key.
    const secretName = load ? "openentity/load" : APP_SECRET;
    const appSecret = sm.Secret.fromSecretNameV2(this, "AppSecret", secretName);

    // ---- Data: Aurora Serverless v2 Postgres, reached only through the Data API (no VPC on the Lambda) ----
    const vpc = new ec2.Vpc(this, "Vpc", {
      maxAzs: 2,
      natGateways: 0,
      subnetConfiguration: [{ name: "db", subnetType: ec2.SubnetType.PRIVATE_ISOLATED }],
    });
    const db = new rds.DatabaseCluster(this, "Db", {
      engine: rds.DatabaseClusterEngine.auroraPostgres({ version: rds.AuroraPostgresEngineVersion.VER_16_13 }),
      // The load copy records per-statement waits (Performance Insights, free 7-day tier) for throughput work.
      writer: rds.ClusterInstance.serverlessV2("writer", load ? { enablePerformanceInsights: true } : {}),
      serverlessV2MinCapacity: 0.5,
      // 4 ACU (2 vCPU) pegged at 100% CPU under 100 adopts/s (p95 4 s, 66 rejected); 8 ACU peaks near 6 and holds p95 under 500 ms. Idle cost is unchanged (min 0.5).
      serverlessV2MaxCapacity: Number(this.node.tryGetContext("maxAcu") ?? 8), // -c maxAcu=N lets the load stack try a lower ceiling before production follows
      enableDataApi: true,
      defaultDatabaseName: "openentity",
      vpc,
      vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_ISOLATED },
      storageEncrypted: true,
      backup: { retention: Duration.days(load ? 1 : 14) },
      deletionProtection: !load,
      removalPolicy: load ? RemovalPolicy.DESTROY : RemovalPolicy.RETAIN,
    });

    // ---- Log: tlog-tiles files and checkpoints; daily snapshots under Object Lock (PRD 7.4) ----
    const logBucket = new s3.Bucket(this, "LogBucket", {
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.S3_MANAGED,
      enforceSSL: true,
      versioned: true,
      removalPolicy: load ? RemovalPolicy.DESTROY : RemovalPolicy.RETAIN,
      autoDeleteObjects: load,
    });
    const snapshotBucket = load ? undefined : new s3.Bucket(this, "SnapshotBucket", {
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.S3_MANAGED,
      enforceSSL: true,
      versioned: true,
      objectLockEnabled: true,
      objectLockDefaultRetention: s3.ObjectLockRetention.compliance(Duration.days(365)),
      removalPolicy: RemovalPolicy.RETAIN,
    });

    // ---- App: one Lambda serves /v1 (registry) and the site, and runs the per-minute cron ----
    const fn = new nodejs.NodejsFunction(this, "AppFn", {
      entry: root("infra/lambda/handler.ts"),
      handler: "handler",
      depsLockFilePath: root("pnpm-lock.yaml"),
      runtime: lambda.Runtime.NODEJS_22_X,
      architecture: lambda.Architecture.ARM_64,
      memorySize: 1024,
      timeout: Duration.seconds(30),
      // Both copies share the account's 1000 concurrent executions: production keeps 200 guaranteed, the load copy is
      // capped at 300 so a run can never starve openentity.org, and 500 stay unreserved.
      reservedConcurrentExecutions: load ? 300 : 200,
      logGroup: new logs.LogGroup(this, "AppFnLogs", { retention: logs.RetentionDays.THREE_MONTHS }),
      bundling: {
        format: nodejs.OutputFormat.ESM,
        minify: true,
        sourceMap: true,
        target: "node22",
        externalModules: ["@electric-sql/pglite"], // test-only, dynamically imported
        mainFields: ["module", "main"],
        banner: "import{createRequire}from'module';const require=createRequire(import.meta.url);",
        // The built sites ship inside the bundle; the handler serves openentity.org from ./dist and oeis.dev from ./dist-dev.
        commandHooks: {
          beforeBundling: () => [],
          beforeInstall: () => [],
          afterBundling: (_in: string, out: string) => [`cp -R ${root("site/dist")} ${out}/dist`, `cp -R ${root("site-dev/dist")} ${out}/dist-dev`],
        },
      },
      environment: {
        APP_SECRET_ARN: appSecret.secretArn,
        DB_CLUSTER_ARN: db.clusterArn,
        DB_SECRET_ARN: db.secret!.secretArn,
        DB_NAME: "openentity",
        LOG_BUCKET: logBucket.bucketName,
        ...(snapshotBucket ? { SNAPSHOT_BUCKET: snapshotBucket.bucketName } : {}),
        ...(load ? { IP_DAILY_LIMIT: "10000000", WRITE_PER_MINUTE: "10000000", LOAD_TIMING: "1" } : {}),
        REGISTRY_HOST: DOMAIN,
        // The load copy measures registry throughput; minting 6,000 stamps at 20 bits outlives their 10-minute window.
        STAMP_BITS: load ? "12" : "20",
        BASE_RPC_URL: "https://mainnet.base.org",
        TURNSTILE_SITE_KEY: "0x4AAAAAAFkggsScyaPIMp2v",
        CF_ANALYTICS_TOKEN: "1c8d90533d834474833d04a8b62d5117",
        SUBSCRIBE_ENABLED: "true",
        NODE_OPTIONS: "--enable-source-maps",
      },
    });
    appSecret.grantRead(fn);
    db.grantDataApiAccess(fn);
    // Read and put only: the log is append-only, so the app never needs to delete or overwrite history it cannot rebuild.
    logBucket.grantRead(fn);
    logBucket.grantPut(fn);
    snapshotBucket?.grantRead(fn);
    snapshotBucket?.grantPut(fn);
    const url = fn.addFunctionUrl({ authType: lambda.FunctionUrlAuthType.NONE });

    new scheduler.Schedule(this, "Cron", {
      schedule: scheduler.ScheduleExpression.rate(Duration.minutes(1)),
      target: new targets.LambdaInvoke(fn, {
        input: scheduler.ScheduleTargetInput.fromObject({ source: "openentity.cron", time: scheduler.ContextAttribute.scheduledTime }),
        retryAttempts: 0,
      }),
    });

    // ---- Edge: CloudFront at openentity.org; every request goes to the Lambda URL ----
    const cert = load ? undefined : new acm.Certificate(this, "Cert", {
      domainName: DOMAIN,
      validation: acm.CertificateValidation.fromDns(),
    });
    const origin = new origins.FunctionUrlOrigin(url, {
      // The Lambda rejects requests without this header, so the function URL is not a bypass around CloudFront.
      customHeaders: { "x-origin-verify": SecretValue.secretsManager(secretName, { jsonField: "ORIGIN_VERIFY" }).unsafeUnwrap() },
    });
    const forward = new cf.OriginRequestPolicy(this, "Forward", {
      headerBehavior: cf.OriginRequestHeaderBehavior.allowList(
        "Accept", "Content-Type", "User-Agent", "X-OE-Stamp", "Origin", "Referer", "If-None-Match",
        "CloudFront-Viewer-Address", "CloudFront-Viewer-Country",
      ),
      queryStringBehavior: cf.OriginRequestQueryStringBehavior.all(),
      cookieBehavior: cf.OriginRequestCookieBehavior.none(),
    });
    const headers = new cf.ResponseHeadersPolicy(this, "SecurityHeaders", {
      securityHeadersBehavior: {
        strictTransportSecurity: { accessControlMaxAge: Duration.days(365), includeSubdomains: true, override: false },
        contentTypeOptions: { override: true },
        referrerPolicy: { referrerPolicy: cf.HeadersReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN, override: false },
        frameOptions: { frameOption: cf.HeadersFrameOption.DENY, override: true },
        contentSecurityPolicy: { contentSecurityPolicy: CSP, override: true },
      },
    });
    const dynamic = {
      origin,
      viewerProtocolPolicy: cf.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
      allowedMethods: cf.AllowedMethods.ALLOW_ALL,
      cachePolicy: cf.CachePolicy.CACHING_DISABLED,
      originRequestPolicy: forward,
      responseHeadersPolicy: headers,
    };
    // Hashed build assets never change, so the edge keeps them.
    const immutable = { ...dynamic, allowedMethods: cf.AllowedMethods.ALLOW_GET_HEAD, cachePolicy: cf.CachePolicy.CACHING_OPTIMIZED };
    const dist = new cf.Distribution(this, "Dist", {
      ...(cert ? { domainNames: [DOMAIN], certificate: cert } : {}),
      minimumProtocolVersion: cf.SecurityPolicyProtocol.TLS_V1_2_2021,
      httpVersion: cf.HttpVersion.HTTP2_AND_3,
      defaultBehavior: dynamic,
      additionalBehaviors: { "/_astro/*": immutable, "/pagefind/*": immutable },
    });

    const out = (k: string, v: string) => new CfnOutput(this, k, { value: v });
    out("DistributionDomain", dist.distributionDomainName);
    out("FunctionName", fn.functionName);
    out("DbClusterArn", db.clusterArn);
    out("DbSecretArn", db.secret!.secretArn);
    out("LogBucketName", logBucket.bucketName);
    if (load) return; // the load copy stops here: no MCP domain, CI role, alarms or budget

    // ---- MCP edge: mcp.openentity.org is a second distribution on the same Lambda ----
    // CloudFront cannot forward the viewer Host to a function URL, so this origin adds x-oe-site and the handler routes on it.
    // Its own certificate keeps the openentity.org certificate untouched.
    const mcpCert = new acm.Certificate(this, "McpCert", {
      domainName: MCP_DOMAIN,
      validation: acm.CertificateValidation.fromDns(),
    });
    const mcpOrigin = new origins.FunctionUrlOrigin(url, {
      customHeaders: {
        "x-origin-verify": SecretValue.secretsManager(secretName, { jsonField: "ORIGIN_VERIFY" }).unsafeUnwrap(),
        "x-oe-site": "mcp",
      },
    });
    const mcpForward = new cf.OriginRequestPolicy(this, "McpForward", {
      headerBehavior: cf.OriginRequestHeaderBehavior.allowList(
        "Accept", "Content-Type", "User-Agent", "Mcp-Session-Id", "Mcp-Protocol-Version", "Last-Event-ID",
        "CloudFront-Viewer-Address", "CloudFront-Viewer-Country",
      ),
      queryStringBehavior: cf.OriginRequestQueryStringBehavior.all(),
      cookieBehavior: cf.OriginRequestCookieBehavior.none(),
    });
    const mcpDist = new cf.Distribution(this, "McpDist", {
      domainNames: [MCP_DOMAIN],
      certificate: mcpCert,
      minimumProtocolVersion: cf.SecurityPolicyProtocol.TLS_V1_2_2021,
      httpVersion: cf.HttpVersion.HTTP2_AND_3,
      defaultBehavior: { ...dynamic, origin: mcpOrigin, originRequestPolicy: mcpForward },
    });

    // ---- Developer hub: oeis.dev is a third distribution on the same Lambda, tagged x-oe-site: dev ----
    // Static pages only (site-dev/dist); the hub has no API of its own, so it shares the site's cache and header policies.
    const hubCert = new acm.Certificate(this, "HubCert", {
      domainName: HUB_DOMAIN,
      validation: acm.CertificateValidation.fromDns(),
    });
    const hubOrigin = new origins.FunctionUrlOrigin(url, {
      customHeaders: {
        "x-origin-verify": SecretValue.secretsManager(secretName, { jsonField: "ORIGIN_VERIFY" }).unsafeUnwrap(),
        "x-oe-site": "dev",
      },
    });
    const hubDist = new cf.Distribution(this, "HubDist", {
      domainNames: [HUB_DOMAIN],
      certificate: hubCert,
      minimumProtocolVersion: cf.SecurityPolicyProtocol.TLS_V1_2_2021,
      httpVersion: cf.HttpVersion.HTTP2_AND_3,
      defaultBehavior: { ...dynamic, origin: hubOrigin, allowedMethods: cf.AllowedMethods.ALLOW_GET_HEAD },
      additionalBehaviors: { "/_astro/*": { ...immutable, origin: hubOrigin }, "/pagefind/*": { ...immutable, origin: hubOrigin } },
    });

    // ---- Mail: every openentity.org address (identity@ is the published one) lands in S3 and is forwarded to OPERATOR_EMAIL in the app secret ----
    // SES allows one active rule set per region; activate it once after deploy (docs/MAILBOX.md). The DKIM CNAMEs
    // and the apex MX live in Cloudflare DNS.
    const mailIdentity = new ses.EmailIdentity(this, "MailIdentity", { identity: ses.Identity.domain(DOMAIN) });
    const mailBucket = new s3.Bucket(this, "MailBucket", {
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.S3_MANAGED,
      enforceSSL: true,
      removalPolicy: RemovalPolicy.RETAIN,
    });
    const forwardFn = new nodejs.NodejsFunction(this, "ForwardFn", {
      entry: root("infra/lambda/forward.ts"),
      handler: "handler",
      depsLockFilePath: root("pnpm-lock.yaml"),
      runtime: lambda.Runtime.NODEJS_22_X,
      architecture: lambda.Architecture.ARM_64,
      timeout: Duration.seconds(30),
      logGroup: new logs.LogGroup(this, "ForwardFnLogs", { retention: logs.RetentionDays.THREE_MONTHS }),
      bundling: { format: nodejs.OutputFormat.ESM, minify: true, target: "node22" },
      environment: { APP_SECRET_ARN: appSecret.secretArn, MAIL_BUCKET: mailBucket.bucketName, MAIL_PREFIX: MAIL_PREFIX },
    });
    appSecret.grantRead(forwardFn);
    mailBucket.grantRead(forwardFn, `${MAIL_PREFIX}*`);
    forwardFn.addToRolePolicy(new iam.PolicyStatement({
      actions: ["ses:SendEmail", "ses:SendRawEmail"],
      resources: [mailIdentity.emailIdentityArn, `arn:aws:ses:${this.region}:${this.account}:identity/*`],
    }));
    new ses.ReceiptRuleSet(this, "MailRules", {
      receiptRuleSetName: "openentity-inbound",
      rules: [{
        recipients: [DOMAIN], // catch-all: the apex MX moved off Google Workspace, so no address may bounce
        scanEnabled: true,
        actions: [
          new sesActions.S3({ bucket: mailBucket, objectKeyPrefix: MAIL_PREFIX }),
          new sesActions.Lambda({ function: forwardFn, invocationType: sesActions.LambdaInvocationType.EVENT }),
        ],
      }],
    });
    out("MailBucketName", mailBucket.bucketName);
    [1, 2, 3].forEach((i) => {
      const n = mailIdentity[`dkimDnsTokenName${i}` as "dkimDnsTokenName1"];
      const v = mailIdentity[`dkimDnsTokenValue${i}` as "dkimDnsTokenValue1"];
      out(`MailDkim${i}`, `${n} ${v}`);
    });

    // ---- CI: GitHub Actions deploys from main through OIDC ----
    const gh = new iam.OpenIdConnectProvider(this, "GitHubOidc", {
      url: "https://token.actions.githubusercontent.com",
      clientIds: ["sts.amazonaws.com"],
    });
    const deployRole = new iam.Role(this, "DeployRole", {
      roleName: "openentity-github-deploy",
      assumedBy: new iam.WebIdentityPrincipal(gh.openIdConnectProviderArn, {
        // The repo uses GitHub's immutable subject (owner and repo carry their numeric ids).
        StringEquals: { "token.actions.githubusercontent.com:aud": "sts.amazonaws.com", "token.actions.githubusercontent.com:sub": GITHUB_SUB },
      }),
      maxSessionDuration: Duration.hours(1),
    });
    // cdk deploy runs through the bootstrap roles; the Data API grant lets CI apply schema.sql.
    deployRole.addToPolicy(new iam.PolicyStatement({ actions: ["sts:AssumeRole"], resources: [`arn:aws:iam::${this.account}:role/cdk-*`] }));
    deployRole.addToPolicy(new iam.PolicyStatement({ actions: ["cloudformation:DescribeStacks"], resources: [this.stackId] }));
    db.grantDataApiAccess(deployRole);

    // ---- Alarms and cost guard ----
    const alerts = new sns.Topic(this, "Alerts");
    alerts.addSubscription(new subs.EmailSubscription(ALERT_EMAIL));
    const alarm = (id: string, metric: cw.IMetric) =>
      new cw.Alarm(this, id, {
        metric,
        threshold: 5,
        evaluationPeriods: 1,
        comparisonOperator: cw.ComparisonOperator.GREATER_THAN_THRESHOLD,
        treatMissingData: cw.TreatMissingData.NOT_BREACHING,
      }).addAlarmAction(new cwActions.SnsAction(alerts));
    alarm("AppErrors", fn.metricErrors({ period: Duration.minutes(5), statistic: "Sum" }));
    alarm("AppThrottles", fn.metricThrottles({ period: Duration.minutes(5), statistic: "Sum" }));
    // The cron is rate(1 minute) with no retries and its Errors share the app's metric, so a cron that fails every run can stay under
    // the alarms above. scheduled() emits ScheduledOk after a fully successful run (every 10 minutes); three silent 10-minute periods,
    // whether from a crash, a failed step, a stale checkpoint or a missing snapshot, raise this alarm.
    new cw.Alarm(this, "CronStalled", {
      metric: new cw.Metric({ namespace: "OpenEntity", metricName: "ScheduledOk", statistic: "Sum", period: Duration.minutes(10) }),
      threshold: 1,
      evaluationPeriods: 3,
      comparisonOperator: cw.ComparisonOperator.LESS_THAN_THRESHOLD,
      treatMissingData: cw.TreatMissingData.BREACHING,
    }).addAlarmAction(new cwActions.SnsAction(alerts));
    new budgets.CfnBudget(this, "Budget", {
      budget: { budgetName: "openentity-monthly", budgetType: "COST", timeUnit: "MONTHLY", budgetLimit: { amount: 150, unit: "USD" } },
      notificationsWithSubscribers: [
        {
          notification: { notificationType: "ACTUAL", comparisonOperator: "GREATER_THAN", threshold: 80, thresholdType: "PERCENTAGE" },
          subscribers: [{ subscriptionType: "EMAIL", address: ALERT_EMAIL }],
        },
      ],
    });

    // ---- Outputs (scripts/cloudflare-dns.ts and the deploy workflow read these) ----
    out("DistributionId", dist.distributionId);
    out("McpDistributionDomain", mcpDist.distributionDomainName);
    out("McpDistributionId", mcpDist.distributionId);
    out("HubDistributionDomain", hubDist.distributionDomainName);
    out("SnapshotBucketName", snapshotBucket!.bucketName);
    out("DeployRoleArn", deployRole.roleArn);
  }
}
