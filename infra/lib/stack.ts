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
  aws_sns as sns,
  aws_sns_subscriptions as subs,
} from "aws-cdk-lib";
import type { Construct } from "constructs";

export const DOMAIN = "openentity.org";
export const ALERT_EMAIL = "will+aws-openentity@onefrequency.ai";
export const GITHUB_SUB = "repo:moltbot-den@263048018/openentity@1432633160:ref:refs/heads/main";
// Created out of band from the GCP Secret Manager copies (moltbot-den project): REGISTRY_KEY_JWK, CUSTODY_KEY, HASH_SALT, TURNSTILE_SECRET, ORIGIN_VERIFY, optional CIO_*.
export const APP_SECRET = "openentity/app";

const root = (p: string) => fileURLToPath(new URL(`../../${p}`, import.meta.url));

export class OpenEntityStack extends Stack {
  constructor(scope: Construct, id: string, props: StackProps) {
    super(scope, id, props);
    const appSecret = sm.Secret.fromSecretNameV2(this, "AppSecret", APP_SECRET);

    // ---- Data: Aurora Serverless v2 Postgres, reached only through the Data API (no VPC on the Lambda) ----
    const vpc = new ec2.Vpc(this, "Vpc", {
      maxAzs: 2,
      natGateways: 0,
      subnetConfiguration: [{ name: "db", subnetType: ec2.SubnetType.PRIVATE_ISOLATED }],
    });
    const db = new rds.DatabaseCluster(this, "Db", {
      engine: rds.DatabaseClusterEngine.auroraPostgres({ version: rds.AuroraPostgresEngineVersion.VER_16_13 }),
      writer: rds.ClusterInstance.serverlessV2("writer"),
      serverlessV2MinCapacity: 0.5,
      serverlessV2MaxCapacity: 4,
      enableDataApi: true,
      defaultDatabaseName: "openentity",
      vpc,
      vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_ISOLATED },
      storageEncrypted: true,
      backup: { retention: Duration.days(14) },
      deletionProtection: true,
      removalPolicy: RemovalPolicy.RETAIN,
    });

    // ---- Log: tlog-tiles files and checkpoints; daily snapshots under Object Lock (PRD 7.4) ----
    const logBucket = new s3.Bucket(this, "LogBucket", {
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.S3_MANAGED,
      enforceSSL: true,
      versioned: true,
      removalPolicy: RemovalPolicy.RETAIN,
    });
    const snapshotBucket = new s3.Bucket(this, "SnapshotBucket", {
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
      logGroup: new logs.LogGroup(this, "AppFnLogs", { retention: logs.RetentionDays.THREE_MONTHS }),
      bundling: {
        format: nodejs.OutputFormat.ESM,
        minify: true,
        sourceMap: true,
        target: "node22",
        externalModules: ["@electric-sql/pglite"], // test-only, dynamically imported
        mainFields: ["module", "main"],
        banner: "import{createRequire}from'module';const require=createRequire(import.meta.url);",
        // The built site (about 2 MB) ships inside the bundle; the handler serves it from ./dist.
        commandHooks: {
          beforeBundling: () => [],
          beforeInstall: () => [],
          afterBundling: (_in: string, out: string) => [`cp -R ${root("site/dist")} ${out}/dist`],
        },
      },
      environment: {
        APP_SECRET_ARN: appSecret.secretArn,
        DB_CLUSTER_ARN: db.clusterArn,
        DB_SECRET_ARN: db.secret!.secretArn,
        DB_NAME: "openentity",
        LOG_BUCKET: logBucket.bucketName,
        SNAPSHOT_BUCKET: snapshotBucket.bucketName,
        REGISTRY_HOST: DOMAIN,
        STAMP_BITS: "20",
        BASE_RPC_URL: "https://mainnet.base.org",
        TURNSTILE_SITE_KEY: "0x4AAAAAAFkggsScyaPIMp2v",
        CF_ANALYTICS_TOKEN: "1c8d90533d834474833d04a8b62d5117",
        SUBSCRIBE_ENABLED: "false",
        NODE_OPTIONS: "--enable-source-maps",
      },
    });
    appSecret.grantRead(fn);
    db.grantDataApiAccess(fn);
    logBucket.grantReadWrite(fn);
    snapshotBucket.grantReadWrite(fn);
    const url = fn.addFunctionUrl({ authType: lambda.FunctionUrlAuthType.NONE });

    new scheduler.Schedule(this, "Cron", {
      schedule: scheduler.ScheduleExpression.rate(Duration.minutes(1)),
      target: new targets.LambdaInvoke(fn, {
        input: scheduler.ScheduleTargetInput.fromObject({ source: "openentity.cron", time: scheduler.ContextAttribute.scheduledTime }),
        retryAttempts: 0,
      }),
    });

    // ---- Edge: CloudFront at openentity.org; every request goes to the Lambda URL ----
    const cert = new acm.Certificate(this, "Cert", {
      domainName: DOMAIN,
      validation: acm.CertificateValidation.fromDns(),
    });
    const origin = new origins.FunctionUrlOrigin(url, {
      // The Lambda rejects requests without this header, so the function URL is not a bypass around CloudFront.
      customHeaders: { "x-origin-verify": SecretValue.secretsManager(APP_SECRET, { jsonField: "ORIGIN_VERIFY" }).unsafeUnwrap() },
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
      domainNames: [DOMAIN],
      certificate: cert,
      minimumProtocolVersion: cf.SecurityPolicyProtocol.TLS_V1_2_2021,
      httpVersion: cf.HttpVersion.HTTP2_AND_3,
      defaultBehavior: dynamic,
      additionalBehaviors: { "/_astro/*": immutable, "/pagefind/*": immutable },
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
    const out = (k: string, v: string) => new CfnOutput(this, k, { value: v });
    out("DistributionDomain", dist.distributionDomainName);
    out("DistributionId", dist.distributionId);
    out("FunctionName", fn.functionName);
    out("DbClusterArn", db.clusterArn);
    out("DbSecretArn", db.secret!.secretArn);
    out("LogBucketName", logBucket.bucketName);
    out("SnapshotBucketName", snapshotBucket.bucketName);
    out("DeployRoleArn", deployRole.roleArn);
  }
}
