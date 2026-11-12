// OpenEntity Account (ADR 0007, PLAN section 4): its own Lambda and role, Aurora through the Data API, KMS keys,
// CloudFront at account.openentity.org, the agent WebSocket at agents.account.openentity.org, the events queue.
// Nothing here is shared with the registry stack: the registry never depends on the account service.
import { fileURLToPath } from "node:url";
import {
  CfnOutput,
  Duration,
  RemovalPolicy,
  Stack,
  type StackProps,
  aws_apigatewayv2 as apigw,
  aws_apigatewayv2_integrations as integrations,
  aws_certificatemanager as acm,
  aws_cloudfront as cf,
  aws_cloudfront_origins as origins,
  aws_ec2 as ec2,
  aws_iam as iam,
  aws_kms as kms,
  aws_lambda as lambda,
  aws_lambda_nodejs as nodejs,
  aws_logs as logs,
  aws_rds as rds,
  aws_sqs as sqs,
  aws_ssm as ssm,
} from "aws-cdk-lib";
import type { Construct } from "constructs";

export type AccountStage = "staging" | "production";
export const ACCOUNT_HOST: Record<AccountStage, string> = { production: "account.openentity.org", staging: "staging.account.openentity.org" };
export const AGENTS_HOST: Record<AccountStage, string> = { production: "agents.account.openentity.org", staging: "agents.staging.account.openentity.org" };
/** SSM parameters: /openentity/account/<name> (both stages) and <name>_prod or <name>_staging (one stage). */
export const PARAM_PATH = "/openentity/account/";
export const SUFFIX: Record<AccountStage, string> = { production: "prod", staging: "staging" };
// aws/ssm, the managed key behind SecureString: the role may decrypt with it only through SSM.
const SSM_KEY_ARN = "arn:aws:kms:us-east-1:099705791378:key/6076f65d-76f2-424d-8375-e74257cd5d07";
const DEPLOY_ROLE = "openentity-github-deploy"; // created by the OpenEntity stack

// API responses are JSON; pages set their own CSP (the origin's header wins, override: false).
export const ACCOUNT_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";

const root = (p: string) => fileURLToPath(new URL(`../../${p}`, import.meta.url));

export interface AccountProps extends StackProps { stage: AccountStage }

export class OpenEntityAccountStack extends Stack {
  constructor(scope: Construct, id: string, props: AccountProps) {
    super(scope, id, props);
    const { stage } = props;
    const prod = stage === "production";
    const host = ACCOUNT_HOST[stage], wsHost = AGENTS_HOST[stage], suffix = SUFFIX[stage];
    const other = SUFFIX[prod ? "staging" : "production"];
    const keep = prod ? RemovalPolicy.RETAIN : RemovalPolicy.DESTROY;

    // ---- Data: Aurora Serverless v2 PostgreSQL, reached only through the Data API (no VPC on the Lambda, no NAT) ----
    // Production: a writer and a reader in a second Availability Zone, 0.5 ACU minimum each. Staging: one writer that
    // pauses after 5 idle minutes (0 ACU; a Data API call resumes it in about 15 s).
    const vpc = new ec2.Vpc(this, "Vpc", { maxAzs: 2, natGateways: 0, subnetConfiguration: [{ name: "db", subnetType: ec2.SubnetType.PRIVATE_ISOLATED }] });
    const [az1, az2] = vpc.availabilityZones;
    const db = new rds.DatabaseCluster(this, "Db", {
      engine: rds.DatabaseClusterEngine.auroraPostgres({ version: rds.AuroraPostgresEngineVersion.VER_16_13 }),
      writer: rds.ClusterInstance.serverlessV2("writer", { availabilityZone: az1 }),
      readers: prod ? [rds.ClusterInstance.serverlessV2("reader", { availabilityZone: az2, scaleWithWriter: true })] : [],
      serverlessV2MinCapacity: prod ? 0.5 : 0,
      serverlessV2MaxCapacity: prod ? 4 : 2,
      ...(prod ? {} : { serverlessV2AutoPauseDuration: Duration.minutes(5) }),
      enableDataApi: true,
      defaultDatabaseName: "account",
      vpc,
      vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_ISOLATED },
      storageEncrypted: true,
      backup: { retention: Duration.days(prod ? 14 : 1) },
      deletionProtection: prod,
      removalPolicy: prod ? RemovalPolicy.RETAIN : RemovalPolicy.SNAPSHOT,
    });

    // ---- Keys: the private halves never leave KMS ----
    const tokenKey = new kms.Key(this, "TokenKey", {
      keySpec: kms.KeySpec.ECC_NIST_P256, keyUsage: kms.KeyUsage.SIGN_VERIFY, removalPolicy: keep,
      alias: `alias/openentity-account-${suffix}-token`, description: `OpenEntity Account ${stage}: ES256 access tokens (jwks.json)`,
    });
    const didKey = new kms.Key(this, "DidKey", {
      keySpec: kms.KeySpec.ECC_NIST_EDWARDS25519, keyUsage: kms.KeyUsage.SIGN_VERIFY, removalPolicy: keep,
      alias: `alias/openentity-account-${suffix}-did`, description: `OpenEntity Account ${stage}: Ed25519 RFC 9421 signatures to products (did.json)`,
    });
    // Signs key log `close` entries (test-vectors/keylog-1: p256 form). Never deleted: a closed log must verify forever, so
    // this key and every retired close key stay in did.json. RETAIN in both stages, and nobody may schedule its deletion.
    const closeKey = new kms.Key(this, "CloseKey", {
      keySpec: kms.KeySpec.ECC_NIST_P256, keyUsage: kms.KeyUsage.SIGN_VERIFY, removalPolicy: RemovalPolicy.RETAIN,
      alias: `alias/openentity-account-${suffix}-close`, description: `OpenEntity Account ${stage}: signs key log close entries; never delete`,
    });
    closeKey.addToResourcePolicy(new iam.PolicyStatement({
      effect: iam.Effect.DENY, principals: [new iam.AnyPrincipal()], actions: ["kms:ScheduleKeyDeletion", "kms:DisableKey"], resources: ["*"],
    }));
    // One symmetric key for data the service encrypts itself (Apple refresh tokens and the like). Each use names its
    // purpose in the encryption context (account/src/seal.ts), so a value sealed for one purpose never opens as another.
    const dataKey = new kms.Key(this, "DataKey", {
      enableKeyRotation: true, removalPolicy: keep,
      alias: `alias/openentity-account-${suffix}-data`, description: `OpenEntity Account ${stage}: data encryption`,
    });

    // ---- Events: app and product analytics events, validated by the API, forwarded by the Monitoring lane's consumer ----
    const deadEvents = new sqs.Queue(this, "EventsDlq", { retentionPeriod: Duration.days(14), encryption: sqs.QueueEncryption.SQS_MANAGED, enforceSSL: true });
    const events = new sqs.Queue(this, "Events", {
      visibilityTimeout: Duration.minutes(2), retentionPeriod: Duration.days(4), encryption: sqs.QueueEncryption.SQS_MANAGED, enforceSSL: true,
      deadLetterQueue: { queue: deadEvents, maxReceiveCount: 5 },
    });

    // ---- App: one function serves HTTP (through CloudFront) and the WebSocket routes ----
    const originVerify = ssm.StringParameter.valueForStringParameter(this, `${PARAM_PATH}origin_verify_${suffix}`);
    const fn = new nodejs.NodejsFunction(this, "AppFn", {
      entry: root("account/src/lambda.ts"),
      handler: "handler",
      depsLockFilePath: root("pnpm-lock.yaml"),
      runtime: lambda.Runtime.NODEJS_22_X,
      architecture: lambda.Architecture.ARM_64,
      memorySize: 1024,
      timeout: Duration.seconds(30),
      logGroup: new logs.LogGroup(this, "AppFnLogs", { retention: logs.RetentionDays.THREE_MONTHS, removalPolicy: keep }),
      bundling: {
        format: nodejs.OutputFormat.ESM,
        minify: true,
        sourceMap: true,
        target: "node22",
        mainFields: ["module", "main"],
        externalModules: ["@electric-sql/pglite"], // tests only
        banner: "import{createRequire}from'module';const require=createRequire(import.meta.url);",
      },
      environment: {
        STAGE: stage,
        HOST: host,
        WS_HOST: wsHost,
        ORIGIN_VERIFY: originVerify,
        PARAM_PATH,
        PARAM_SUFFIX: suffix,
        DB_CLUSTER_ARN: db.clusterArn,
        DB_SECRET_ARN: db.secret!.secretArn,
        DB_NAME: "account",
        TOKEN_KEY_ID: tokenKey.keyArn,
        DID_KEY_ID: didKey.keyArn,
        CLOSE_KEY_ID: closeKey.keyArn,
        DATA_KEY_ID: dataKey.keyArn,
        EVENTS_QUEUE_URL: events.queueUrl,
        // Production sign-in stays closed until device binding and the Day 6 review gate (PLAN 3.6); staging is open.
        SIGNIN_OPEN: prod ? "0" : "1",
        NODE_OPTIONS: "--enable-source-maps",
      },
    });
    db.grantDataApiAccess(fn);
    tokenKey.grant(fn, "kms:Sign", "kms:GetPublicKey");
    didKey.grant(fn, "kms:Sign", "kms:GetPublicKey");
    closeKey.grant(fn, "kms:Sign", "kms:GetPublicKey");
    dataKey.grant(fn, "kms:Encrypt", "kms:Decrypt");
    events.grantSendMessages(fn);
    // Its own parameters only: never /openentity/app (the registry's keys), never the other stage's values.
    fn.addToRolePolicy(new iam.PolicyStatement({ actions: ["ssm:GetParameters"], resources: [`arn:aws:ssm:${this.region}:${this.account}:parameter${PARAM_PATH}*`] }));
    fn.addToRolePolicy(new iam.PolicyStatement({ effect: iam.Effect.DENY, actions: ["ssm:GetParameter*"], resources: [`arn:aws:ssm:${this.region}:${this.account}:parameter${PARAM_PATH}*_${other}`] }));
    fn.addToRolePolicy(new iam.PolicyStatement({
      actions: ["kms:Decrypt"], resources: [SSM_KEY_ARN], conditions: { StringEquals: { "kms:ViaService": `ssm.${this.region}.amazonaws.com` } },
    }));
    const url = fn.addFunctionUrl({ authType: lambda.FunctionUrlAuthType.NONE });

    // ---- Edge: CloudFront at the account host; every request goes to the function URL ----
    const cert = new acm.Certificate(this, "Cert", { domainName: host, validation: acm.CertificateValidation.fromDns() });
    const headers = new cf.ResponseHeadersPolicy(this, "SecurityHeaders", {
      securityHeadersBehavior: {
        strictTransportSecurity: { accessControlMaxAge: Duration.days(365), includeSubdomains: true, override: false },
        contentTypeOptions: { override: true },
        referrerPolicy: { referrerPolicy: cf.HeadersReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN, override: false },
        frameOptions: { frameOption: cf.HeadersFrameOption.DENY, override: true },
        contentSecurityPolicy: { contentSecurityPolicy: ACCOUNT_CSP, override: false },
      },
    });
    const dist = new cf.Distribution(this, "Dist", {
      domainNames: [host],
      certificate: cert,
      minimumProtocolVersion: cf.SecurityPolicyProtocol.TLS_V1_2_2021,
      httpVersion: cf.HttpVersion.HTTP2_AND_3,
      defaultBehavior: {
        // The function rejects requests without this header, so the function URL is not a way around CloudFront.
        origin: new origins.FunctionUrlOrigin(url, { customHeaders: { "x-origin-verify": originVerify } }),
        viewerProtocolPolicy: cf.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
        allowedMethods: cf.AllowedMethods.ALLOW_ALL,
        cachePolicy: cf.CachePolicy.CACHING_DISABLED,
        // Every viewer header but Host (Authorization, cookies, the RFC 9421 headers, Apple's form posts): what a function URL needs.
        originRequestPolicy: cf.OriginRequestPolicy.ALL_VIEWER_EXCEPT_HOST_HEADER,
        responseHeadersPolicy: headers,
      },
    });

    // ---- Agent channel: API Gateway WebSocket at wss://<agents host>/ ----
    const connect = (name: string) => new integrations.WebSocketLambdaIntegration(`Ws${name}`, fn); // never the id "Default": CDK drops it from logical ids
    const ws = new apigw.WebSocketApi(this, "AgentsWs", {
      apiName: `openentity-account-agents-${suffix}`,
      routeSelectionExpression: "$request.body.action",
      connectRouteOptions: { integration: connect("Connect") },
      disconnectRouteOptions: { integration: connect("Disconnect") },
      defaultRouteOptions: { integration: connect("Default") },
    });
    ws.addRoute("sync", { integration: connect("Sync") });
    ws.addRoute("ack", { integration: connect("Ack") });
    // Heartbeats keep a socket under the 10-minute idle timeout. A MOCK route answers them, so they cost no Lambda time.
    const beat = new apigw.CfnIntegration(this, "HeartbeatIntegration", {
      apiId: ws.apiId, integrationType: "MOCK", requestTemplates: { $default: '{"statusCode": 200}' }, templateSelectionExpression: "\\$default",
    });
    new apigw.CfnIntegrationResponse(this, "HeartbeatIntegrationResponse", {
      apiId: ws.apiId, integrationId: beat.ref, integrationResponseKey: "$default", responseTemplates: { $default: '{"type":"heartbeat"}' }, templateSelectionExpression: "\\$default",
    });
    const beatRoute = new apigw.CfnRoute(this, "HeartbeatRoute", { apiId: ws.apiId, routeKey: "heartbeat", target: `integrations/${beat.ref}`, routeResponseSelectionExpression: "$default" });
    new apigw.CfnRouteResponse(this, "HeartbeatRouteResponse", { apiId: ws.apiId, routeId: beatRoute.ref, routeResponseKey: "$default" });
    const wsStage = new apigw.WebSocketStage(this, "AgentsStage", { webSocketApi: ws, stageName: "v1", autoDeploy: true, throttle: { rateLimit: 100, burstLimit: 200 } });
    wsStage.node.addDependency(beatRoute);
    ws.grantManageConnections(fn);
    fn.addEnvironment("WS_CALLBACK_URL", wsStage.callbackUrl);
    const wsCert = new acm.Certificate(this, "WsCert", { domainName: wsHost, validation: acm.CertificateValidation.fromDns() });
    const wsDomain = new apigw.DomainName(this, "WsDomain", { domainName: wsHost, certificate: wsCert });
    new apigw.ApiMapping(this, "WsMapping", { api: ws, domainName: wsDomain, stage: wsStage });

    // ---- CI: the deploy role applies account/schema.sql through the Data API ----
    // Each stage attaches its own inline policy to the shared role; the default name would collide between the stages.
    const deployRole = iam.Role.fromRoleName(this, "DeployRole", DEPLOY_ROLE, { defaultPolicyName: `AccountCi${suffix}` });
    db.grantDataApiAccess(deployRole);
    deployRole.addToPrincipalPolicy(new iam.PolicyStatement({ actions: ["cloudformation:DescribeStacks"], resources: [this.stackId] }));

    // ---- Outputs (infra/scripts/cloudflare-dns.ts, migrate-account.ts and the deploy workflow read these) ----
    const out = (k: string, v: string) => new CfnOutput(this, k, { value: v });
    out("DistributionDomain", dist.distributionDomainName);
    out("DistributionId", dist.distributionId);
    out("WsDomainTarget", wsDomain.regionalDomainName);
    out("FunctionName", fn.functionName);
    out("DbClusterArn", db.clusterArn);
    out("DbSecretArn", db.secret!.secretArn);
    out("TokenKeyArn", tokenKey.keyArn);
    out("DidKeyArn", didKey.keyArn);
    out("CloseKeyArn", closeKey.keyArn);
    out("DataKeyArn", dataKey.keyArn);
    out("EventsQueueUrl", events.queueUrl);
  }
}
