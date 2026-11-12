// Self-contained: the Account lane imports this into its stack.
//   new AnalyticsForwarder(this, "Analytics", { environment: "production", })
// `queue` is where the account service sends validated events (SendMessage, JSON body shaped like QueuedEvent).
import { fileURLToPath } from "node:url";
import { Duration, Stack } from "aws-cdk-lib";
import * as cloudwatch from "aws-cdk-lib/aws-cloudwatch";
import * as lambda from "aws-cdk-lib/aws-lambda";
import { SqsEventSource } from "aws-cdk-lib/aws-lambda-event-sources";
import * as nodejs from "aws-cdk-lib/aws-lambda-nodejs";
import * as iam from "aws-cdk-lib/aws-iam";
import * as sqs from "aws-cdk-lib/aws-sqs";
import { Construct } from "constructs";
import { analyticsParamNames, SSM_PREFIX } from "./params.ts";

// aws/ssm, the managed key behind SecureString (same key the app role uses).
const DEFAULT_SSM_KEY_ARN = "arn:aws:kms:us-east-1:099705791378:key/6076f65d-76f2-424d-8375-e74257cd5d07";

export type AnalyticsForwarderProps = {
  environment: "production" | "staging";
  /** ARN of the aws/ssm key. Defaults to the openentity account key. */
  ssmKeyArn?: string;
};

export class AnalyticsForwarder extends Construct {
  readonly queue: sqs.Queue;
  readonly deadLetterQueue: sqs.Queue;
  readonly fn: nodejs.NodejsFunction;
  /** Alarm: any message in the DLQ. Wire to the ops topic. */
  readonly dlqAlarm: cloudwatch.Alarm;

  constructor(scope: Construct, id: string, props: AnalyticsForwarderProps) {
    super(scope, id);
    this.deadLetterQueue = new sqs.Queue(this, "Dlq", { retentionPeriod: Duration.days(14), enforceSSL: true });
    this.queue = new sqs.Queue(this, "Queue", {
      visibilityTimeout: Duration.seconds(60), // 2x the function timeout
      enforceSSL: true,
      deadLetterQueue: { queue: this.deadLetterQueue, maxReceiveCount: 5 },
    });
    this.fn = new nodejs.NodejsFunction(this, "Fn", {
      entry: fileURLToPath(new URL("./handler.ts", import.meta.url)),
      runtime: lambda.Runtime.NODEJS_22_X,
      timeout: Duration.seconds(30),
      memorySize: 256,
      environment: { ANALYTICS_ENV: props.environment },
      bundling: { format: nodejs.OutputFormat.ESM, minify: true, target: "node22", mainFields: ["module", "main"], banner: "import { createRequire } from 'module'; const require = createRequire(import.meta.url);" },
    });
    // Exactly this stage's analytics parameters, by ARN. No path grant: a path cannot be narrowed, and would expose other stages and account secrets.
    const arns = analyticsParamNames(props.environment).map((n) =>
      Stack.of(this).formatArn({ service: "ssm", resource: "parameter", resourceName: SSM_PREFIX.slice(1) + n }),
    );
    this.fn.addToRolePolicy(new iam.PolicyStatement({ actions: ["ssm:GetParameters"], resources: arns }));
    this.fn.addToRolePolicy(new iam.PolicyStatement({
      actions: ["kms:Decrypt"],
      resources: [props.ssmKeyArn ?? DEFAULT_SSM_KEY_ARN],
      conditions: { StringEquals: { "kms:ViaService": `ssm.${Stack.of(this).region}.amazonaws.com` } },
    }));
    this.fn.addEventSource(new SqsEventSource(this.queue, { batchSize: 10, maxBatchingWindow: Duration.seconds(5), reportBatchItemFailures: true }));
    this.dlqAlarm = new cloudwatch.Alarm(this, "DlqAlarm", {
      metric: this.deadLetterQueue.metricApproximateNumberOfMessagesVisible({ period: Duration.minutes(1) }),
      threshold: 1,
      evaluationPeriods: 1,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      alarmDescription: "Analytics forwarder dead-letter queue is not empty",
    });
  }
}
