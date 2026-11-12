// Self-contained: the Account lane imports this into its stack.
//   new AccountServiceMonitoring(this, "Monitoring", { alertEmail, stage: "production", functions: [apiFn], httpApiId: api.apiId, dlqs: [fwd.deadLetterQueue], alarms: [fwd.dlqAlarm] })
// Cost: standard alarms, one SNS topic and a tiny relay Lambda (SNS -> Customer.io email; no confirmation click). No Synthetics canaries, no dashboards, no X-Ray.
import { fileURLToPath } from "node:url";
import { Duration, Stack } from "aws-cdk-lib";
import * as iam from "aws-cdk-lib/aws-iam";
import * as nodejs from "aws-cdk-lib/aws-lambda-nodejs";
import * as lambdaLib from "aws-cdk-lib/aws-lambda";
import * as cloudwatch from "aws-cdk-lib/aws-cloudwatch";
import { SnsAction } from "aws-cdk-lib/aws-cloudwatch-actions";
import type * as lambda from "aws-cdk-lib/aws-lambda";
import * as sns from "aws-cdk-lib/aws-sns";
import { LambdaSubscription } from "aws-cdk-lib/aws-sns-subscriptions";
import type * as sqs from "aws-cdk-lib/aws-sqs";
import { Construct } from "constructs";
import { cioParamNames, PARAM_PATH } from "./relay.ts";

export type AccountServiceMonitoringProps = {
  /** The ops email. Alarms reach it through the relay Lambda (Customer.io), so no confirmation click is needed. */
  alertEmail: string;
  /** Named in every subject line. */
  stage: "production" | "staging";
  ssmKeyArn?: string;
  /** Lambdas of the account service (Errors and Throttles alarms on each). */
  functions: lambda.IFunction[];
  /** HTTP API id (API Gateway v2). Without it, latency and 5xx fall back to the Lambda metrics. */
  httpApiId?: string;
  /** Queues that must stay empty (dead-letter queues). */
  dlqs?: sqs.IQueue[];
  /** Alarms made elsewhere (for example AnalyticsForwarder.dlqAlarm) to route to the same topic. */
  alarms?: cloudwatch.Alarm[];
};

export class AccountServiceMonitoring extends Construct {
  readonly topic: sns.Topic;
  readonly relay: nodejs.NodejsFunction;
  readonly alarms: cloudwatch.Alarm[] = [];

  constructor(scope: Construct, id: string, props: AccountServiceMonitoringProps) {
    super(scope, id);
    this.topic = new sns.Topic(this, "Alerts", { enforceSSL: true });
    this.relay = new nodejs.NodejsFunction(this, "Relay", {
      entry: fileURLToPath(new URL("./relay.ts", import.meta.url)),
      runtime: lambdaLib.Runtime.NODEJS_22_X,
      timeout: Duration.seconds(20),
      memorySize: 128,
      environment: { STAGE: props.stage, TOPIC_ARN: this.topic.topicArn, ALERT_EMAIL: props.alertEmail },
      bundling: { format: nodejs.OutputFormat.ESM, minify: true, target: "node22", mainFields: ["module", "main"], banner: "import { createRequire } from 'module'; const require = createRequire(import.meta.url);" },
    });
    this.relay.addToRolePolicy(new iam.PolicyStatement({ actions: ["ssm:GetParameters"], resources: cioParamNames(props.stage).map((n) => Stack.of(this).formatArn({ service: "ssm", resource: "parameter", resourceName: PARAM_PATH.slice(1) + n })) }));
    this.relay.addToRolePolicy(new iam.PolicyStatement({
      actions: ["kms:Decrypt"],
      resources: [props.ssmKeyArn ?? "arn:aws:kms:us-east-1:099705791378:key/6076f65d-76f2-424d-8375-e74257cd5d07"],
      conditions: { StringEquals: { "kms:ViaService": `ssm.${Stack.of(this).region}.amazonaws.com` } },
    }));
    this.topic.addSubscription(new LambdaSubscription(this.relay)); // no confirmation step
    // enforceSSL leaves a policy with only a Deny, so CloudWatch needs an explicit Allow (found by the staging proof: "not authorized to perform SNS:Publish").
    this.topic.addToResourcePolicy(new iam.PolicyStatement({
      actions: ["sns:Publish"],
      principals: [new iam.ServicePrincipal("cloudwatch.amazonaws.com")],
      resources: [this.topic.topicArn],
      conditions: {
        StringEquals: { "aws:SourceAccount": Stack.of(this).account },
        ArnLike: { "aws:SourceArn": `arn:${Stack.of(this).partition}:cloudwatch:${Stack.of(this).region}:${Stack.of(this).account}:alarm:*` },
      },
    }));
    const action = new SnsAction(this.topic);
    const add = (alarmId: string, alarm: cloudwatch.Alarm) => {
      alarm.addAlarmAction(action);
      this.alarms.push(alarm);
    };
    const base = { evaluationPeriods: 1, treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING, comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD } as const;

    props.functions.forEach((fn, i) => {
      add(`Errors${i}`, new cloudwatch.Alarm(this, `Errors${i}`, { ...base, metric: fn.metricErrors({ period: Duration.minutes(5), statistic: "Sum" }), threshold: 1, alarmDescription: `${fn.functionName}: Lambda errors` }));
      add(`Throttles${i}`, new cloudwatch.Alarm(this, `Throttles${i}`, { ...base, metric: fn.metricThrottles({ period: Duration.minutes(5), statistic: "Sum" }), threshold: 1, alarmDescription: `${fn.functionName}: Lambda throttles` }));
    });

    // p95 latency above 800 ms, and 5xx above 1% for 5 minutes (5 one-minute periods).
    const api = (metricName: string, statistic: string) => new cloudwatch.Metric({ namespace: "AWS/ApiGateway", metricName, dimensionsMap: { ApiId: props.httpApiId! }, period: Duration.minutes(1), statistic });
    const agg = (name: "metricInvocations" | "metricErrors", statistic: string, pre: string) =>
      new cloudwatch.MathExpression({ expression: props.functions.map((_, i) => `${pre}${i}`).join("+") || "0", usingMetrics: Object.fromEntries(props.functions.map((f, i) => [`${pre}${i}`, f[name]({ period: Duration.minutes(1), statistic })])), period: Duration.minutes(1) });
    if (props.httpApiId) {
      add("P95", new cloudwatch.Alarm(this, "P95", { ...base, evaluationPeriods: 3, metric: api("Latency", "p95"), threshold: 800, alarmDescription: "Account service p95 latency above 800 ms" }));
      add("Rate5xx", new cloudwatch.Alarm(this, "Rate5xx", { ...base, evaluationPeriods: 5, threshold: 1, alarmDescription: "Account service 5xx above 1% for 5 minutes",
        metric: new cloudwatch.MathExpression({ expression: "IF(c > 0, 100 * e / c, 0)", usingMetrics: { e: api("5xx", "Sum"), c: api("Count", "Sum") }, period: Duration.minutes(1) }) }));
    } else if (props.functions.length) {
      // ponytail: Lambda duration and errors stand in for API metrics; pass httpApiId for the real ones.
      add("P95", new cloudwatch.Alarm(this, "P95", { ...base, evaluationPeriods: 3, metric: props.functions[0].metricDuration({ period: Duration.minutes(1), statistic: "p95" }), threshold: 800, alarmDescription: "Account service p95 duration above 800 ms" }));
      add("Rate5xx", new cloudwatch.Alarm(this, "Rate5xx", { ...base, evaluationPeriods: 5, threshold: 1, alarmDescription: "Account service error rate above 1% for 5 minutes",
        metric: new cloudwatch.MathExpression({ expression: "IF(c > 0, 100 * e / c, 0)", usingMetrics: { e: agg("metricErrors", "Sum", "e"), c: agg("metricInvocations", "Sum", "c") }, period: Duration.minutes(1) }) }));
    }

    (props.dlqs ?? []).forEach((q, i) =>
      add(`Dlq${i}`, new cloudwatch.Alarm(this, `Dlq${i}`, { ...base, metric: q.metricApproximateNumberOfMessagesVisible({ period: Duration.minutes(1) }), threshold: 1, alarmDescription: "Dead-letter queue is not empty" })));
    (props.alarms ?? []).forEach((a) => a.addAlarmAction(action));
  }
}
