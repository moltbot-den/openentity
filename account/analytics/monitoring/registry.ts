// Registry (OpenEntity stack) monitoring: Lambda alarms through AccountServiceMonitoring's topic and relay, CloudFront 5xx rate,
// and a scheduled Lambda uptime probe. Self-contained and deployed on its own (see app.ts); the OpenEntity stack is not edited.
import { fileURLToPath } from "node:url";
import { Duration } from "aws-cdk-lib";
import * as cloudwatch from "aws-cdk-lib/aws-cloudwatch";
import * as events from "aws-cdk-lib/aws-events";
import * as targets from "aws-cdk-lib/aws-events-targets";
import * as iam from "aws-cdk-lib/aws-iam";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as nodejs from "aws-cdk-lib/aws-lambda-nodejs";
import { Construct } from "constructs";
import { AccountServiceMonitoring } from "./aws.ts";
import type { Target } from "./probe.ts";

export type RegistryMonitoringProps = {
  alertEmail: string;
  stage: "production" | "staging";
  /** Physical name of the registry app Lambda (OpenEntity stack output FunctionName). */
  functionName: string;
  /** CloudFront distribution ids to watch for 5xx (stack outputs DistributionId, McpDistributionId, hub). */
  distributionIds: string[];
  probeTargets: Target[];
};

export class RegistryMonitoring extends Construct {
  readonly monitoring: AccountServiceMonitoring;
  readonly probeFn: nodejs.NodejsFunction;

  constructor(scope: Construct, id: string, props: RegistryMonitoringProps) {
    super(scope, id);
    const base = { treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING, comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD } as const;
    const extra: cloudwatch.Alarm[] = [];

    // 5xx above 1% for 5 minutes, measured at the edge (what a visitor sees).
    props.distributionIds.forEach((d, i) =>
      extra.push(new cloudwatch.Alarm(this, `Edge5xx${i}`, {
        ...base, evaluationPeriods: 5, threshold: 1,
        metric: new cloudwatch.Metric({ namespace: "AWS/CloudFront", metricName: "5xxErrorRate", dimensionsMap: { DistributionId: d, Region: "Global" }, statistic: "Average", period: Duration.minutes(1) }),
        alarmDescription: `CloudFront ${d}: 5xx above 1% for 5 minutes`,
      })));

    // Uptime probe: one alarm per target. A dead probe is an outage too, so missing data breaches.
    this.probeFn = new nodejs.NodejsFunction(this, "Probe", {
      entry: fileURLToPath(new URL("./probe.ts", import.meta.url)),
      runtime: lambda.Runtime.NODEJS_22_X, timeout: Duration.seconds(30), memorySize: 128,
      environment: { TARGETS: JSON.stringify(props.probeTargets) },
      bundling: { format: nodejs.OutputFormat.ESM, minify: true, target: "node22", mainFields: ["module", "main"], banner: "import { createRequire } from 'module'; const require = createRequire(import.meta.url);", externalModules: ["@aws-sdk/*"] },
    });
    this.probeFn.addToRolePolicy(new iam.PolicyStatement({ actions: ["cloudwatch:PutMetricData"], resources: ["*"], conditions: { StringEquals: { "cloudwatch:namespace": "OpenEntity/Uptime" } } }));
    new events.Rule(this, "ProbeSchedule", { schedule: events.Schedule.rate(Duration.minutes(5)), targets: [new targets.LambdaFunction(this.probeFn)] });
    props.probeTargets.forEach((t, i) =>
      extra.push(new cloudwatch.Alarm(this, `Down${i}`, {
        evaluationPeriods: 2, threshold: 1, comparisonOperator: cloudwatch.ComparisonOperator.LESS_THAN_THRESHOLD, treatMissingData: cloudwatch.TreatMissingData.BREACHING,
        metric: new cloudwatch.Metric({ namespace: "OpenEntity/Uptime", metricName: "Up", dimensionsMap: { Target: t.name }, statistic: "Minimum", period: Duration.minutes(5) }),
        alarmDescription: `${t.name} is down: ${t.url}`,
      })));

    this.monitoring = new AccountServiceMonitoring(this, "Monitoring", {
      alertEmail: props.alertEmail, stage: props.stage, alarms: extra,
      functions: [lambda.Function.fromFunctionName(this, "Registry", props.functionName)],
    });
  }
}
