// One CloudWatch dashboard for the registry and the account service (PLAN 13.3). The account resources are found with metric
// search expressions on the stack-name prefix (their stacks are not this stack's to read); the registry's are explicit.
import { Duration } from "aws-cdk-lib";
import * as cloudwatch from "aws-cdk-lib/aws-cloudwatch";
import { Construct } from "constructs";
import { NAMESPACE } from "../forwarder/emf.ts";
import type { Target } from "./probe.ts";

export type OperationsDashboardProps = {
  name: string;
  registryFunctionName: string;
  distributionIds: string[];
  probeTargets: Target[];
  /** Stack-name prefix of the account stacks (their physical names start with it). */
  accountPrefix?: string;
};

const period = Duration.minutes(5);

/** A search expression: every metric whose dimensions match, one line each. */
const search = (schema: string, metric: string, term: string, stat: string, label?: string) =>
  new cloudwatch.MathExpression({ expression: `SEARCH('{${schema}} MetricName="${metric}" ${term}', '${stat}', 300)`, usingMetrics: {}, period, label });

export class OperationsDashboard extends Construct {
  readonly dashboard: cloudwatch.Dashboard;

  constructor(scope: Construct, id: string, props: OperationsDashboardProps) {
    super(scope, id);
    const prefix = props.accountPrefix ?? "OpenEntityAccount";
    const graph = (title: string, left: cloudwatch.IMetric[], width = 8, extra: Partial<cloudwatch.GraphWidgetProps> = {}) => new cloudwatch.GraphWidget({ title, left, width, height: 6, ...extra });
    const reg = (metric: string, statistic: string, label: string) => new cloudwatch.Metric({ namespace: "AWS/Lambda", metricName: metric, dimensionsMap: { FunctionName: props.registryFunctionName }, statistic, period, label });
    const events = (event: string, label: string, extra = "") => new cloudwatch.MathExpression({ expression: `SEARCH('{${NAMESPACE},Stage,Event${extra}} MetricName="Count" Event="${event}"', 'Sum', 3600)`, usingMetrics: {}, period: Duration.hours(1), label });

    this.dashboard = new cloudwatch.Dashboard(this, "Dash", { dashboardName: props.name });
    this.dashboard.addWidgets(
      new cloudwatch.TextWidget({ markdown: "# Registry", width: 24, height: 1 }),
      graph("Registry p95 duration (ms)", [reg("Duration", "p95", "p95")], 8, { leftYAxis: { min: 0 } }),
      graph("Registry errors and throttles", [reg("Errors", "Sum", "errors"), reg("Throttles", "Sum", "throttles")]),
      graph("Edge 5xx rate (%)", props.distributionIds.map((d) => new cloudwatch.Metric({ namespace: "AWS/CloudFront", metricName: "5xxErrorRate", dimensionsMap: { DistributionId: d, Region: "Global" }, statistic: "Average", period, label: d })), 8, { leftYAxis: { min: 0 } }),
      graph("Uptime (1 = up)", props.probeTargets.map((t) => new cloudwatch.Metric({ namespace: "OpenEntity/Uptime", metricName: "Up", dimensionsMap: { Target: t.name }, statistic: "Minimum", period, label: t.name })), 24, { leftYAxis: { min: 0, max: 1 }, height: 4 }),

      new cloudwatch.TextWidget({ markdown: `# Account service (stacks ${prefix}*)`, width: 24, height: 1 }),
      graph("Account p95 duration (ms)", [search("AWS/Lambda,FunctionName", "Duration", `"${prefix}"`, "p95")], 8, { leftYAxis: { min: 0 } }),
      graph("Account 5xx: Lambda errors and edge 5xx rate (%)", [search("AWS/Lambda,FunctionName", "Errors", `"${prefix}"`, "Sum"), search("AWS/CloudFront,DistributionId,Region", "5xxErrorRate", "", "Average")]),
      graph("WebSocket connections", [search("AWS/ApiGateway,ApiId,Stage", "ConnectCount", "", "Sum"), search("AWS/ApiGateway,ApiId,Stage", "Count", "", "Sum", "messages")]),
      graph("SQS depth (messages visible)", [search("AWS/SQS,QueueName", "ApproximateNumberOfMessagesVisible", `"${prefix}"`, "Maximum")]),
      graph("Dead-letter queues (must be 0)", [search("AWS/SQS,QueueName", "ApproximateNumberOfMessagesVisible", `"${prefix}" Dlq`, "Maximum")], 8, { leftYAxis: { min: 0 } }),
      graph("Account uptime", [new cloudwatch.Metric({ namespace: "OpenEntity/Uptime", metricName: "Up", dimensionsMap: { Target: "account jwks" }, statistic: "Minimum", period })], 8, { leftYAxis: { min: 0, max: 1 } }),

      new cloudwatch.TextWidget({ markdown: "# Signals (from the analytics event stream)", width: 24, height: 1 }),
      graph("Sign-ins by method (hourly)", [events("sign_in_completed", "completed", ",Method"), events("sign_in_failed", "failed", ",Method")]),
      graph("Approvals (hourly)", [events("approval_requested", "requested"), events("approval_decided", "decided"), events("approval_expired", "expired"), events("approval_rejected_by_verifier", "rejected")]),
      graph("Pairing by framework (hourly)", [events("pair_confirmed", "confirmed", ",Framework"), events("pair_failed", "failed", ",Framework")]),
    );
  }
}
