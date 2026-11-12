// PLAN 13.3 alarms that metrics can drive. Sources:
//   OpenEntity/Events   emitted by the analytics forwarder (forwarder/emf.ts) from the validated event stream
//   OpenEntity/Account  emitted by the account service (PushSent, PushFailed, PendingRecoveriesMax): see DAY-4-monitoring.md for the exact lines
// Rate alarms ignore windows with fewer events than `min`, so one failure out of three does not page anyone.
import { Duration } from "aws-cdk-lib";
import * as cloudwatch from "aws-cdk-lib/aws-cloudwatch";
import { Construct } from "constructs";
import { FRAMEWORKS, METHODS, NAMESPACE } from "../forwarder/emf.ts";

export type SignalAlarmsProps = {
  stage: "production" | "staging" | "proof";
  /** PLAN 13.3: legacy approval attempts alert only after Day 8; until then the alarm exists but sends nothing. */
  legacyApprovalActionsEnabled?: boolean;
};

export class SignalAlarms extends Construct {
  readonly alarms: cloudwatch.Alarm[] = [];
  readonly legacyApproval: cloudwatch.Alarm;

  constructor(scope: Construct, id: string, props: SignalAlarmsProps) {
    super(scope, id);
    const { stage } = props;
    const count = (event: string, extra: Record<string, string>, period: Duration) =>
      new cloudwatch.Metric({ namespace: NAMESPACE, metricName: "Count", dimensionsMap: { Stage: stage, Event: event, ...extra }, statistic: "Sum", period });
    const account = (metricName: string, statistic: string, period: Duration) =>
      new cloudwatch.Metric({ namespace: "OpenEntity/Account", metricName, dimensionsMap: { Stage: stage }, statistic, period });
    const add = (name: string, a: cloudwatch.Alarm) => { this.alarms.push(a); return a; };

    /** Percent of `bad` in bad+good, or in `total` when given, above `pct`, ignoring windows under `min` events. */
    const rate = (name: string, o: { bad: cloudwatch.IMetric; good?: cloudwatch.IMetric; total?: cloudwatch.IMetric; pct: number; min: number; period: Duration; description: string }) => {
      const total = o.total ? "t" : "(b + g)";
      return add(name, new cloudwatch.Alarm(this, name, {
        metric: new cloudwatch.MathExpression({
          expression: `IF(${total} >= ${o.min}, 100 * b / ${total}, 0)`,
          usingMetrics: { b: o.bad, ...(o.good ? { g: o.good } : {}), ...(o.total ? { t: o.total } : {}) },
          period: o.period, label: name,
        }),
        threshold: o.pct, evaluationPeriods: 1, comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING, alarmDescription: `[${stage}] ${o.description}`,
      }));
    };
    const hour = Duration.hours(1);

    for (const m of [...METHODS, "other"])
      rate(`SignInFailures-${m}`, { bad: count("sign_in_failed", { Method: m }, hour), good: count("sign_in_completed", { Method: m }, hour), pct: 5, min: 20, period: hour, description: `Sign-in failures above 5% for ${m} in the last hour` });

    rate("PushFailures", { bad: account("PushFailed", "Sum", hour), good: account("PushSent", "Sum", hour), pct: 2, min: 20, period: hour, description: "Push delivery failures above 2% in the last hour" });

    for (const f of [...FRAMEWORKS, "other", "unknown"])
      rate(`PairFailed-${f}`, { bad: count("pair_failed", { Framework: f }, hour), good: count("pair_confirmed", { Framework: f }, hour), pct: 10, min: 10, period: hour, description: `pair_failed above 10% for ${f} in the last hour` });

    rate("VerifierRejections", { bad: count("approval_rejected_by_verifier", {}, hour), good: count("approval_decided", {}, hour), pct: 1, min: 20, period: hour, description: "Verifier rejections above 1% of approvals in the last hour" });

    const day = Duration.days(1);
    rate("ApprovalExpiry", { bad: count("approval_expired", {}, day), total: count("approval_requested", {}, day), pct: 30, min: 10, period: day, description: "Approval expiry above 30% of requests in the last day" });

    add("PauseEnforcement", new cloudwatch.Alarm(this, "PauseEnforcement", {
      metric: new cloudwatch.Metric({ namespace: NAMESPACE, metricName: "PauseSeconds", dimensionsMap: { Stage: stage }, statistic: "Maximum", period: Duration.minutes(5) }),
      threshold: 60, evaluationPeriods: 1, comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD, treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      alarmDescription: `[${stage}] A pause took more than 60 seconds to enforce`,
    }));

    add("PendingRecoveries", new cloudwatch.Alarm(this, "PendingRecoveries", {
      metric: account("PendingRecoveriesMax", "Maximum", hour),
      threshold: 3, evaluationPeriods: 1, comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD, treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      alarmDescription: `[${stage}] More than 3 recoveries pending for one owner in a day`,
    }));

    this.legacyApproval = add("LegacyApproval", new cloudwatch.Alarm(this, "LegacyApproval", {
      metric: count("legacy_approval_attempted", {}, Duration.minutes(5)),
      threshold: 0, evaluationPeriods: 1, comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD, treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      alarmDescription: `[${stage}] A legacy (approval/1.0) approval was attempted`,
      actionsEnabled: props.legacyApprovalActionsEnabled ?? false,
    }));
  }
}
