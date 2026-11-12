// CloudWatch embedded metric format: one log line per data point, in OpenEntity/Account with the Stage dimension. The
// Monitoring lane's alarms read these (docs/mobile/qa/DAY-4-monitoring.md in the meta repo).
export function emitMetrics(stage: string, values: Record<string, number>): void {
  console.log(JSON.stringify({
    _aws: { Timestamp: Date.now(), CloudWatchMetrics: [{ Namespace: "OpenEntity/Account", Dimensions: [["Stage"]], Metrics: Object.keys(values).map((Name) => ({ Name, Unit: "Count" })) }] },
    Stage: stage, ...values,
  }));
}
