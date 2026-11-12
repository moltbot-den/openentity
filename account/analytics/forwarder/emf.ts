// CloudWatch Embedded Metric Format lines for the events that PLAN 13.3 alarms read. The forwarder already sees every
// validated event, so no account code has to log anything. Cost control: only these events, a closed set of dimension
// values (anything else becomes "other"), so the number of custom metrics stays small and bounded.
import type { QueuedEvent } from "../src/validate.ts";

export const NAMESPACE = "OpenEntity/Events";
export const METHODS = ["apple", "google", "passkey", "email_code"] as const; // sign_in method enum in events.yaml
export const FRAMEWORKS = ["langchain", "adk", "crewai", "openai-agents", "mastra", "vercel-ai", "goose"] as const;

const BY_METHOD = new Set(["sign_in_completed", "sign_in_failed"]);
const BY_FRAMEWORK = new Set(["pair_confirmed", "pair_failed"]);
const PLAIN = new Set(["approval_requested", "approval_expired", "approval_decided", "approval_rejected_by_verifier", "legacy_approval_attempted"]);

type Line = Record<string, unknown>;
const emf = (stage: string, now: number, dims: Record<string, string>, metric: string, value: number, unit: string): Line => ({
  _aws: { Timestamp: now, CloudWatchMetrics: [{ Namespace: NAMESPACE, Dimensions: [["Stage", ...Object.keys(dims)]], Metrics: [{ Name: metric, Unit: unit }] }] },
  Stage: stage, ...dims, [metric]: value,
});

const framework = (p: Record<string, string | number | boolean>) => {
  const f = typeof p.framework === "string" ? p.framework : "unknown";
  return f === "unknown" || (FRAMEWORKS as readonly string[]).includes(f) ? f : "other";
};

/** One aggregated EMF line per (event, dimension value), plus the max pause time. */
export function metricLines(stage: string, events: QueuedEvent[], now = Date.now()): Line[] {
  const counts = new Map<string, { dims: Record<string, string>; n: number }>();
  let pause = -1;
  for (const e of events) {
    let dims: Record<string, string> | undefined;
    if (BY_METHOD.has(e.event)) dims = { Event: e.event, Method: (METHODS as readonly string[]).includes(String(e.props.method)) ? String(e.props.method) : "other" };
    else if (BY_FRAMEWORK.has(e.event)) dims = { Event: e.event, Framework: framework(e.props) };
    else if (PLAIN.has(e.event)) dims = { Event: e.event };
    else if (e.event === "agent_pause_enforced" && typeof e.props.seconds === "number") pause = Math.max(pause, e.props.seconds);
    if (!dims) continue;
    const k = JSON.stringify(dims);
    counts.set(k, { dims, n: (counts.get(k)?.n ?? 0) + 1 });
  }
  const lines = [...counts.values()].map(({ dims, n }) => emf(stage, now, dims, "Count", n, "Count"));
  if (pause >= 0) lines.push(emf(stage, now, {}, "PauseSeconds", pause, "Seconds"));
  return lines;
}
