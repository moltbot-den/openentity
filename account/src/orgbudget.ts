// Org budgets (enterprise orgs spec): a budget per org, team or agent, in integer cents. Products enforce mandate/1, so a
// budget reaches them as the mandates the org signs; this file holds the arithmetic that keeps a narrower budget (a team's,
// an agent's) and every mandate inside the wider one. Pure: no database, no clock.
import type { Mandate } from "@openentity/sdk";

export const PERIOD_DAYS: Record<string, number> = { P1D: 1, P7D: 7, P1M: 30 };
export const RAILS = ["card", "x402", "mpp", "credits", "usdc"];

export interface Budget { per_tx_max: number; period: string; period_max: number; step_up_over: number; merchants: string[]; rails: string[] }

const uint = (v: unknown): v is number => Number.isSafeInteger(v) && (v as number) >= 0;
const strs = (v: unknown): v is string[] => Array.isArray(v) && v.length <= 50 && v.every((x) => typeof x === "string" && x.length > 0 && x.length <= 253);

/** The budget in a request body, or why not. Amounts are integer cents (no floats), rails a non-empty subset. */
export function parseBudget(b: Record<string, any>): Budget | string {
  if (!uint(b.per_tx_max) || !uint(b.period_max) || b.per_tx_max < 1 || b.period_max < b.per_tx_max) return "per_tx_max and period_max are integer cents, 1 or more, period_max at least per_tx_max";
  if (!Object.hasOwn(PERIOD_DAYS, b.period)) return `period is one of ${Object.keys(PERIOD_DAYS).join(", ")}`;
  const step = b.step_up_over === undefined ? Math.floor(b.per_tx_max / 2) : b.step_up_over;
  if (!uint(step) || step > b.per_tx_max) return "step_up_over is integer cents, at most per_tx_max";
  const merchants = b.merchants ?? [];
  if (!strs(merchants)) return "merchants is an array of DIDs or domain patterns";
  if (!Array.isArray(b.rails) || !b.rails.length || b.rails.some((r: unknown) => !RAILS.includes(r as string)) || new Set(b.rails).size !== b.rails.length) return `rails is a non-empty list of ${RAILS.join(", ")}`;
  return { per_tx_max: b.per_tx_max, period: b.period, period_max: b.period_max, step_up_over: step, merchants, rails: b.rails };
}

/** Whether `inner` fits inside `outer`: per-transaction cap, the period cap (its per-day rate, or the whole cap when the inner period is longer), the step-up threshold, rails and merchants. */
export function within(inner: Budget, outer: Budget): boolean {
  return inner.per_tx_max <= outer.per_tx_max
    && (PERIOD_DAYS[inner.period] > PERIOD_DAYS[outer.period]
      ? inner.period_max <= outer.period_max // a longer inner period can burn its whole cap inside one outer window
      : inner.period_max * PERIOD_DAYS[outer.period] <= outer.period_max * PERIOD_DAYS[inner.period])
    && inner.step_up_over <= outer.step_up_over
    && inner.rails.every((r) => outer.rails.includes(r))
    && (outer.merchants.length === 0 || (inner.merchants.length > 0 && inner.merchants.every((m) => outer.merchants.includes(m))));
}

/** The budget a mandate/1 amounts to. */
export const ofMandate = (m: Pick<Mandate, "limits" | "scope" | "step_up_over">): Budget =>
  ({ per_tx_max: m.limits.per_tx_max, period: m.limits.period, period_max: m.limits.period_max, step_up_over: m.step_up_over, merchants: m.scope.merchants, rails: m.scope.rails });

/** The mandate/1 body (unsigned) that spends exactly `b` for `days` days. */
export function draftMandate(b: Budget, o: { id: string; issuer: string; agent: string; t: number; days: number; status: string }) {
  return {
    version: "mandate/1", mandate_id: o.id, issuer_did: o.issuer, agent_did: o.agent, issued_at: o.t, expires_at: o.t + o.days * 86_400,
    limits: { currency: "USD", per_tx_max: b.per_tx_max, period: b.period, period_max: b.period_max, total_max: b.period_max * Math.ceil(o.days / PERIOD_DAYS[b.period]) },
    scope: { merchants: b.merchants, rails: b.rails }, step_up_over: b.step_up_over, status: o.status,
  };
}
