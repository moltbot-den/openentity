// Weekly digest (PRD 7.9): once a week the cron triggers a Customer.io API-triggered broadcast to the
// confirmed-subscriber segment. Every number comes from the /v1/stats object or the same tables; none is typed.
import type { Env } from "./env.ts";

const DAY = 86400_000;
/** Monday 14:00 UTC. The cron checks every 10 minutes, so a missed tick is caught up later the same week. */
export const SLOT = { day: 1, hour: 14 };

type Stats = { entities: { total: number }; record_entries: number; attestations: number; observers: number; log: { tree_size: number } };
export type Changes = { entities: number; record_entries: number; log: number; recent: { eid: string; name: string; level: number }[] };

/** The start of this week's slot as a date string ("YYYY-MM-DD" of the Monday), or null before it opens. */
export function dueSlot(now: Date): string | null {
  const monday = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() - ((now.getUTCDay() + 6) % 7), SLOT.hour));
  return now >= monday ? monday.toISOString().slice(0, 10) : null;
}

const clean = (s: string) => s.replace(/[\u0000-\u001f\u007f]/g, " ").trim().slice(0, 80);

/** The trigger `data` for the broadcast template (workspace 238139, template "Weekly digest"). */
export function buildDigest(s: Stats, c: Changes, slot: string) {
  return {
    week_of: slot,
    stats_url: "https://openentity.org/v1/stats",
    entities_total: s.entities.total, entities_change: c.entities,
    record_entries_total: s.record_entries, record_entries_change: c.record_entries,
    attestations_total: s.attestations, observers_total: s.observers,
    log_size: s.log.tree_size, log_size_change: c.log,
    recent: c.recent.map((e) => ({ name: clean(e.name), level: `L${e.level}`, url: `https://openentity.org/entities/${encodeURIComponent(e.eid)}` })),
  };
}

async function changes(env: Env, now: Date): Promise<Changes> {
  const since = new Date(now.getTime() - 7 * DAY).toISOString();
  const n = async (sql: string) => (await env.db.first<{ n: number }>(sql, [since]))?.n ?? 0;
  return {
    entities: await n("SELECT COUNT(*) AS n FROM entities WHERE suppressed = 0 AND level IS NOT NULL AND created >= $1"),
    record_entries: await n("SELECT COUNT(*) AS n FROM record_entries WHERE received_at >= $1"),
    log: await n("SELECT COUNT(*) AS n FROM log_leaves WHERE received_at >= $1"),
    recent: await env.db.all("SELECT eid, name, level FROM entities WHERE suppressed = 0 AND level IS NOT NULL AND created >= $1 ORDER BY created DESC LIMIT 5", [since]),
  };
}

/**
 * Sends at most one digest per weekly slot. The slot is claimed in rate_events before the call (one row per slot,
 * the primary key makes the claim atomic), so two overlapping ticks cannot both send. A failed call releases the claim.
 * Returns true when it sent.
 */
export async function sendDigest(env: Env, s: Stats, now = new Date()): Promise<boolean> {
  const slot = dueSlot(now);
  if (!slot || !env.CIO_APP_API_KEY || !env.CIO_BROADCAST_ID) return false;
  const claim = await env.db.first<{ count: number }>(
    "INSERT INTO rate_events (key, window_start, count) VALUES ('digest', $1, 1) ON CONFLICT (key, window_start) DO UPDATE SET count = rate_events.count + 1 RETURNING count", [slot]);
  if (claim!.count > 1) return false;
  try {
    const res = await fetch(`https://api.customer.io/v1/campaigns/${env.CIO_BROADCAST_ID}/triggers`, {
      method: "POST",
      headers: { authorization: `Bearer ${env.CIO_APP_API_KEY}`, "content-type": "application/json" },
      body: JSON.stringify({ data: buildDigest(s, await changes(env, now), slot)}),
    });
    if (!res.ok) throw new Error(`customer.io trigger ${res.status}: ${(await res.text()).slice(0, 200)}`);
    return true;
  } catch (e) {
    await env.db.run("DELETE FROM rate_events WHERE key = 'digest' AND window_start = $1", [slot]);
    throw e;
  }
}
