// Scheduled work (EventBridge, account-stack.ts): lambda.ts calls runJobs on every tick. Both lanes add their jobs to
// JOBS; each must be quick, idempotent and safe to run twice at once.
import type { Deps } from "./app.ts";
import { now } from "./db.ts";
import { purgeTestAccounts, runDueDeletions } from "./deletion.ts";
import { emitMetrics } from "./metrics.ts";
import { retryOutbox } from "./outbound.ts";
import { appReviewWatch } from "./signin.ts";

const JOBS: [string, (d: Deps) => Promise<unknown>][] = [
  ["outbox", retryOutbox],
  ["deletions", runDueDeletions],
  ["test_accounts", (d) => purgeTestAccounts(d)], // staging only (deletion.ts)
  ["app_review", appReviewWatch],
  // PendingRecoveriesMax, every tick (0 included): the most recoveries one owner started in the last 24 hours that have
  // neither taken effect nor been cancelled (a cancel names its target's hash). The Monitoring lane alarms above 3.
  ["recoveries", async (d) => {
    const t = now();
    const r = await d.db.first<{ n: number | null }>(
      `SELECT MAX(n) AS n FROM (SELECT count(*) AS n FROM keylog_entries r
         WHERE r.op = 'recover' AND r.first_seen_at > $1 AND r.effective_at > $2
           AND NOT EXISTS (SELECT 1 FROM keylog_entries c WHERE c.owner_id = r.owner_id AND c.op = 'cancel' AND (c.line::jsonb -> 'body' ->> 'target') = r.hash)
         GROUP BY r.owner_id) x`, [t - 86_400, t]);
    emitMetrics(d.stage, { PendingRecoveriesMax: Number(r?.n ?? 0) });
  }],
  ["login_codes", (d) => d.db.run("DELETE FROM login_codes WHERE expires_at < $1", [now() - 3600])],
  // Sign-in rows past any use: codes (they name an address), nonces and passkey challenges after a day.
  ["signin_rows", async (d) => {
    const t = now() - 86_400;
    await d.db.run("DELETE FROM email_codes WHERE expires_at < $1", [t]);
    await d.db.run("DELETE FROM auth_nonces WHERE expires_at < $1", [t]);
    await d.db.run("DELETE FROM passkey_challenges WHERE expires_at < $1", [t]);
  }],
  // Rate counters (some keyed by a hashed address) after a day. Windows are minute or hour numbers (db.ts bump):
  // ponytail: told apart by size (minutes since 1970 are past 10 million, hours are not); add a column if a third unit comes.
  ["rate_events", (d) => {
    const m = Math.floor(now() / 60), h = Math.floor(now() / 3600);
    return d.db.run("DELETE FROM rate_events WHERE window_start ~ '^[0-9]+$' AND ((window_start::bigint >= 10000000 AND window_start::bigint < $1) OR (window_start::bigint < 10000000 AND window_start::bigint < $2))", [m - 1440, h - 48]);
  }],
  // Push tokens removed 8 days ago, and tokens of installs with no session alive or ended in the last 8 days.
  ["push_tokens", (d) => d.db.run(`DELETE FROM push_tokens p WHERE p.removed_at < $1 OR NOT EXISTS (SELECT 1 FROM sessions s
    WHERE s.account_id = p.account_id AND s.install_id = p.install_id AND COALESCE(s.revoked_at, s.expires_at) > $1)`, [now() - 8 * 86_400])],
  ["sig_nonces", (d) => d.db.run("DELETE FROM sig_nonces WHERE expires_at < $1", [now() - 60])],
  // Agent channel rows past any use: acknowledged items after 7 days, pairings and step-up requests after a day, and
  // enrollments past their 24-hour listing window plus a week.
  ["agent_rows", async (d) => {
    const t = now();
    await d.db.run("DELETE FROM inbox WHERE acked_at < $1", [t - 7 * 86_400]);
    await d.db.run("DELETE FROM pairings WHERE expires_at < $1 AND (state <> 'confirmed' OR confirmed_at < $1)", [t - 86_400]);
    await d.db.run("DELETE FROM step_ups WHERE expires_at < $1", [t - 86_400]);
    await d.db.run("DELETE FROM enrollments WHERE expires_at < $1 AND state IN ('pending', 'cancelled', 'completed')", [t - 8 * 86_400]);
    await d.db.run("DELETE FROM event_ids WHERE seen_at < $1", [t - 7 * 86_400]);
    // Uploads no message took, and uploads whose object the bucket's 90-day lifecycle has removed.
    await d.db.run("DELETE FROM uploads WHERE (message_id IS NULL AND expires_at < $1) OR created_at < $2", [t - 86_400, t - 90 * 86_400]);
  }],
];

/** Runs every job; one failing job never stops the others. */
export async function runJobs(d: Deps): Promise<void> {
  for (const [name, job] of JOBS) {
    try {
      await job(d);
    } catch (e) {
      console.error(`job ${name} failed`, e);
    }
  }
}
