// Scheduled work (EventBridge, account-stack.ts): lambda.ts calls runJobs on every tick. Both lanes add their jobs to
// JOBS; each must be quick, idempotent and safe to run twice at once.
import type { Deps } from "./app.ts";
import { now } from "./db.ts";
import { runDueDeletions } from "./deletion.ts";
import { retryOutbox } from "./outbound.ts";
import { appReviewWatch } from "./signin.ts";

const JOBS: [string, (d: Deps) => Promise<unknown>][] = [
  ["outbox", retryOutbox],
  ["deletions", runDueDeletions],
  ["app_review", appReviewWatch],
  ["login_codes", (d) => d.db.run("DELETE FROM login_codes WHERE expires_at < $1", [now() - 3600])],
  ["push_tokens", (d) => d.db.run("DELETE FROM push_tokens WHERE removed_at < $1", [now() - 8 * 86_400])],
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
