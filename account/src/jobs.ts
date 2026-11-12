// Scheduled work (EventBridge, account-stack.ts): lambda.ts calls runJobs on every tick. Both lanes add their jobs to
// JOBS; each must be quick, idempotent and safe to run twice at once.
import type { Deps } from "./app.ts";
import { now } from "./db.ts";
import { runDueDeletions } from "./deletion.ts";
import { retryOutbox } from "./outbound.ts";

const JOBS: [string, (d: Deps) => Promise<unknown>][] = [
  ["outbox", retryOutbox],
  ["deletions", runDueDeletions],
  ["push_tokens", (d) => d.db.run("DELETE FROM push_tokens WHERE removed_at < $1", [now() - 8 * 86_400])],
  ["sig_nonces", (d) => d.db.run("DELETE FROM sig_nonces WHERE expires_at < $1", [now() - 60])],
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
