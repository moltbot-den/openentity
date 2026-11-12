// Push hub (web lane): POST /v1/notify (product-signed, ids only), push tokens, APNs and FCM. Its own routes only;
// registered once in app.ts.
import type { Hono } from "hono";
import type { Deps } from "./app.ts";

export function routes(_app: Hono, _d: Deps) {}

/** A notice for the owner, from the service itself: pushed with ids only, and mailed when `email` is set. */
export interface OwnerNotice {
  /** The push type, e.g. keylog.revoke, keylog.recover, keylog.replace_root, enrollment.pending, agent.muted. */
  type: string;
  /** The id the app fetches (a key log seq, an enrollment id, an agent DID). */
  id: string;
  agent?: string;
  /** Mail the account email too, with this subject and plain text (PLAN 3.2: revoke, recover and replace_root). */
  email?: { subject: string; text: string };
}

/**
 * Sends a notice to every install of the account, including installs signed out in the last 7 days (PLAN 3.2: revoked
 * approvers are told for 7 days), and mails the account email when asked. Core calls it; the web lane delivers it.
 * Never throws: a notice that cannot go out is logged.
 */
export async function notifyOwner(_d: Deps, _accountId: string, _n: OwnerNotice): Promise<void> {}
