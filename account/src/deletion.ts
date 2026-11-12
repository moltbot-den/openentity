// Account deletion (PLAN 2.3, guideline 5.1.1(v); openapi /v1/account/delete and /v1/account/deletion-request):
// - with a key log: step-up account.delete (an approval/2.0 from a key log credential);
// - with no key log yet: a sign-in in the last 5 minutes;
// - a key log that can no longer sign: a request that waits 7 days, told to every install and the account email, which
//   a current approver or the root passkey can cancel (verifyApproval with allowRoot).
// Deleting revokes Apple's tokens, sends owner.deleted to every product, closes the key log with the service's close key
// (the log stays readable, so old signatures still verify) and removes the account's personal data.
import type { Hono } from "hono";
import type { Deps } from "./app.ts";
import { newId, now } from "./db.ts";
import { bearer, fail } from "./http.ts";
import { closeKeyLog, keyLogState } from "./keylog.ts";
import { notifyOwner } from "./notify.ts";
import { sendEvent } from "./outbound.ts";
import { revokeAppleTokens } from "./apple.ts";
import { requireApproval } from "./stepup.ts";
import { PRODUCT_DIDS } from "./wellknown.ts";

export const REAUTH_WINDOW = 300, DELETION_WAIT = 7 * 86_400;

interface Row { id: string; requested_at: number; effective_at: number; state: string }
const shape = (r: Row) => ({ id: r.id, requested_at: Number(r.requested_at), effective_at: Number(r.effective_at), state: r.state });

/** The account's pending deletion request (Account.deletion), or null. */
export async function deletionOf(d: Deps, accountId: string) {
  const r = await d.db.first<Row>("SELECT id, requested_at, effective_at, state FROM deletion_requests WHERE account_id = $1 AND state = 'pending'", [accountId]);
  return r ? shape(r) : null;
}

/**
 * Deletes the account. Products learn it through owner.deleted (retried from the outbox when one is down); a failed
 * Apple revocation is logged and never blocks the deletion. Idempotent: a deleted account is left as it is.
 */
export async function deleteAccount(d: Deps, accountId: string): Promise<number> {
  const a = await d.db.first<{ owner_did: string | null; deleted_at: number | null }>("SELECT owner_did, deleted_at FROM accounts WHERE id = $1", [accountId]);
  if (!a) return fail(404, "not_found", "no such account");
  if (a.deleted_at !== null) return Number(a.deleted_at);
  await revokeAppleTokens(d, accountId);
  // Close first: if anything after it fails, a closed log signs nothing more, and the delete route then takes a fresh
  // sign-in instead of an approval, so the owner can finish.
  if (a.owner_did) {
    const log = await keyLogState(d, a.owner_did);
    if (log && !log.closed) await closeKeyLog(d, a.owner_did);
  }
  const t = now();
  await d.db.tx(async (tx) => {
    await tx.run("UPDATE accounts SET deleted_at = $2, email = NULL WHERE id = $1", [accountId, t]);
    await tx.run("UPDATE sessions SET revoked_at = $2, revoke_reason = 'account_deleted' WHERE account_id = $1 AND revoked_at IS NULL", [accountId, t]);
    await tx.run("DELETE FROM methods WHERE account_id = $1", [accountId]); // the same Apple ID, Google account or email may start a new account
    await tx.run("DELETE FROM push_tokens WHERE account_id = $1", [accountId]);
    await tx.run("UPDATE deletion_requests SET state = 'done' WHERE account_id = $1 AND state = 'pending'", [accountId]);
  });
  // Products know the owner only by its DID; an account with no key log never had a product token.
  if (a.owner_did) await Promise.all(PRODUCT_DIDS.map((p) => sendEvent(d, p, "owner.deleted", { owner_did: a.owner_did, deleted_at: t })));
  return t;
}

/** jobs.ts: carries out deletion requests whose 7 days have passed. */
export async function runDueDeletions(d: Deps): Promise<void> {
  for (const r of await d.db.all<{ account_id: string }>("SELECT account_id FROM deletion_requests WHERE state = 'pending' AND effective_at <= $1 LIMIT 20", [now()])) {
    await deleteAccount(d, r.account_id);
  }
}

export function routes(app: Hono, d: Deps) {
  app.post("/v1/account/delete", async (c) => {
    const owner = await bearer(c, d);
    const log = owner.ownerDid ? await keyLogState(d, owner.ownerDid) : null;
    // A closed log means this deletion was approved and stopped part way: a fresh sign-in finishes it.
    if (log && !log.closed) await requireApproval(c, d, { accountId: owner.accountId, ownerDid: owner.ownerDid, action: "account.delete", params: {} });
    else if (now() - owner.authTime > REAUTH_WINDOW) fail(401, "reauth_required", "sign in again, then delete within 5 minutes");
    return c.json({ deleted_at: await deleteAccount(d, owner.accountId) }, 202);
  });

  app.post("/v1/account/deletion-request", async (c) => {
    const owner = await bearer(c, d);
    if (!owner.ownerDid) fail(409, "no_key_log", "an account with no key log deletes at once: POST /v1/account/delete after signing in again");
    if (await deletionOf(d, owner.accountId)) fail(409, "deletion_pending", "a deletion request is already waiting");
    const t = now(), row = { id: newId("del"), requested_at: t, effective_at: t + DELETION_WAIT, state: "pending" };
    const r = await d.db.run("INSERT INTO deletion_requests (id, account_id, requested_at, effective_at, state) VALUES ($1, $2, $3, $4, 'pending') ON CONFLICT DO NOTHING",
      [row.id, owner.accountId, row.requested_at, row.effective_at]);
    if (!r.changes) fail(409, "deletion_pending", "a deletion request is already waiting");
    await notifyOwner(d, owner.accountId, {
      type: "deletion.requested", id: row.id,
      email: {
        subject: "Your OpenEntity account will be deleted in 7 days",
        text: `Someone signed in to your OpenEntity account asked to delete it. It will be deleted on ${new Date(row.effective_at * 1000).toUTCString()}.\n\nIf this was not you, open the OpenEntity app or https://${d.host} and cancel it with an approver or your passkey.`,
      },
    });
    return c.json(row, 202);
  });

  app.post("/v1/account/deletion-request/cancel", async (c) => {
    const owner = await bearer(c, d);
    if (!(await deletionOf(d, owner.accountId))) fail(404, "not_found", "no deletion request is waiting");
    // A current approver or the root passkey; revoked approvers keep only the key log cancel op.
    await requireApproval(c, d, { accountId: owner.accountId, ownerDid: owner.ownerDid, action: "deletion.cancel", params: {}, allowRoot: true });
    const r = await d.db.first<Row>("UPDATE deletion_requests SET state = 'cancelled' WHERE account_id = $1 AND state = 'pending' RETURNING id, requested_at, effective_at, state", [owner.accountId]);
    return r ? c.json(shape(r)) : fail(404, "not_found", "no deletion request is waiting");
  });
}
