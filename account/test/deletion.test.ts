import { verifyKeyLog } from "@openentity/sdk";
import { expect, test } from "vitest";
import { PRODUCT_DIDS } from "../src/app.ts";
import { runDueDeletions } from "../src/deletion.ts";
import { keyLogState } from "../src/keylog.ts";
import { approvalHeader, approve, bearer, call, owner, stepUp, webApp } from "./owner.ts";

const { d, app, out } = await webApp();
const events = (type: string) => out.calls.filter((c) => c.url.endsWith("/v1/oe/events") && c.body.type === type);

test("guard: no key log deletes after a fresh sign-in; a sign-in older than 5 minutes is refused", async () => {
  const stale = await owner(d, { keyLog: false, authAgo: 600 });
  expect((await call(app, "POST", "/v1/account/delete", undefined, bearer(stale))).body.error).toBe("reauth_required");
  const fresh = await owner(d, { keyLog: false });
  const r = await call(app, "POST", "/v1/account/delete", undefined, bearer(fresh));
  expect(r.status).toBe(202);
  expect(r.body.deleted_at).toBeGreaterThan(0);
  expect(await d.db.first("SELECT 1 FROM methods WHERE account_id = $1", [fresh.accountId])).toBeNull();
  expect((await d.db.first<any>("SELECT email, deleted_at FROM accounts WHERE id = $1", [fresh.accountId])).email).toBeNull();
  expect((await call(app, "GET", "/v1/me", undefined, bearer(fresh))).status).toBe(401); // the session ended with the account
});

test("guard: with a key log the session alone cannot delete, nor an approval for another action", async () => {
  const o = await owner(d);
  expect((await call(app, "POST", "/v1/account/delete", undefined, bearer(o))).status).toBe(428);
  const other = await stepUp(app, o, "method.remove", { method_id: "mth_x" }).catch(() => null); // no such method: 404 at step-up
  expect(other).toBeNull();
  const wrong = await stepUp(app, o, "email.change", { email: "new@example.com" });
  expect((await call(app, "POST", "/v1/account/delete", undefined, wrong)).body.error).toBe("approval_invalid");
  expect((await d.db.first<any>("SELECT deleted_at FROM accounts WHERE id = $1", [o.accountId])).deleted_at).toBeNull();
});

test("deletion with step-up: owner.deleted to every product, the key log closed by the service and still verifying", async () => {
  const o = await owner(d);
  const r = await call(app, "POST", "/v1/account/delete", undefined, await stepUp(app, o, "account.delete"));
  expect(r.status).toBe(202);
  const sent = events("owner.deleted").filter((e) => e.body.data.owner_did === o.ownerDid);
  expect(sent.map((e) => new URL(e.url).host).sort()).toEqual(["api.agentsecretstore.com", "api.clawgrc.com", "api.moltbotden.com", "api.securemyagent.ai"]);
  expect(sent.length).toBe(PRODUCT_DIDS.length);
  expect(sent[0].body.data).toEqual({ owner_did: o.ownerDid, deleted_at: r.body.deleted_at });
  expect(sent[0].headers["signature-input"]).toContain(`keyid="did:web:${d.host}#${d.keys.did.kid}"`);
  // The log is closed by the close key and still verifies for anyone holding the service's close keys.
  expect((await keyLogState(d, o.ownerDid))!.closed).toBe(true);
  const lines = (await call(app, "GET", `/o/${o.ownerDid.split(":o:")[1]}/log`)).text.trim().split("\n");
  expect(JSON.parse(lines.at(-1)!).op).toBe("close");
  const v = verifyKeyLog(o.ownerDid, lines, lines.map(() => Math.floor(Date.now() / 1000)), { rpId: d.rp.id, origins: d.rp.origins, serviceKeys: [d.keys.close.jwk as any] });
  expect(v.ok && v.state.closed).toBe(true);
  expect((await call(app, "GET", "/v1/me", undefined, bearer(o))).status).toBe(401);
});

test("deletion request: needs a key log, waits 7 days, tells the owner, and one at a time", async () => {
  const none = await owner(d, { keyLog: false });
  expect((await call(app, "POST", "/v1/account/deletion-request", undefined, bearer(none))).body.error).toBe("no_key_log");
  const o = await owner(d, { email: "wait@example.com" });
  const r = await call(app, "POST", "/v1/account/deletion-request", undefined, bearer(o));
  expect(r.status).toBe(202);
  expect(r.body).toMatchObject({ state: "pending" });
  expect(r.body.effective_at - r.body.requested_at).toBe(7 * 86_400);
  expect(out.mail.at(-1)).toMatchObject({ to: "wait@example.com", subject: "Your OpenEntity account will be deleted in 7 days" });
  expect((await call(app, "POST", "/v1/account/deletion-request", undefined, bearer(o))).body.error).toBe("deletion_pending");
});

test("guard: cancelling a deletion request needs an approval; the root passkey may sign it (allowRoot)", async () => {
  const o = await owner(d);
  await call(app, "POST", "/v1/account/deletion-request", undefined, bearer(o));
  expect((await call(app, "POST", "/v1/account/deletion-request/cancel", undefined, bearer(o))).status).toBe(428);
  const viaRoot = await stepUp(app, o, "deletion.cancel", {}, o.root);
  const r = await call(app, "POST", "/v1/account/deletion-request/cancel", undefined, viaRoot);
  expect([r.status, r.body.state]).toEqual([200, "cancelled"]);
  expect((await call(app, "POST", "/v1/account/deletion-request/cancel", undefined, viaRoot)).body.error).toBe("not_found");
  // The root passkey is not enough for deleting outright: account.delete never allows the root while approvers exist.
  const rootDelete = await stepUp(app, o, "account.delete", {}, o.root);
  expect((await call(app, "POST", "/v1/account/delete", undefined, rootDelete)).body.error).toBe("approval_invalid");
});

test("guard: an approval is single use", async () => {
  const o = await owner(d);
  await call(app, "POST", "/v1/account/deletion-request", undefined, bearer(o));
  const h = await stepUp(app, o, "deletion.cancel");
  expect((await call(app, "POST", "/v1/account/deletion-request/cancel", undefined, h)).status).toBe(200);
  await call(app, "POST", "/v1/account/deletion-request", undefined, bearer(o));
  expect((await call(app, "POST", "/v1/account/deletion-request/cancel", undefined, h)).body.error).toBe("approval_reused");
});

test("a deletion request runs after 7 days (jobs)", async () => {
  const o = await owner(d);
  await call(app, "POST", "/v1/account/deletion-request", undefined, bearer(o));
  await d.db.run("UPDATE deletion_requests SET effective_at = 1 WHERE account_id = $1", [o.accountId]);
  await runDueDeletions(d);
  expect(Number((await d.db.first<any>("SELECT deleted_at FROM accounts WHERE id = $1", [o.accountId])).deleted_at)).toBeGreaterThan(0);
  expect((await d.db.first<any>("SELECT state FROM deletion_requests WHERE account_id = $1", [o.accountId])).state).toBe("done");
  expect((await keyLogState(d, o.ownerDid))!.closed).toBe(true);
});

test("guard: an approval signed by a key outside the owner's log is refused", async () => {
  const o = await owner(d), stranger = await owner(d);
  const r = await call(app, "POST", "/v1/step-up", { action: "account.delete", params: {} }, bearer(o));
  const forged = approvalHeader(approve(stranger.approver!, r.body));
  expect((await call(app, "POST", "/v1/account/delete", undefined, { ...bearer(o), ...forged })).body.error).toBe("approval_invalid");
});

test("a deletion stopped after the log closed finishes with a fresh sign-in (a closed log signs nothing)", async () => {
  const { closeKeyLog } = await import("../src/keylog.ts");
  const stale = await owner(d, { authAgo: 600 });
  await closeKeyLog(d, stale.ownerDid);
  expect((await call(app, "POST", "/v1/account/delete", undefined, bearer(stale))).body.error).toBe("reauth_required");
  const fresh = await owner(d);
  await closeKeyLog(d, fresh.ownerDid);
  expect((await call(app, "POST", "/v1/account/delete", undefined, bearer(fresh))).status).toBe(202);
  expect(events("owner.deleted").some((e) => e.body.data.owner_did === fresh.ownerDid)).toBe(true);
});

test("deletion removes the account's sessions and refresh token hashes, not only revokes them", async () => {
  const o = await owner(d, { keyLog: false });
  await call(app, "POST", "/v1/account/delete", undefined, bearer(o));
  expect(await d.db.first("SELECT 1 FROM sessions WHERE account_id = $1", [o.accountId])).toBeNull();
  expect(await d.db.first("SELECT 1 FROM refresh_tokens r JOIN sessions s ON s.id = r.session_id WHERE s.account_id = $1", [o.accountId])).toBeNull();
});

test("jobs drop sign-in rows a day after they expire, and rate counters a day old (minute and hour windows)", async () => {
  const { runJobs } = await import("../src/jobs.ts");
  const t = Math.floor(Date.now() / 1000), old = t - 2 * 86_400;
  await d.db.run("INSERT INTO email_codes (id, email, code_mac, created_at, expires_at) VALUES ('eml_old', 'old@example.com', 'x', $1, $1), ('eml_new', 'new@example.com', 'x', $2, $3)", [old, t, t + 600]);
  await d.db.run("INSERT INTO auth_nonces (hash, platform, flow, created_at, expires_at) VALUES ('h_old', 'ios', 'native', $1, $1)", [old]);
  await d.db.run("INSERT INTO passkey_challenges (id, challenge, mode, created_at, expires_at) VALUES ('pkc_old', 'c', 'authenticate', $1, $1)", [old]);
  const minute = Math.floor(t / 60), hour = Math.floor(t / 3600);
  await d.db.run("INSERT INTO rate_events (key, window_start, count) VALUES ('ip:a', $1, 1), ('ip:a', $2, 1), ('attest:a', $3, 1), ('attest:a', $4, 1)",
    [String(minute - 2000), String(minute), String(hour - 100), String(hour)]);
  await runJobs(d);
  expect((await d.db.all<{ id: string }>("SELECT id FROM email_codes WHERE id IN ('eml_old', 'eml_new')")).map((r) => r.id)).toEqual(["eml_new"]);
  expect(await d.db.first("SELECT 1 FROM auth_nonces WHERE hash = 'h_old'")).toBeNull();
  expect(await d.db.first("SELECT 1 FROM passkey_challenges WHERE id = 'pkc_old'")).toBeNull();
  expect((await d.db.all<{ window_start: string }>("SELECT window_start FROM rate_events WHERE key IN ('ip:a', 'attest:a') ORDER BY window_start")).map((r) => r.window_start).sort())
    .toEqual([String(minute), String(hour)].sort());
});

test("staging purges test owners older than a day with all their rows; production never does", async () => {
  const { purgeTestAccounts } = await import("../src/deletion.ts");
  const old = Math.floor(Date.now() / 1000) - 2 * 86_400;
  const mk = async (email: string, age: number) => {
    const o = await owner(d, { email });
    await d.db.run("UPDATE accounts SET created_at = $2 WHERE id = $1", [o.accountId, age]);
    await d.db.run("INSERT INTO methods (id, account_id, type, subject, email, created_at) VALUES ($1, $2, 'email', $3, $3, $4)", [`mth_${o.accountId.slice(5)}`, o.accountId, email, age]);
    await d.db.run("INSERT INTO deletion_requests (id, account_id, requested_at, effective_at, state) VALUES ($1, $2, 1, 2, 'pending')", [`del_${o.accountId.slice(5)}`, o.accountId]);
    return o;
  };
  const test1 = await mk("ass-e2e-1@test.openentity.org", old), young = await mk("ass-e2e-2@test.openentity.org", Math.floor(Date.now() / 1000)), real = await mk("person@example.com", old);
  const prod = { ...d, stage: "production" as const };
  expect(await purgeTestAccounts(prod)).toBe(0);
  expect(await d.db.first("SELECT 1 FROM accounts WHERE id = $1", [test1.accountId])).not.toBeNull();
  expect(await purgeTestAccounts(d)).toBe(1);
  for (const [table, col, v] of [["accounts", "id", test1.accountId], ["methods", "account_id", test1.accountId], ["sessions", "account_id", test1.accountId], ["deletion_requests", "account_id", test1.accountId], ["keylog_entries", "owner_id", test1.ownerDid.split(":o:")[1]]] as const) {
    expect(await d.db.first(`SELECT 1 FROM ${table} WHERE ${col} = $1`, [v]), table).toBeNull();
  }
  expect(await d.db.first("SELECT 1 FROM accounts WHERE id = $1", [young.accountId])).not.toBeNull(); // under a day
  expect(await d.db.first("SELECT 1 FROM accounts WHERE id = $1", [real.accountId])).not.toBeNull(); // not a test address
});
