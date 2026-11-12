import { afterEach, expect, test, vi } from "vitest";
import { createApp } from "../src/app.ts";
import { now } from "../src/db.ts";
import { runJobs } from "../src/jobs.ts";
import { push } from "../src/notify.ts";
import { caller, signIn, testDeps } from "./helpers.ts";

// The CloudWatch embedded metric lines the Monitoring lane's alarms read (DAY-4-monitoring.md in the meta repo).
const d = await testDeps({ web: { apns: async (t) => (t.token === "good" ? null : t.token === "dead" ? "gone" : "BadDeviceToken") } });
const call = caller(createApp(d));
afterEach(() => vi.restoreAllMocks());
const metricLines = (log: { mock: { calls: unknown[][] } }) =>
  log.mock.calls.map((c) => { try { return JSON.parse(String(c[0])); } catch { return null; } }).filter((x) => x?._aws);

test("push: one PushSent or PushFailed data point per delivery attempt, none where no provider is set up", async () => {
  const email = `metrics-${Date.now()}@example.com`; // three installs: an address gets three codes an hour
  const installs: string[] = [];
  for (let i = 0; i < 3; i++) installs.push((await signIn(call, d, email)).install);
  const { account_id: accountId } = (await d.db.first<{ account_id: string }>("SELECT account_id FROM sessions WHERE install_id = $1", [installs[0]]))!;
  const t = now();
  for (const [i, token] of ["good", "bad"].entries()) {
    await d.db.run("INSERT INTO push_tokens (install_id, account_id, provider, token, environment, created_at, updated_at) VALUES ($1, $2, 'apns', $3, 'sandbox', $4, $4)", [installs[i], accountId, token, t]);
  }
  await d.db.run("INSERT INTO push_tokens (install_id, account_id, provider, token, environment, created_at, updated_at) VALUES ($1, $2, 'fcm', 'android', NULL, $3, $3)", [installs[2], accountId, t]);
  const log = vi.spyOn(console, "log").mockImplementation(() => {});
  vi.spyOn(console, "warn").mockImplementation(() => {});
  expect(await push(d, accountId, { sender: "did:web:moltbotden.com", type: "alert", id: "a1" })).toBe(1);
  const lines = metricLines(log);
  expect(lines).toHaveLength(2); // the FCM token is skipped until FCM exists: no attempt, no data point
  for (const l of lines) expect(l).toMatchObject({ Stage: "staging", _aws: { CloudWatchMetrics: [{ Namespace: "OpenEntity/Account", Dimensions: [["Stage"]], Metrics: [{ Name: "PushSent", Unit: "Count" }, { Name: "PushFailed", Unit: "Count" }] }] } });
  expect(lines.map((l) => [l.PushSent, l.PushFailed]).sort()).toEqual([[0, 1], [1, 0]]);
});

test("jobs: PendingRecoveriesMax on every tick, the most one owner has in flight, cancelled and taken-effect ones left out", async () => {
  const t = now(), day = 86_400;
  const entry = (owner: string, seq: number, op: string, seen: number, body: object = {}) =>
    d.db.run("INSERT INTO keylog_entries (owner_id, seq, line, hash, op, first_seen_at, effective_at) VALUES ($1, $2, $3, $4, $5, $6, $7)",
      [owner, seq, JSON.stringify({ op, body }), `${owner}-${seq}`, op, seen, op === "recover" ? seen + day : seen]);
  await entry("ownera", 1, "recover", t - 2 * day); // took effect a day ago
  await entry("ownera", 2, "recover", t - 300);
  await entry("ownera", 3, "recover", t - 200);
  await entry("ownera", 4, "recover", t - 100);
  await entry("ownera", 5, "cancel", t - 50, { target: "ownera-4" });
  await entry("ownerb", 1, "recover", t - 60);
  const tick = async () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    await runJobs(d);
    const l = metricLines(log).filter((x) => "PendingRecoveriesMax" in x);
    log.mockRestore();
    return l;
  };
  expect(await tick()).toMatchObject([{ Stage: "staging", PendingRecoveriesMax: 2, _aws: { CloudWatchMetrics: [{ Metrics: [{ Name: "PendingRecoveriesMax", Unit: "Count" }] }] } }]);
  await d.db.run("DELETE FROM keylog_entries WHERE owner_id IN ('ownera', 'ownerb')");
  expect((await tick()).map((l) => l.PendingRecoveriesMax)).toEqual([0]);
});
