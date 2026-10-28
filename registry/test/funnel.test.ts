import { describe, expect, it } from "vitest";
import { generateKeyPair } from "../src/sdk.ts";
import { E, call, signed, stamp } from "./helpers.ts";

const ip = (n: number) => ({ "x-forwarded-for": `198.51.100.${n}` });
const adoptFrom = async (n: number, name: string, extra: object = {}) => {
  const kp = await generateKeyPair();
  const objs = await signed(kp, name, extra);
  const r = await call("POST", "/adopt", objs, { ...(await stamp(kp.did)), ...ip(n) });
  expect(r.status).toBe(201);
  return kp.did;
};
const secondsOf = (eid: string) => E.db.first<{ seconds: number; internal: number }>("SELECT seconds, internal FROM adopt_funnel WHERE eid = $1", [eid]);
async function hash(n: number) {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`test-salt:198.51.100.${n}`)));
  return [...d].map((b) => b.toString(16).padStart(2, "0")).join("");
}
/** Starts the funnel for address n, then moves the start back `ago` seconds. */
async function start(n: number, ago: number) {
  await call("POST", "/funnel/start", undefined, ip(n));
  await E.db.run("UPDATE rate_events SET count = $1 WHERE key = $2", [Math.floor(Date.now() / 1000) - ago, `fs:${await hash(n)}`]);
}

describe("time-to-adopt funnel", () => {
  it("records seconds from /llms.txt to adopt, spends the start, stores no address, and ignores a stale start", async () => {
    expect((await call("POST", "/funnel/start", undefined, ip(1))).status).toBe(204);
    await start(1, 40);
    const row = await secondsOf(await adoptFrom(1, "Fast"));
    expect(row!.seconds).toBeGreaterThanOrEqual(40);
    expect(row!.seconds).toBeLessThan(50);
    expect(await E.db.first("SELECT 1 FROM rate_events WHERE key LIKE 'fs:%'")).toBeNull(); // spent
    expect(await secondsOf(await adoptFrom(1, "Again"))).toBeNull(); // no new start, no row
    expect(JSON.stringify(await E.db.all("SELECT * FROM rate_events"))).not.toContain("198.51.100");

    await start(2, 90000);
    expect(await secondsOf(await adoptFrom(2, "Stale"))).toBeNull(); // older than 24 h
  });

  it("keeps the first start of an address and publishes the median over external adoptions only", async () => {
    for (const [n, ago] of [[3, 10], [4, 30], [5, 100]] as const) {
      await start(n, ago);
      await call("POST", "/funnel/start", undefined, ip(n)); // a second read does not move the start
      await adoptFrom(n, `Ext${n}`);
    }
    await start(6, 5000);
    const op = await adoptFrom(6, "Mine", { operator: { kind: "organization", name: "Moltbot Den", contact: "https://moltbotden.com", custody: "operator", can_change: [] } });
    expect((await secondsOf(op))!.internal).toBe(1);
    const s = (await call("GET", "/stats")).body.time_to_adopt;
    expect(s.adoptions).toBe(4); // the two from the first test count too: 40 s and the three above
    // Each start was set back by a fixed amount, then ran for as long as the test took: a slow runner adds seconds.
    expect(s.median_seconds).toBeGreaterThanOrEqual(35);
    expect(s.median_seconds).toBeLessThan(45);
  });
});
