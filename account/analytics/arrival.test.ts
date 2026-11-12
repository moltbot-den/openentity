// Staging arrival test (PLAN 13.2): one tagged event per loop must reach Amplitude, GA4 and PostHog within 30 minutes.
// Skipped unless ARRIVAL=1. Credentials come from the environment (never committed); see arrival.env.example.
//   ARRIVAL=1 AMPLITUDE_API_KEY=... AMPLITUDE_SECRET_KEY=... POSTHOG_KEY=... POSTHOG_PERSONAL_KEY=... POSTHOG_PROJECT_ID=...
//   GA4_MEASUREMENT_ID=... GA4_API_SECRET=... GA4_PROPERTY_ID=... GA4_ACCESS_TOKEN=... pnpm test arrival
import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { sendAmplitude, sendGa4, sendPosthog, type Keys } from "./forwarder/senders.ts";
import type { QueuedEvent } from "./src/validate.ts";

const e = process.env;
const on = e.ARRIVAL === "1";
const run = `arrival-${Date.now()}`;
const base = (event: QueuedEvent["event"], props: QueuedEvent["props"] = {}): QueuedEvent => ({
  event, props, event_id: randomUUID(), ts_ms: Date.now(), user_id: run, install_id: run, platform: "server", app_version: "arrival",
});
// One event per loop of PLAN 13.2.
const LOOPS: QueuedEvent[] = [
  base("app_first_opened"),
  base("sign_in_completed", { method: "passkey", new_account: true }),
  base("pair_confirmed", { permissions_count: 1, seconds_from_code: 5 }),
  base("approval_decided", { decision: "approved", product: "openentity", kind: "arrival", risk: "low", seconds_to_decide: 3, number_match: false, form: "arrival" }),
  base("agent_message_sent", { has_attachment: false }),
  base("purchase_completed", { sku: "arrival", rail: "stripe", price_usd: 1, storefront: "US" }),
  base("app_opened"),
  base("entity_viewed"),
];
const keys: Keys = {
  amplitudeApiKey: e.AMPLITUDE_API_KEY ?? "", posthogKey: e.POSTHOG_KEY ?? "", posthogHost: e.POSTHOG_HOST,
  ga4MeasurementId: e.GA4_MEASUREMENT_ID ?? "", ga4ApiSecret: e.GA4_API_SECRET ?? "",
};
const names = LOOPS.map((x) => x.event).sort();
const poll = async (fn: () => Promise<string[]>) => {
  const deadline = Date.now() + 30 * 60_000;
  let got: string[] = [];
  while (Date.now() < deadline) {
    got = await fn().catch(() => []);
    if (names.every((n) => got.includes(n))) return got;
    await new Promise((r) => setTimeout(r, 30_000));
  }
  return got;
};

describe.skipIf(!on)("arrival in staging", () => {
  it("sends every loop to all three tools", async () => {
    await Promise.all([sendAmplitude(fetch, keys, LOOPS), sendPosthog(fetch, keys, LOOPS), sendGa4(fetch, keys, LOOPS)]);
  });

  it.skipIf(!e.AMPLITUDE_SECRET_KEY)("Amplitude: Dashboard REST user activity shows all loops", async () => {
    const auth = "Basic " + Buffer.from(`${e.AMPLITUDE_API_KEY}:${e.AMPLITUDE_SECRET_KEY}`).toString("base64");
    const got = await poll(async () => {
      const s = await (await fetch(`https://amplitude.com/api/2/usersearch?user=${run}`, { headers: { authorization: auth } })).json();
      const id = s.matches?.[0]?.amplitude_id;
      if (!id) return [];
      const a = await (await fetch(`https://amplitude.com/api/2/useractivity?user=${id}`, { headers: { authorization: auth } })).json();
      return (a.events ?? []).map((x: { event_type: string }) => x.event_type);
    });
    expect(names.filter((n) => !got.includes(n))).toEqual([]);
  }, 31 * 60_000);

  it.skipIf(!e.POSTHOG_PERSONAL_KEY)("PostHog: query API shows all loops", async () => {
    const host = e.POSTHOG_HOST ?? "https://us.posthog.com";
    const got = await poll(async () => {
      const r = await (await fetch(`${host.replace("i.posthog", "posthog")}/api/projects/${e.POSTHOG_PROJECT_ID}/query/`, {
        method: "POST", headers: { authorization: `Bearer ${e.POSTHOG_PERSONAL_KEY}`, "content-type": "application/json" },
        body: JSON.stringify({ query: { kind: "HogQLQuery", query: `select distinct event from events where distinct_id = '${run}'` } }),
      })).json();
      return (r.results ?? []).map((x: string[]) => x[0]);
    });
    expect(names.filter((n) => !got.includes(n))).toEqual([]);
  }, 31 * 60_000);

  it.skipIf(!e.GA4_ACCESS_TOKEN)("GA4: Data API realtime report on the staging-only property shows all loops", async () => {
    const got = await poll(async () => {
      const r = await (await fetch(`https://analyticsdata.googleapis.com/v1beta/properties/${e.GA4_PROPERTY_ID}:runRealtimeReport`, {
        method: "POST", headers: { authorization: `Bearer ${e.GA4_ACCESS_TOKEN}`, "content-type": "application/json" },
        body: JSON.stringify({ dimensions: [{ name: "eventName" }], metrics: [{ name: "eventCount" }], minuteRanges: [{ startMinutesAgo: 29, endMinutesAgo: 0 }] }),
      })).json();
      return (r.rows ?? []).map((x: { dimensionValues: { value: string }[] }) => x.dimensionValues[0].value);
    });
    expect(names.filter((n) => !got.includes(n))).toEqual([]);
  }, 31 * 60_000);
});
