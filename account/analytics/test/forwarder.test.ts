import type { SQSEvent } from "aws-lambda";
import { describe, expect, it, vi } from "vitest";
import { ga4Requests } from "../forwarder/senders.ts";
import { keysFrom, makeHandler } from "../forwarder/handler.ts";

const keys = keysFrom(
  Object.fromEntries(["amplitude_api_key", "posthog_key", "ga4_measurement_id", "ga4_api_secret"].map((k) => [`analytics_${k}_staging`, `test-${k}`])),
  "staging",
);
const ev = (i: number, install = "inst-1", over: object = {}) => ({
  event: "app_opened", props: {}, event_id: `00000000-0000-4000-8000-${String(i).padStart(12, "0")}`, ts_ms: 1790000000000 + i, install_id: install, platform: "ios", ...over,
});
const sqs = (...bodies: unknown[]): SQSEvent => ({ Records: bodies.map((b, i) => ({ messageId: `m${i}`, body: typeof b === "string" ? b : JSON.stringify(b) })) as SQSEvent["Records"] });
const run = (e: SQSEvent, fetchImpl: typeof fetch) => makeHandler({ getKeys: async () => keys, fetch: fetchImpl, log: () => {} })(e);
const ok = () => vi.fn(async (_u: unknown, _i?: RequestInit) => new Response("{}", { status: 200 }));

describe("forwarder", () => {
  it("sends each event to Amplitude, PostHog and GA4 with idempotency ids", async () => {
    const f = ok();
    const r = await run(sqs(ev(1)), f as unknown as typeof fetch);
    expect(r.batchItemFailures).toEqual([]);
    const urls = f.mock.calls.map((c) => String(c[0]));
    expect(urls).toEqual(expect.arrayContaining([expect.stringContaining("amplitude.com/2/httpapi"), expect.stringContaining("/batch/"), expect.stringContaining("google-analytics.com/mp/collect")]));
    const bodies = f.mock.calls.map((c) => JSON.parse(String((c[1] as RequestInit).body)));
    const amp = bodies.find((b) => b.events?.[0]?.insert_id);
    expect(amp.events[0]).toMatchObject({ event_type: "app_opened", insert_id: ev(1).event_id, device_id: "inst-1" });
    expect(bodies.find((b) => b.batch).batch[0].uuid).toBe(ev(1).event_id);
  });

  it("never sends more than 25 events per GA4 request", () => {
    const reqs = ga4Requests(Array.from({ length: 60 }, (_, i) => ev(i)) as never);
    expect(reqs.map((r) => r.events.length)).toEqual([25, 25, 10]);
  });

  it("fails every record when a destination fails, so SQS retries", async () => {
    const f = vi.fn(async (u: unknown, _i?: RequestInit) => new Response("", { status: String(u).includes("posthog") ? 500 : 200 }));
    const r = await run(sqs(ev(1), ev(2, "inst-2")), f as unknown as typeof fetch);
    expect(r.batchItemFailures.map((x) => x.itemIdentifier).sort()).toEqual(["m0", "m1"]);
  });

  it("a GA4 failure retries only that client's records", async () => {
    let n = 0;
    const f = vi.fn(async (u: unknown, _i?: RequestInit) => new Response("", { status: String(u).includes("google-analytics") && n++ === 0 ? 503 : 200 }));
    const r = await run(sqs(ev(1, "inst-1"), ev(2, "inst-2")), f as unknown as typeof fetch);
    expect(r.batchItemFailures).toHaveLength(1);
  });

  it("rejects an event that is not in events.yaml and still delivers the valid ones", async () => {
    const f = ok();
    const r = await run(sqs(ev(1), ev(2, "inst-1", { event: "made_up" }), ev(3, "inst-1", { props: { email: "a@b.co" } }), "not json"), f as unknown as typeof fetch);
    expect(r.batchItemFailures.map((x) => x.itemIdentifier).sort()).toEqual(["m1", "m2", "m3"]);
    const amp = f.mock.calls.map((c) => JSON.parse(String((c[1] as RequestInit).body))).find((b) => b.events?.[0]?.insert_id);
    expect(amp.events).toHaveLength(1);
  });

  it("fails when the secret lacks a key", () => {
    expect(() => keysFrom({}, "production")).toThrow(/analytics_amplitude_api_key_prod/);
  });
});
