import { afterEach, describe, expect, it, vi } from "vitest";
import { buildDigest, dueSlot, sendDigest } from "../src/digest.ts";
import { E } from "./helpers.ts";

const stats = { entities: { total: 7 }, record_entries: 40, attestations: 3, observers: 2, log: { tree_size: 99 } };
const env = { ...E, CIO_APP_API_KEY: "app-key", CIO_BROADCAST_ID: "3" };
const MON = new Date("2026-11-02T14:05:00Z"); // Monday, past 14:00 UTC

afterEach(() => vi.unstubAllGlobals());

describe("weekly digest slot", () => {
  it("opens Monday 14:00 UTC and stays the same slot until the next Monday", () => {
    expect(dueSlot(new Date("2026-11-02T13:59:00Z"))).toBeNull(); // slot not open yet
    expect(dueSlot(MON)).toBe("2026-11-02");
    expect(dueSlot(new Date("2026-11-08T23:59:00Z"))).toBe("2026-11-02");
  });
});

describe("digest content", () => {
  it("is built from the stats object, strips control characters, and has no em dash", () => {
    const d = buildDigest(stats, { entities: 2, record_entries: 5, log: 9, recent: [{ eid: "did:web:a.example", name: "Ag\u0000ent", level: 1 }] }, "2026-11-02");
    expect(d).toMatchObject({ entities_total: 7, entities_change: 2, record_entries_total: 40, log_size: 99, log_size_change: 9, attestations_total: 3, observers_total: 2 });
    expect(d.recent).toEqual([{ name: "Ag ent", level: "L1", url: "https://openentity.org/entities/did%3Aweb%3Aa.example" }]);
    expect(JSON.stringify(d)).not.toContain(String.fromCharCode(0x2014));
  });
});

describe("digest send guard", () => {
  it("sends once per slot however often the cron ticks, and again the next week", async () => {
    const fetchMock = vi.fn(async () => new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    expect(await sendDigest(env, stats, MON)).toBe(true);
    expect(await sendDigest(env, stats, new Date(MON.getTime() + 600_000))).toBe(false);
    expect(await sendDigest(env, stats, new Date(MON.getTime() + 3 * 86400_000))).toBe(false);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("https://api.customer.io/v1/campaigns/3/triggers");
    expect((init.headers as Record<string, string>).authorization).toBe("Bearer app-key");
    expect(JSON.parse(init.body as string).data.entities_total).toBe(7);
    expect(await sendDigest(env, stats, new Date(MON.getTime() + 7 * 86400_000))).toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("releases the slot when Customer.io refuses, so the next tick retries", async () => {
    const fetchMock = vi.fn(async () => new Response("no", { status: 500 }));
    vi.stubGlobal("fetch", fetchMock);
    const later = new Date(MON.getTime() + 14 * 86400_000);
    await expect(sendDigest(env, stats, later)).rejects.toThrow(/500/);
    fetchMock.mockImplementation(async () => new Response("{}", { status: 200 }));
    expect(await sendDigest(env, stats, later)).toBe(true);
  });

  it("does nothing without a broadcast id", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    expect(await sendDigest({ ...env, CIO_BROADCAST_ID: undefined }, stats, new Date("2026-12-07T15:00:00Z"))).toBe(false);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
