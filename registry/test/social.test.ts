import { afterEach, describe, expect, it, vi } from "vitest";
import calendar from "../social/calendar.json" with { type: "json" };
import { configured, due, fill, linkFacets, postSocial, textFor, type Entry } from "../src/social.ts";
import { BANNED, BRAND } from "../src/video.ts";
import { E } from "./helpers.ts";

const stats = { entities: { total: 27, l2: 9 }, record_entries: 20, attestations: 34, observers: 1, log: { tree_size: 162 } };
const entry: Entry = { id: "t1", at: "2026-11-16T15:00:00Z", text: "Registry today: {total} entities. https://openentity.org" };
const NOW = new Date("2026-11-16T15:05:00Z");

afterEach(() => vi.unstubAllGlobals());

describe("social calendar", () => {
  it("has unique ids, valid times, no em dash, and no fields stats cannot fill", () => {
    const ids = calendar.map((e) => e.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const e of calendar as Entry[]) {
      expect(Number.isNaN(Date.parse(e.at))).toBe(false);
      expect(fill(e.text, stats)).not.toMatch(/\{\w+\}/);
      expect(e.text).not.toContain(String.fromCharCode(0x2014));
    }
  });

  it("lints the agentic commerce posts like a video script: no banned word, brand form or typed count", () => {
    const posts = (calendar as Entry[]).filter((e) => /^c\d-oe-/.test(e.id));
    expect(posts.length).toBeGreaterThanOrEqual(8);
    for (const e of posts) {
      expect(e.text, e.id).not.toMatch(BANNED);
      expect(e.text, e.id).not.toMatch(BRAND);
      expect(e.text.replace(/https?:\/\/\S+|\{\w+\}|x402|RFC 9421|\bL[0-3]\b/g, ""), e.id).not.toMatch(/\d/);
      expect(e.text, e.id).toMatch(/https:\/\/(openentity\.org|moltbotden\.com)/);
    }
  });

  it("is due for 24 hours from its time, and only then", () => {
    expect(due([entry], new Date("2026-11-16T14:59:00Z"))).toEqual([]);
    expect(due([entry], NOW)).toEqual([entry]);
    expect(due([entry], new Date("2026-11-17T15:00:00Z"))).toEqual([]);
  });

  it("keeps Instagram captions free of dead links and gives Bluesky byte-accurate link facets", () => {
    expect(textFor("instagram", "Spec is CC0. https://openentity.org")).toBe("Spec is CC0.\n\nopenentity.org");
    const t = "Ünïcode then https://openentity.org.";
    const [f] = linkFacets(t);
    expect(f!.features[0]!.uri).toBe("https://openentity.org");
    expect(new TextDecoder().decode(new TextEncoder().encode(t).slice(f!.index.byteStart, f!.index.byteEnd))).toBe("https://openentity.org");
  });

  it("skips a network without credentials", () => {
    expect(configured({})).toEqual([]);
    expect(configured({ BLUESKY_HANDLE: "h", BLUESKY_APP_PASSWORD: "p", META_TOKEN: "t", META_PAGE_ID: "1" })).toEqual(["facebook", "bluesky"]);
  });
});

describe("social send guard", () => {
  it("posts each entry once per network however often the cron ticks, with live numbers", async () => {
    const bodies: string[] = [];
    vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
      bodies.push(String(init?.body ?? ""));
      return Response.json(url.endsWith("createSession") ? { did: "did:plc:x", accessJwt: "j" } : { uri: `at://post/${bodies.length}` });
    }));
    const env = { ...E, BLUESKY_HANDLE: "openentity.org", BLUESKY_APP_PASSWORD: "pw" };
    await postSocial(env, stats, NOW, [entry]);
    await postSocial(env, stats, new Date(NOW.getTime() + 600_000), [entry]);
    expect(fetch).toHaveBeenCalledTimes(2); // one session, one post
    expect(JSON.parse(bodies[1]!).record.text).toContain("27 entities");
    const row = await env.db.first<{ status: string; ref: string }>("SELECT status, ref FROM social_posts WHERE entry_id = 't1' AND platform = 'bluesky'");
    expect(row).toEqual({ status: "posted", ref: "at://post/2" });
  });

  it("marks a failed send failed, does not retry it, and fails loud", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("bad", { status: 401 })));
    const env = { ...E, BLUESKY_HANDLE: "h", BLUESKY_APP_PASSWORD: "p" };
    const e2 = { ...entry, id: "t2" };
    await expect(postSocial(env, stats, NOW, [e2])).rejects.toThrow(/bluesky 401/);
    await postSocial(env, stats, new Date(NOW.getTime() + 600_000), [e2]);
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it("skips a Buffer channel that is not connected, without a failed row", async () => {
    vi.stubGlobal("fetch", vi.fn(async (_u: string, init?: RequestInit) => {
      const q = JSON.parse(String(init!.body)).query as string;
      return Response.json({ data: q.includes("organizations") ? { account: { organizations: [{ id: "o" }] } } : { channels: [{ id: "c1", service: "twitter" }] } });
    }));
    const e3 = { ...entry, id: "t3" };
    const env = { ...E, BUFFER_API_KEY: "k" };
    await expect(postSocial(env, stats, NOW, [{ ...e3 }]).catch((x) => String(x))).resolves.not.toMatch(/threads|linkedin/);
    expect(await env.db.first("SELECT 1 AS x FROM social_posts WHERE entry_id = 't3' AND platform IN ('threads', 'linkedin')")).toBeFalsy();
  });
});
