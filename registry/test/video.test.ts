import { afterEach, describe, expect, it, vi } from "vitest";
import { postVideo, captionFor, configuredVideo, pinBoard } from "../src/video-post.ts";
import { readFileSync } from "node:fs";
import { dueVideos, factProblems, LEVELS, lintScript, topicFor, TOPICS, variantFor, videoProps, videoTick, type Llm, type Mark, type Script, type VideoDeps } from "../src/video.ts";
import { E } from "./helpers.ts";

const stats = { entities: { total: 27, l2: 9 }, record_entries: 20, attestations: 34, observers: 1, log: { tree_size: 162 } };
const good: Script = {
  title: "Why agents lose their identity",
  caption: "An agent is only as persistent as the key it controls. Open Entity gives it one.",
  beats: [
    { say: "Your agent forgets who it is every time the key rotates or the model changes.", show: "Identity gone with the session" },
    { say: "Open Entity gives every agent one identifier it controls, signed by its own key, not by whoever hosts it.", show: "One key. One identifier." },
    { say: "Today the registry lists {total} entities, and every one of them can be checked locally by anyone.", show: "Live from the registry", stat: "total" },
    { say: "A model upgrade becomes an event in a signed record, not a new agent with no past.", show: "Upgrades are events" },
    { say: "Adopt in one command with no account and no wallet. Find it at open entity dot org.", show: "openentity.org" },
  ],
};
const words = (t: string): Mark[] => { let at = 0; return t.split(" ").map((v, i) => { const m = { time: i * 400, start: at, end: at + v.length, value: v }; at += v.length + 1; return m; }); };
const spokenOf = (s: Script) => s.beats.map((b) => b.say).join(" ");

describe("video topics and rotation", () => {
  it("has 30+ unique topics with no em dash and rotates through all of them before repeating", () => {
    expect(TOPICS.length).toBeGreaterThanOrEqual(30);
    expect(new Set(TOPICS.map((t) => t.id)).size).toBe(TOPICS.length);
    expect(JSON.stringify(TOPICS)).not.toContain(String.fromCharCode(0x2014));
    const seen = new Set<string>();
    for (let i = 0; i < TOPICS.length; i++) seen.add(topicFor(new Date(Date.UTC(2026, 11, 1 + i)).toISOString().slice(0, 10)).id);
    expect(seen.size).toBe(TOPICS.length);
    expect(topicFor("2026-12-01").id).not.toBe(topicFor("2026-12-02").id);
  });
  it("rotates three visual variants by date", () => {
    expect(new Set(["2026-12-01", "2026-12-02", "2026-12-03"].map(variantFor)).size).toBe(3);
    expect(variantFor("2026-12-01")).toBe(variantFor("2026-12-04"));
  });
});

describe("script lint", () => {
  it("passes a clean script", () => expect(lintScript(good)).toEqual([]));
  const bad = (f: (s: Script) => Script) => lintScript(f(structuredClone(good))).join("|");
  it("rejects dashes, typed counts, banned words, brand slips and unknown placeholders", () => {
    expect(bad((s) => ({ ...s, caption: `One key ${String.fromCharCode(0x2014)} one identity.` }))).toMatch(/dash/);
    expect(bad((s) => { s.beats[2]!.say = "Today the registry lists 27 entities, and every one of them can be checked locally by anyone."; return s; })).toMatch(/typed number/);
    expect(bad((s) => ({ ...s, caption: "The best identity for agents." }))).toMatch(/banned/);
    expect(bad((s) => ({ ...s, title: "OpenEntity for agents" }))).toMatch(/banned/);
    expect(bad((s) => ({ ...s, title: "OEIS explained" }))).toMatch(/banned/);
    expect(bad((s) => { s.beats[2]!.say += " {users}"; return s; })).toMatch(/unknown placeholder/);
    expect(bad((s) => ({ ...s, caption: "Read https://openentity.org now" }))).toMatch(/URL/);
  });
  it("rejects a script that is too short, has too many beats or an over-long headline", () => {
    expect(bad((s) => ({ ...s, beats: s.beats.slice(0, 2) }))).toMatch(/beats/);
    expect(bad((s) => { s.beats[0]!.show = "one two three four five six seven eight"; return s; })).toMatch(/7 words/);
    expect(bad((s) => { s.beats = s.beats.map((b) => ({ ...b, say: "Short." })); return s; })).toMatch(/words; needs/);
  });
});

describe("fact check", () => {
  // The L1-to-L2 error a real draft made: L2 needs an accredited observer's attestation, not L1.
  const wrong: Script = { ...good, beats: good.beats.map((b, i) => (i === 3 ? { ...b, say: "A signed attestation moves the agent from L1 to L2, a higher trust level in the Open Entity standard." } : b)) };
  it("rejects the L1 to L2 observer claim a real draft made", () => {
    expect(factProblems(wrong).join("|")).toMatch(/not a ladder/);
    expect(lintScript(wrong).join("|")).toMatch(/not a ladder/);
  });
  it("rejects a wrong level name and typed counts in words, and passes a correct level claim", () => {
    const say = (t: string): Script => ({ ...good, caption: t });
    expect(factProblems(say("L2 means the agent is Verified."))).toEqual(["L2 is Observed, not Verified"]);
    expect(factProblems(say("An observer attests and the agent shows as L2 Observed. Open Entity lists seven entities."))).toEqual(["typed count in words: counts come only from the placeholders"]);
    expect(factProblems(say("L2 means an accredited observer has attested to the agent's record."))).toEqual([]);
  });
  it("keeps the level table equal to spec/OEIS-1.md section 2.2", () => {
    const spec = readFileSync(new URL("../../spec/OEIS-1.md", import.meta.url), "utf8");
    for (const [l, v] of Object.entries(LEVELS)) expect(spec).toMatch(new RegExp(`\\| ${l} \\| ${v.name} \\|`));
  });
  it("stops a script the judge rejects for an unsupported claim from being rendered", async () => {
    const { attempt } = await import("../src/video.ts");
    const llm: Llm = { draft: async () => good, judge: async (_s, t) => ({ score: 1, reason: `unsupported claim, topic ${t.id}` }) };
    expect(await attempt(llm, TOPICS[0]!, [])).toEqual({ problems: ["an editor scored the last draft 1 of 10: unsupported claim, topic problem"] });
  });
});

describe("video props", () => {
  const text = spokenOf(good);
  it("times beats from the voice marks and fills numbers from stats", () => {
    const p = videoProps(good, words(text), "https://a/x.mp3", stats, "2026-12-01");
    expect(p.beats).toHaveLength(5);
    expect(p.beats[0]!.from).toBe(0);
    expect(p.beats[1]!.from).toBeGreaterThan(p.beats[0]!.from);
    expect(p.beats.at(-1)!.to).toBe(p.durationSec);
    expect(p.beats[2]!.stat).toEqual({ value: "27", label: "entities" });
    expect(p.durationSec).toBeGreaterThanOrEqual(20);
    expect(p.variant).toBe(variantFor("2026-12-01"));
  });
  it("refuses a voiceover longer than 40 seconds", () => {
    const slow = words(text).map((m) => ({ ...m, time: m.time * 3 }));
    expect(() => videoProps(good, slow, "u", stats, "2026-12-01")).toThrow(/over 40/);
  });
});

function deps(over: Partial<{ scores: number[]; progress: { done: boolean; error?: string }[] }> = {}) {
  const scores = [...(over.scores ?? [8])], progress = [...(over.progress ?? [{ done: true }])];
  const calls = { draft: 0, judge: 0, voice: 0, start: 0 };
  const d: VideoDeps = {
    llm: { draft: async () => (calls.draft++, good), judge: async (_s, _t) => (calls.judge++, { score: scores.shift() ?? 8, reason: "tighten the hook" }) } as Llm,
    voice: async (t) => (calls.voice++, { audio: "https://b/a.mp3", marks: words(t) }),
    render: { start: async (_p, day) => (calls.start++, { id: "r1", bucket: "bkt", url: `https://bkt/renders/r1/${day}.mp4` }), progress: async () => progress.shift() ?? { done: true } },
  };
  return { d, calls };
}
const NOW = new Date("2026-12-01T06:00:00Z");
const row = (day: string) => E.db.first<{ status: string; tries: number; url: string | null; script: string | null }>("SELECT status, tries, url, script FROM social_videos WHERE day = $1", [day]);
const tick = (d: VideoDeps, at = NOW) => videoTick(E, stats, at, d);

describe("render-ahead scheduling", () => {
  it("moves a day through script, render and ready one step per tick, then starts tomorrow", async () => {
    const { d, calls } = deps();
    await tick(d); expect((await row("2026-12-01"))!.status).toBe("scripted");
    await tick(d); const r = (await row("2026-12-01"))!;
    expect(r.status).toBe("rendering");
    expect(JSON.parse(r.script!).beats[2].say).toContain("27 entities"); // numbers filled from stats at render time
    await tick(d); expect((await row("2026-12-01"))!.status).toBe("ready");
    await tick(d); expect((await row("2026-12-02"))!.status).toBe("scripted"); // the next day is rendered ahead of its post time
    await tick(d); await tick(d); await tick(d);
    await tick(d); expect(calls.start).toBe(2); // both days done: nothing more to do
    expect(calls.draft).toBe(2);
  });
  it("skips a day whose script never passes the judge, without rendering it", async () => {
    const { d, calls } = deps({ scores: [4, 5, 6, 6.4] });
    const at = new Date("2026-12-10T06:00:00Z");
    for (let i = 0; i < 4; i++) await tick(d, at);
    expect((await row("2026-12-10"))!.status).toBe("skipped");
    expect(calls.start).toBe(0);
  });
  it("retries a failed render from the stored script and fails loud after four tries", async () => {
    const { d, calls } = deps({ progress: Array(4).fill({ done: false, error: "boom" }) });
    const at = new Date("2026-12-20T06:00:00Z");
    await tick(d, at); await tick(d, at); await tick(d, at); // scripted, rendering, error
    expect((await row("2026-12-20"))!.status).toBe("scripted");
    let err = "";
    for (let i = 0; i < 12 && !err; i++) await tick(d, at).catch((e) => (err = e.message));
    expect(err).toMatch(/video 2026-12-20: render: boom/);
    expect((await row("2026-12-20"))!.status).toBe("failed");
    expect(calls.draft).toBe(1);
    expect(calls.start).toBe(4);
  });
});

describe("video posting", () => {
  afterEach(() => vi.unstubAllGlobals());
  const day = "2026-12-30";
  const at = new Date(`${day}T16:05:00Z`);
  const seed = async (id = day, status = "ready") => {
    await E.db.run("INSERT INTO social_videos (day, topic, status, script, url, at) VALUES ($1, 'x', $2, $3, $4, 'now') ON CONFLICT DO NOTHING", [id, status, JSON.stringify(good), `https://bkt/renders/r1/${id}.mp4`]);
  };
  const env = { ...E, META_TOKEN: "t", META_PAGE_ID: "p", META_IG_USER_ID: "ig", ZERNIO_API_KEY: "z", BUFFER_API_KEY: "b", VIDEO_POSTING: "on" };
  type Call = { url: string; init?: RequestInit; body: string };
  function mock(over: (c: Call) => unknown = () => undefined) {
    const calls: Call[] = [];
    vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
      const c = { url, init, body: String(init?.body ?? "") };
      calls.push(c);
      const o = over(c); if (o !== undefined) return o instanceof Response ? o : Response.json(o);
      if (url.includes("?fields=access_token")) return Response.json({ access_token: "pt" });
      if (url.includes("video_reels") && c.body.includes("start")) return Response.json({ video_id: "v1", upload_url: "https://rupload/v1" });
      if (url.startsWith("https://rupload")) return Response.json({ success: true });
      if (url.endsWith("/media")) return Response.json({ id: "c1" });
      if (url.includes("fields=status_code")) return Response.json({ status_code: "FINISHED" });
      if (url.endsWith("media_publish")) return Response.json({ id: "m1" });
      if (url.endsWith("/accounts")) return Response.json({ accounts: [{ _id: "a-tt", platform: "tiktok" }, { _id: "a-yt", platform: "youtube" }] });
      if (url.endsWith("/posts")) return Response.json({ post: { _id: "zp" } });
      if (url === "https://api.buffer.com") {
        const q = JSON.parse(c.body).query as string;
        return Response.json({ data: q.includes("organizations") ? { account: { organizations: [{ id: "o" }] } } : q.includes("boards") ? { channel: { metadata: { boards: [{ serviceId: "b1", name: "Open Entity" }, { serviceId: "b2", name: "Videos" }] } } } : q.includes("channels(") ? { channels: [{ id: "ch", service: "pinterest" }] } : { createPost: { post: { id: "bp" } } } });
      }
      return Response.json({ id: "x" });
    }));
    return calls;
  }
  const refs = () => E.db.all<{ platform: string; status: string; ref: string }>("SELECT platform, status, ref FROM social_posts WHERE entry_id = $1 ORDER BY platform", [`video-${day}`]);

  it("is due from 16:00 UTC for 24 hours, and only when rendered", async () => {
    await seed(); await seed("2026-12-29", "rendering");
    expect((await dueVideos(E, new Date(`${day}T15:59:00Z`))).map((v) => v.day)).not.toContain(day);
    expect((await dueVideos(E, at)).map((v) => v.day)).toEqual([day]);
    expect(await dueVideos(E, new Date("2026-12-31T16:00:00Z"))).toEqual([]);
  });

  it("sends every network its request shape, and never posts twice however often the cron ticks", async () => {
    await seed();
    const calls = mock();
    await postVideo(env, at);
    // Instagram made its container and waits; the other four are posted.
    expect(await refs()).toEqual([
      { platform: "facebook_reel", status: "posted", ref: "v1" }, { platform: "instagram_reel", status: "processing", ref: "c1" },
      { platform: "pinterest", status: "posted", ref: "bp" }, { platform: "tiktok", status: "posted", ref: "zp" }, { platform: "youtube", status: "posted", ref: "zp" },
    ]);
    const ig = calls.find((c) => c.url.endsWith("ig/media"))!;
    expect(Object.fromEntries(new URLSearchParams(ig.body))).toMatchObject({ media_type: "REELS", video_url: `https://bkt/renders/r1/${day}.mp4`, share_to_feed: "true" });
    expect(Object.fromEntries(new URLSearchParams(ig.body)).caption).toContain("openentity.org");
    const fb = calls.find((c) => c.url.includes("p/video_reels") && c.body.includes("finish"))!;
    expect(Object.fromEntries(new URLSearchParams(fb.body))).toMatchObject({ upload_phase: "finish", video_state: "PUBLISHED", video_id: "v1", access_token: "pt" });
    expect(calls.find((c) => c.url.startsWith("https://rupload"))!.init!.headers).toMatchObject({ file_url: `https://bkt/renders/r1/${day}.mp4`, Authorization: "OAuth pt" });
    const posts = calls.filter((c) => c.url.endsWith("/posts")).map((c) => JSON.parse(c.body));
    expect(posts[0]).toMatchObject({ publishNow: true, mediaItems: [{ type: "video", url: `https://bkt/renders/r1/${day}.mp4` }], platforms: [{ platform: "tiktok", accountId: "a-tt" }], tiktokSettings: { video_made_with_ai: true } });
    expect(posts[1].platforms[0]).toMatchObject({ platform: "youtube", accountId: "a-yt", platformSpecificData: { title: good.title, madeForKids: false } });
    expect(posts[1].content).toContain("#Shorts");
    const pin = JSON.parse(calls.filter((c) => c.url === "https://api.buffer.com").at(-1)!.body).variables.input;
    expect(pin).toMatchObject({ channelId: "ch", assets: [{ video: { url: `https://bkt/renders/r1/${day}.mp4` } }], metadata: { pinterest: { boardServiceId: "b2", title: good.title } } });
    const sent = calls.length;
    // Next ticks: Instagram's container finishes and is published once; nothing else is sent again.
    await postVideo(env, new Date(at.getTime() + 600_000));
    await postVideo(env, new Date(at.getTime() + 1200_000));
    expect((await refs()).find((r) => r.platform === "instagram_reel")).toMatchObject({ status: "posted", ref: "m1" });
    const after = calls.slice(sent);
    expect(after.filter((c) => c.url.endsWith("ig/media")).length).toBe(0);
    expect(after.filter((c) => c.url.endsWith("media_publish")).length).toBe(1);
    expect(after.filter((c) => c.url.endsWith("/posts") || c.url.includes("video_reels") || c.url === "https://api.buffer.com").length).toBe(0);
  });

  it("posts nothing until VIDEO_POSTING is on", async () => {
    await seed("2027-02-01");
    const calls = mock();
    await postVideo({ ...env, VIDEO_POSTING: undefined }, new Date("2027-02-01T16:05:00Z"));
    expect(calls).toEqual([]);
  });

  it("skips a network without credentials or a connected channel instead of failing it", async () => {
    await seed("2026-12-31", "ready");
    const d2 = "2026-12-31", t2 = new Date(`${d2}T16:05:00Z`);
    const calls = mock((c) => (c.url.endsWith("/accounts") ? { accounts: [] } : undefined));
    await postVideo({ ...E, ZERNIO_API_KEY: "z", VIDEO_POSTING: "on" }, t2);
    expect(calls.map((c) => c.url)).toEqual(["https://zernio.com/api/v1/accounts", "https://zernio.com/api/v1/accounts"]);
    expect(await E.db.first("SELECT 1 AS x FROM social_posts WHERE entry_id = $1", [`video-${d2}`])).toBeFalsy();
    expect(configuredVideo({})).toEqual([]);
    expect(configuredVideo({ BUFFER_API_KEY: "b" })).toEqual(["pinterest"]);
  });

  it("marks a failed send failed and does not retry it", async () => {
    await seed("2027-01-02");
    const t3 = new Date("2027-01-02T16:05:00Z");
    const calls = mock((c) => (c.url.endsWith("/posts") ? new Response("nope", { status: 401 }) : undefined));
    const only = { ...E, ZERNIO_API_KEY: "z", VIDEO_POSTING: "on" };
    await expect(postVideo(only, t3)).rejects.toThrow(/tiktok.*zernio 401/);
    const n = calls.length;
    await expect(postVideo(only, new Date(t3.getTime() + 600_000))).resolves.toBeUndefined();
    expect(calls.length).toBe(n);
  });

  it("keeps captions free of dead links on Instagram and picks the video board for pins", () => {
    expect(captionFor("instagram_reel", good)).not.toMatch(/https?:/);
    expect(captionFor("youtube", good)).toContain("https://openentity.org");
    expect(pinBoard([{ serviceId: "1", name: "Open Entity" }, { serviceId: "2", name: "Video pins" }])).toBe("2");
    expect(pinBoard([{ serviceId: "1", name: "Open Entity" }])).toBe("1");
  });
});
