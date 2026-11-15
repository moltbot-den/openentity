// Social publisher: posts registry/social/calendar.json to every network whose credentials are in /openentity/app.
// Same publishers as the One Frequency United feed: Meta Graph (Facebook, Instagram), Buffer (X, Threads, LinkedIn),
// atproto (Bluesky). Each entry goes out once per network inside a 24 hour window after its time.
import type { Env } from "./env.ts";
import calendar from "../social/calendar.json" with { type: "json" };

export const PLATFORMS = ["facebook", "instagram", "x", "threads", "linkedin", "bluesky"] as const;
export type Platform = (typeof PLATFORMS)[number];
export type Entry = { id: string; at: string; text: string; image?: string };
export type Stats = { entities: { total: number; l2: number }; record_entries: number; attestations: number; observers: number; log: { tree_size: number } };
type Creds = Pick<Env, "META_TOKEN" | "META_PAGE_ID" | "META_IG_USER_ID" | "BUFFER_API_KEY" | "BLUESKY_HANDLE" | "BLUESKY_APP_PASSWORD">;

const WINDOW_MS = 24 * 3600_000;
const IMAGE = "https://openentity.org/og.jpg"; // Instagram takes JPEG only and needs an image on every post
const GRAPH = "https://graph.facebook.com/v26.0";
const BUFFER_SERVICE = { x: "twitter", threads: "threads", linkedin: "linkedin" } as const;

export const configured = (c: Creds): Platform[] =>
  PLATFORMS.filter((p) => ({
    facebook: c.META_TOKEN && c.META_PAGE_ID,
    instagram: c.META_TOKEN && c.META_IG_USER_ID,
    x: c.BUFFER_API_KEY, threads: c.BUFFER_API_KEY, linkedin: c.BUFFER_API_KEY,
    bluesky: c.BLUESKY_HANDLE && c.BLUESKY_APP_PASSWORD,
  })[p]);

export const due = (entries: Entry[], now: Date) =>
  entries.filter((e) => { const t = Date.parse(e.at); return t <= now.getTime() && now.getTime() < t + WINDOW_MS; });

/** Numbers come from /v1/stats at post time, never typed (CLAUDE.md "Truth from code"). */
export const fill = (text: string, s: Stats) =>
  text.replace(/\{(\w+)\}/g, (m, k: string) => String(({
    total: s.entities.total, l2: s.entities.l2, record_entries: s.record_entries,
    attestations: s.attestations, observers: s.observers, log_size: s.log.tree_size,
  } as Record<string, number>)[k] ?? m));

/** Instagram links are not clickable: the URL goes, the domain stays readable. */
export const textFor = (p: Platform, text: string) =>
  p === "instagram" ? text.replace(/\s*https?:\/\/\S+/g, "").trim() + "\n\nopenentity.org" : text;

/** A Buffer channel not connected yet: skipped like a network without keys, so it posts once connected. */
class NotConnected extends Error {}

async function ok<T>(service: string, res: Response): Promise<T> {
  const body = await res.text();
  if (!res.ok) throw new Error(`${service} ${res.status}: ${body.slice(0, 300)}`);
  return JSON.parse(body) as T;
}
const form = (path: string, params: Record<string, string>) =>
  fetch(`${GRAPH}/${path}`, { method: "POST", body: new URLSearchParams(params) });

async function facebook(c: Creds, text: string) {
  const { access_token } = await ok<{ access_token: string }>("facebook", await fetch(`${GRAPH}/${c.META_PAGE_ID}?fields=access_token&access_token=${c.META_TOKEN}`));
  return (await ok<{ id: string }>("facebook", await form(`${c.META_PAGE_ID}/feed`, { message: text, access_token }))).id;
}

async function instagram(c: Creds, text: string, image: string) {
  const t = c.META_TOKEN!;
  const { id } = await ok<{ id: string }>("instagram", await form(`${c.META_IG_USER_ID}/media`, { image_url: image, caption: text, access_token: t }));
  for (let i = 0; i < 10; i++) {
    const { status_code } = await ok<{ status_code: string }>("instagram", await fetch(`${GRAPH}/${id}?fields=status_code&access_token=${t}`));
    if (status_code === "FINISHED") break;
    if (status_code === "ERROR") throw new Error("instagram: media container failed");
    await new Promise((r) => setTimeout(r, 1000));
  }
  return (await ok<{ id: string }>("instagram", await form(`${c.META_IG_USER_ID}/media_publish`, { creation_id: id, access_token: t }))).id;
}

async function buffer(c: Creds, p: keyof typeof BUFFER_SERVICE, text: string) {
  const q = async <T>(query: string, variables: Record<string, unknown> = {}) => {
    const r = await ok<{ data?: T; errors?: { message: string }[] }>("buffer", await fetch("https://api.buffer.com", {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${c.BUFFER_API_KEY}` },
      body: JSON.stringify({ query, variables }),
    }));
    if (!r.data) throw new Error(`buffer: ${JSON.stringify(r.errors ?? r).slice(0, 300)}`);
    return r.data;
  };
  const { account } = await q<{ account: { organizations: { id: string }[] } }>("query{account{organizations{id}}}");
  const { channels } = await q<{ channels: { id: string; service: string }[] }>(
    "query($organizationId: OrganizationId!){channels(input:{organizationId:$organizationId}){id service}}", { organizationId: account.organizations[0]?.id });
  const channel = channels.find((ch) => ch.service === BUFFER_SERVICE[p]);
  if (!channel) throw new NotConnected(p);
  const r = await q<{ createPost: { post?: { id: string }; message?: string } }>(
    "mutation($input: CreatePostInput!){createPost(input:$input){... on PostActionSuccess{post{id}} ... on MutationError{message}}}",
    { input: { text, channelId: channel.id, schedulingType: "automatic", mode: "shareNow" } });
  if (!r.createPost.post) throw new Error(`buffer: ${r.createPost.message ?? "createPost failed"}`);
  return r.createPost.post.id;
}

/** Clickable-link facets: Bluesky links a URL only when the post gives its UTF-8 byte range. */
export function linkFacets(text: string) {
  const enc = new TextEncoder();
  return [...text.matchAll(/https?:\/\/[^\s)]+[^\s).,!?]/g)].map((m) => {
    const byteStart = enc.encode(text.slice(0, m.index)).length;
    return { index: { byteStart, byteEnd: byteStart + enc.encode(m[0]).length }, features: [{ $type: "app.bsky.richtext.facet#link", uri: m[0] }] };
  });
}

async function bluesky(c: Creds, text: string) {
  const pds = "https://bsky.social/xrpc";
  const s = await ok<{ did: string; accessJwt: string }>("bluesky", await fetch(`${pds}/com.atproto.server.createSession`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ identifier: c.BLUESKY_HANDLE, password: c.BLUESKY_APP_PASSWORD }),
  }));
  const record = { $type: "app.bsky.feed.post", text, facets: linkFacets(text), createdAt: new Date().toISOString() };
  return (await ok<{ uri: string }>("bluesky", await fetch(`${pds}/com.atproto.repo.createRecord`, {
    method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${s.accessJwt}` },
    body: JSON.stringify({ repo: s.did, collection: "app.bsky.feed.post", record }),
  }))).uri;
}

export function publish(c: Creds, p: Platform, text: string, image = IMAGE): Promise<string> {
  const t = textFor(p, text);
  if (p === "facebook") return facebook(c, t);
  if (p === "instagram") return instagram(c, t, image);
  if (p === "bluesky") return bluesky(c, t);
  return buffer(c, p, t);
}

/**
 * Posts every due entry to every configured network it has not gone to. The row is claimed before the send, so a
 * crash or timeout never double posts; a failed send stays failed (logged, raises the Lambda error alarm).
 */
export async function postSocial(env: Env, s: Stats, now = new Date(), entries: Entry[] = calendar as Entry[]) {
  const failures: string[] = [];
  for (const e of due(entries, now)) {
    for (const p of configured(env)) {
      const claim = await env.db.first<{ entry_id: string }>(
        "INSERT INTO social_posts (entry_id, platform, status, at) VALUES ($1, $2, 'sending', $3) ON CONFLICT DO NOTHING RETURNING entry_id", [e.id, p, now.toISOString()]);
      if (!claim) continue;
      try {
        const ref = await publish(env, p, fill(e.text, s), e.image);
        await env.db.run("UPDATE social_posts SET status = 'posted', ref = $3 WHERE entry_id = $1 AND platform = $2", [e.id, p, ref]);
      } catch (err) {
        if (err instanceof NotConnected) {
          await env.db.run("DELETE FROM social_posts WHERE entry_id = $1 AND platform = $2", [e.id, p]);
          continue;
        }
        const msg = String((err as Error).message ?? err).slice(0, 500);
        await env.db.run("UPDATE social_posts SET status = 'failed', error = $3 WHERE entry_id = $1 AND platform = $2", [e.id, p, msg]);
        failures.push(`${p} ${e.id}: ${msg}`);
      }
    }
  }
  if (failures.length) throw new Error(`social: ${failures.join("; ")}`);
}
