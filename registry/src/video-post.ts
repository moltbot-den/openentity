// Short-form video, posting half: each rendered video goes once to every video network that has credentials and a connected channel.
// Ported from the One Frequency United feed: Meta Graph Reels, Zernio (TikTok, YouTube), Buffer (Pinterest video pins).
import type { Env } from "./env.ts";
import { form, GRAPH, NotConnected, ok, sendOnce, type Creds } from "./social.ts";
import { dueVideos, type Script } from "./video.ts";

export const VIDEO_PLATFORMS = ["instagram_reel", "facebook_reel", "tiktok", "youtube", "pinterest"] as const;
export type VideoPlatform = (typeof VIDEO_PLATFORMS)[number];
const SITE = "https://openentity.org";
const TAGS = "#AIagents #AgentIdentity #OpenEntity";
const IG_EXPIRES_MS = 2 * 3600_000;

export const configuredVideo = (c: Creds): VideoPlatform[] =>
  VIDEO_PLATFORMS.filter((p) => ({
    instagram_reel: c.META_TOKEN && c.META_IG_USER_ID, facebook_reel: c.META_TOKEN && c.META_PAGE_ID,
    tiktok: c.ZERNIO_API_KEY, youtube: c.ZERNIO_API_KEY, pinterest: c.BUFFER_API_KEY,
  })[p]);

/** The caption as each network wants it: tags where they sort content, the domain where links are dead. */
export const captionFor = (p: VideoPlatform, s: Script) =>
  ({ instagram_reel: `${s.caption}\n\nopenentity.org\n\n${TAGS}`, facebook_reel: `${s.caption}\n\n${SITE}`, tiktok: `${s.caption}\n\n${TAGS}`,
    youtube: `${s.caption}\n\n${SITE}\n\n#Shorts ${TAGS}`, pinterest: s.caption })[p];

/** Instagram makes the container, processes it for a while, then publishes. The first tick creates it and later ticks publish it, because Lambda cannot wait. */
async function instagramReel(c: Creds, caption: string, url: string, container?: string): Promise<{ container: string } | { id: string } | { wait: true }> {
  const t = c.META_TOKEN!;
  if (!container) {
    const { id } = await ok<{ id: string }>("instagram", await form(`${c.META_IG_USER_ID}/media`, { media_type: "REELS", video_url: url, caption, share_to_feed: "true", access_token: t }));
    return { container: id };
  }
  const { status_code } = await ok<{ status_code: string }>("instagram", await fetch(`${GRAPH}/${container}?fields=status_code&access_token=${t}`));
  if (status_code === "ERROR" || status_code === "EXPIRED") throw new Error("instagram: reel container failed");
  if (status_code !== "FINISHED") return { wait: true };
  return { id: (await ok<{ id: string }>("instagram", await form(`${c.META_IG_USER_ID}/media_publish`, { creation_id: container, access_token: t }))).id };
}

/** Facebook Reels: start an upload session, hand Meta the hosted file, then publish. */
async function facebookReel(c: Creds, caption: string, url: string) {
  const { access_token: t } = await ok<{ access_token: string }>("facebook", await fetch(`${GRAPH}/${c.META_PAGE_ID}?fields=access_token&access_token=${c.META_TOKEN}`));
  const page = `${c.META_PAGE_ID}/video_reels`;
  const { video_id, upload_url } = await ok<{ video_id: string; upload_url: string }>("facebook", await form(page, { upload_phase: "start", access_token: t }));
  await ok("facebook", await fetch(upload_url, { method: "POST", headers: { Authorization: `OAuth ${t}`, file_url: url } }));
  await ok("facebook", await form(page, { upload_phase: "finish", video_id, video_state: "PUBLISHED", description: caption, access_token: t }));
  return video_id;
}

async function zernio(c: Creds, platform: "tiktok" | "youtube", caption: string, title: string, url: string) {
  const h = { authorization: `Bearer ${c.ZERNIO_API_KEY}`, "content-type": "application/json" };
  const { accounts } = await ok<{ accounts: { _id: string; platform: string }[] }>("zernio", await fetch("https://zernio.com/api/v1/accounts", { headers: h }));
  const account = accounts.find((a) => a.platform === platform);
  if (!account) throw new NotConnected(platform);
  const body = {
    content: caption, publishNow: true, mediaItems: [{ type: "video", url }],
    platforms: [{ platform, accountId: account._id, ...(platform === "youtube" ? { platformSpecificData: { title: title.slice(0, 100), visibility: "public", madeForKids: false } } : {}) }],
    // The voice is synthetic, so TikTok's AI label is on.
    ...(platform === "tiktok" ? { tiktokSettings: { privacy_level: "PUBLIC_TO_EVERYONE", allow_comment: true, allow_duet: true, allow_stitch: true, commercial_content_type: "none", content_preview_confirmed: true, express_consent_given: true, media_type: "video", auto_add_music: false, video_made_with_ai: true } } : {}),
  };
  const r = await ok<{ post?: { _id: string }; _id?: string }>("zernio", await fetch("https://zernio.com/api/v1/posts", { method: "POST", headers: h, body: JSON.stringify(body) }));
  const id = r.post?._id ?? r._id;
  if (!id) throw new Error(`zernio: no post id ${JSON.stringify(r).slice(0, 200)}`);
  return id;
}

/** The video board when the account has one named for video, else the first. */
export const pinBoard = (boards: { serviceId: string; name: string }[]) => (boards.find((b) => /video/i.test(b.name)) ?? boards[0])?.serviceId;

async function pinterest(c: Creds, caption: string, title: string, url: string) {
  const q = async <T>(query: string, variables: Record<string, unknown> = {}) => {
    const r = await ok<{ data?: T; errors?: { message: string }[] }>("buffer", await fetch("https://api.buffer.com", {
      method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${c.BUFFER_API_KEY}` }, body: JSON.stringify({ query, variables }),
    }));
    if (!r.data) throw new Error(`buffer: ${JSON.stringify(r.errors ?? r).slice(0, 300)}`);
    return r.data;
  };
  const { account } = await q<{ account: { organizations: { id: string }[] } }>("query{account{organizations{id}}}");
  const { channels } = await q<{ channels: { id: string; service: string }[] }>(
    "query($organizationId: OrganizationId!){channels(input:{organizationId:$organizationId}){id service}}", { organizationId: account.organizations[0]?.id });
  const channel = channels.find((ch) => ch.service === "pinterest");
  if (!channel) throw new NotConnected("pinterest");
  const { channel: ch } = await q<{ channel: { metadata: { boards?: { serviceId: string; name: string }[] } } }>(
    "query($id: ChannelId!){channel(input:{id:$id}){metadata{... on PinterestMetadata{boards{serviceId name}}}}}", { id: channel.id });
  const board = pinBoard(ch.metadata.boards ?? []);
  if (!board) throw new NotConnected("pinterest board");
  const r = await q<{ createPost: { post?: { id: string }; message?: string } }>(
    "mutation($input: CreatePostInput!){createPost(input:$input){... on PostActionSuccess{post{id}} ... on MutationError{message}}}",
    { input: { text: caption, channelId: channel.id, schedulingType: "automatic", mode: "shareNow", assets: [{ video: { url } }], metadata: { pinterest: { boardServiceId: board, title: title.slice(0, 100), url: SITE } } } });
  if (!r.createPost.post) throw new Error(`buffer: ${r.createPost.message ?? "createPost failed"}`);
  return r.createPost.post.id;
}

/** Posts each due, rendered video to every configured video network it has not gone to, once. */
export async function postVideo(env: Env, now = new Date()) {
  if (env.VIDEO_POSTING !== "on") return; // videos render ahead either way; publishing starts when this key is "on" in /openentity/app
  const failures: string[] = [];
  for (const v of await dueVideos(env, now)) {
    for (const p of configuredVideo(env)) {
      const caption = captionFor(p, v.script);
      if (p === "instagram_reel") {
        const row = await env.db.first<{ status: string; ref: string | null; at: string }>("SELECT status, ref, at FROM social_posts WHERE entry_id = $1 AND platform = $2", [v.id, p]);
        if (row?.status === "processing") {
          try {
            const r = await instagramReel(env, caption, v.url, row.ref!);
            if ("id" in r) await env.db.run("UPDATE social_posts SET status = 'posted', ref = $3 WHERE entry_id = $1 AND platform = $2", [v.id, p, r.id]);
            else if (now.getTime() - Date.parse(row.at) > IG_EXPIRES_MS) throw new Error("instagram: reel container still processing after 2 hours");
          } catch (err) {
            const msg = String((err as Error).message ?? err).slice(0, 500);
            await env.db.run("UPDATE social_posts SET status = 'failed', error = $3 WHERE entry_id = $1 AND platform = $2", [v.id, p, msg]);
            failures.push(`${p} ${v.id}: ${msg}`);
          }
          continue;
        }
        // First tick: make the container and keep its id as the ref, status processing; the branch above publishes it later.
        const f = await sendOnce(env, v.id, p, now, async () => ((await instagramReel(env, caption, v.url)) as { container: string }).container, "processing");
        if (f) failures.push(f);
        continue;
      }
      const f = await sendOnce(env, v.id, p, now, () => ({
        facebook_reel: () => facebookReel(env, caption, v.url),
        tiktok: () => zernio(env, "tiktok", caption, v.script.title, v.url),
        youtube: () => zernio(env, "youtube", caption, v.script.title, v.url),
        pinterest: () => pinterest(env, caption, v.script.title, v.url),
      })[p]());
      if (f) failures.push(f);
    }
  }
  if (failures.length) throw new Error(`social video: ${failures.join("; ")}`);
}
