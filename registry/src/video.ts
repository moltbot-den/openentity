// Short-form video, render-ahead half: topic -> script (model, injected) -> lint + judge -> voice -> render, one step per tick.
// A row per day in social_videos moves scripting -> scripted -> rendering -> ready (or skipped / failed). Posting is video-post.ts.
import type { Env } from "./env.ts";
import { fill, type Stats } from "./social.ts";
import topicList from "../social/video-topics.json" with { type: "json" };

export type Topic = { id: string; title: string; brief: string };
export type StatKey = "total" | "l2" | "record_entries" | "attestations" | "observers" | "log_size";
export type Beat = { say: string; show: string; stat?: StatKey };
export type Script = { beats: Beat[]; caption: string; title: string };
export type Mark = { time: number; start: number; end: number; value: string }; // Polly word marks: ms, UTF-8 byte offsets
export type VideoProps = {
  variant: 0 | 1 | 2;
  beats: { show: string; from: number; to: number; stat?: { value: string; label: string } }[];
  words: { text: string; from: number; to: number }[];
  audio: string;
  durationSec: number;
};
export type Llm = {
  /** `problems` are what the previous draft got wrong. */
  draft(topic: Topic, problems: string[]): Promise<Script>;
  /** Scores the script and rejects (score 1) any claim the topic's facts and LEVEL_FACTS do not support. */
  judge(script: Script, topic: Topic): Promise<{ score: number; reason: string }>;
};
export type VideoDeps = {
  llm: Llm;
  /** Synthesizes the voiceover, stores the audio at a public URL and returns it with the word marks. */
  voice(text: string, day: string): Promise<{ audio: string; marks: Mark[] }>;
  render: {
    start(props: VideoProps, day: string): Promise<{ id: string; bucket: string; url: string }>;
    progress(id: string, bucket: string): Promise<{ done: boolean; error?: string }>;
  };
};

export const TOPICS = topicList as Topic[];
export const PASS_SCORE = 6.5; // the editor prompt is strict: 6 to 6.5 reads as clear and accurate but ordinary
export const MAX_TRIES = 4;
export const MIN_SEC = 20, MAX_SEC = 40;
const STAT_LABEL: Record<StatKey, string> = { total: "entities", l2: "observed", record_entries: "record entries", attestations: "attestations", observers: "observers", log_size: "log entries" };

const dayNumber = (day: string) => Math.floor(Date.parse(day) / 86400_000);
export const dayOf = (d: Date) => d.toISOString().slice(0, 10);
/** One topic per day in list order, so none repeats within a full pass; three visual variants by date. */
export const topicFor = (day: string, topics: Topic[] = TOPICS) => topics[((dayNumber(day) % topics.length) + topics.length) % topics.length]!;
export const variantFor = (day: string) => (((dayNumber(day) % 3) + 3) % 3) as 0 | 1 | 2;

const BANNED = /coming soon|global standard|\bbest\b|world'?s first|revolution|cutting.edge|\busers?\b|millions?|thousands?/i;
const BRAND = /\bOEIS\b|OpenEntity|Openentity|MoltbotDen|Moltbot-Den/; // "openentity.org" and the CLI name stay lowercase
const ALLOWED_DIGITS = /\{\w+\}|\bL[0-3]\b|RFC 9421|ERC-8004|\bCC0\b/g;
/** Level names and how each is reached, from spec/OEIS-1.md 2.2 (a test checks this table against the spec). Levels are not a ladder: L2 needs an observer's attestation, not L1. */
export const LEVELS: Record<string, { name: string; how: string }> = {
  L0: { name: "Declared", how: "a valid identifier with a valid Declaration in the log; any entity, one command" },
  L1: { name: "Verified", how: "control of something beyond a bare key is proven: at least one verified alias such as a domain, wallet, ERC-8004 agent or platform account" },
  L2: { name: "Observed", how: "at least one accredited observer has issued a current attestation about the entity's record" },
  L3: { name: "Entity", how: "an accredited observer attests the stage is entity, from evidence thresholds" },
};
export const LEVEL_FACTS = Object.entries(LEVELS).map(([l, v]) => `${l} ${v.name}: ${v.how}.`).join(" ") + " Levels are not a ladder: reaching one does not require holding the one below.";
const NUMBER_WORDS = "one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|dozens?|hundreds?|thousands?";
/** Deterministic claims the spec contradicts; the judge covers the rest. */
export function factProblems(s: Script): string[] {
  const p: string[] = [];
  const text = s.beats.map((b) => b.say).join(" ") + " " + s.caption;
  if (/\bfrom L[0-3]\b|\b(L[0-3]|level [0-3])\s+(to|then|and then|up to)\s+L[0-3]\b|\b(moves?|promot\w+|upgrad\w+|advanc\w+|climbs?|steps?)\b[^.]*\bL[0-3]\b/i.test(text)) p.push("levels are not a ladder: say what an observer or alias proves, never that an agent moves from one level to another");
  for (const sentence of text.split(/(?<=[.!?])\s+/)) {
    const mentioned = [...sentence.matchAll(/\bL([0-3])\b/g)].map((m) => `L${m[1]}`);
    for (const [l, v] of Object.entries(LEVELS))
      if (mentioned.length === 1 && mentioned[0] !== l && new RegExp(`\\b${v.name}\\b`).test(sentence) && l !== "L3") // "Entity" is also the brand, so L3 is only checked by the judge
        p.push(`${mentioned[0]} is ${LEVELS[mentioned[0]!]!.name}, not ${v.name}`);
  }
  if (new RegExp(`\\b(${NUMBER_WORDS})\\s+(registered\\s+)?(entities|agents|attestations|observers|record entries)\\b`, "i").test(text)) p.push("typed count in words: counts come only from the placeholders");
  return p;
}
const spoken = (s: Script) => s.beats.map((b) => b.say).join(" ");
const wc = (t: string) => t.trim().split(/\s+/).filter(Boolean).length;

/** Deterministic rules every script must pass before the judge sees it. */
export function lintScript(s: Script): string[] {
  const all = [...s.beats.flatMap((b) => [b.say, b.show]), s.caption, s.title];
  const text = all.join("\n");
  const p: string[] = [];
  if (/[\u2014\u2013]/.test(text)) p.push("dash: use a period or a comma");
  if (/\d/.test(text.replace(ALLOWED_DIGITS, ""))) p.push("typed number: counts come only from {total}, {l2}, {record_entries}, {attestations}, {observers}, {log_size}");
  const bad = text.match(BANNED) ?? text.match(BRAND);
  if (bad) p.push(`banned word or brand form: ${bad[0]}`);
  const unknown = [...text.matchAll(/\{(\w+)\}/g)].map((m) => m[1]!).filter((k) => !(k in STAT_LABEL));
  if (unknown.length) p.push(`unknown placeholder: ${unknown[0]}`);
  if (/https?:\/\//.test(s.caption)) p.push("caption must not contain a URL");
  if (s.beats.length < 4 || s.beats.length > 7) p.push("use 4 to 7 beats");
  const n = wc(spoken(s));
  if (n < 55 || n > 95) p.push(`spoken script has ${n} words; needs 55 to 95`);
  if (s.beats.some((b) => wc(b.show) > 7)) p.push("a show line has more than 7 words");
  if (s.beats.some((b) => b.stat && !(b.stat in STAT_LABEL))) p.push("unknown stat key");
  if (s.caption.length > 220 || s.title.length > 90) p.push("caption over 220 or title over 90 characters");
  p.push(...factProblems(s));
  if (!/Open Entity/.test(spoken(s))) p.push('say "Open Entity" aloud at least once');
  return p;
}

/** Up to one attempt per call: drafts, lints, judges. Returns the script, or the problems to feed the next try. */
export async function attempt(llm: Llm, topic: Topic, problems: string[]): Promise<{ script: Script } | { problems: string[] }> {
  const script = await llm.draft(topic, problems);
  const lint = lintScript(script);
  if (lint.length) return { problems: lint };
  const { score, reason } = await llm.judge(script, topic);
  return score >= PASS_SCORE ? { script } : { problems: [`an editor scored the last draft ${score} of 10: ${reason}`] };
}

const enc = new TextEncoder();
/** Voice marks to composition props. Beat starts come from the byte offset of each beat's first word, so no tokenizer has to agree with Polly's. */
export function videoProps(script: Script, marks: Mark[], audio: string, s: Stats, day: string): VideoProps {
  if (!marks.length) throw new Error("video: no word marks");
  let offset = 0;
  const starts = script.beats.map((b) => {
    const at = offset;
    offset += enc.encode(b.say).length + 1;
    return marks.find((m) => m.start >= at)?.time ?? marks.at(-1)!.time;
  });
  const sec = (ms: number) => Math.round(ms) / 1000;
  const last = marks.at(-1)!;
  const durationSec = Math.max(MIN_SEC, sec(last.time) + 2.5);
  if (durationSec > MAX_SEC) throw new Error(`video: ${durationSec}s is over ${MAX_SEC}s`);
  const stat = (k: StatKey) => ({ value: fill(`{${k}}`, s), label: STAT_LABEL[k] });
  return {
    variant: variantFor(day),
    beats: script.beats.map((b, i) => ({
      show: b.show, from: i === 0 ? 0 : sec(starts[i]!), to: i === script.beats.length - 1 ? durationSec : sec(starts[i + 1]!),
      ...(b.stat ? { stat: stat(b.stat) } : {}),
    })),
    words: marks.map((m, i) => ({ text: m.value, from: sec(m.time), to: i + 1 < marks.length ? sec(marks[i + 1]!.time) : sec(m.time) + 0.6 })),
    audio, durationSec,
  };
}

type Row = { day: string; topic: string; status: string; script: string | null; render_id: string | null; bucket: string | null; url: string | null; tries: number; error: string | null };
const fillScript = (s: Script, st: Stats): Script => ({
  caption: fill(s.caption, st), title: fill(s.title, st), beats: s.beats.map((b) => ({ ...b, say: fill(b.say, st), show: fill(b.show, st) })),
});

/**
 * One step for the first of today and tomorrow that is not finished. Lambda has 30 s, so each tick does one slow thing:
 * one draft, or voice plus starting the render, or one progress check. Skipped scripts and failed renders are final for the day.
 */
export async function videoTick(env: Env, s: Stats, now: Date, deps: VideoDeps, topics: Topic[] = TOPICS) {
  const { db } = env;
  for (const day of [dayOf(now), dayOf(new Date(now.getTime() + 86400_000))]) {
    let row = await db.first<Row>("SELECT * FROM social_videos WHERE day = $1", [day]);
    if (!row) {
      const topic = topicFor(day, topics);
      const claim = await db.first<{ day: string }>("INSERT INTO social_videos (day, topic, status, at) VALUES ($1, $2, 'scripting', $3) ON CONFLICT DO NOTHING RETURNING day", [day, topic.id, now.toISOString()]);
      if (!claim) return;
      row = (await db.first<Row>("SELECT * FROM social_videos WHERE day = $1", [day]))!;
    }
    if (["ready", "skipped", "failed"].includes(row.status)) continue;
    const fail = async (error: string, next = row!.status) => {
      const tries = row!.tries + 1;
      const status = tries >= MAX_TRIES ? "failed" : next;
      await db.run("UPDATE social_videos SET tries = $2, status = $3, error = $4 WHERE day = $1", [day, tries, status, error.slice(0, 500)]);
      if (status === "failed") throw new Error(`video ${day}: ${error}`);
    };
    try {
      if (row.status === "scripting") {
        const topic = topics.find((t) => t.id === row.topic)!;
        const r = await attempt(deps.llm, topic, row.error ? [row.error] : []);
        if ("script" in r) await db.run("UPDATE social_videos SET status = 'scripted', script = $2 WHERE day = $1", [day, JSON.stringify(r.script)]);
        else {
          const tries = row.tries + 1;
          await db.run("UPDATE social_videos SET tries = $2, status = $3, error = $4 WHERE day = $1", [day, tries, tries >= MAX_TRIES ? "skipped" : "scripting", r.problems.join("; ").slice(0, 500)]);
        }
      } else if (row.status === "scripted") {
        const script = fillScript(JSON.parse(row.script!) as Script, s);
        const { audio, marks } = await deps.voice(spoken(script), day);
        const r = await deps.render.start(videoProps(script, marks, audio, s, day), day);
        await db.run("UPDATE social_videos SET status = 'rendering', script = $2, render_id = $3, bucket = $4, url = $5 WHERE day = $1", [day, JSON.stringify(script), r.id, r.bucket, r.url]);
      } else {
        const p = await deps.render.progress(row.render_id!, row.bucket!);
        if (p.error) {
          // Re-render from the stored (already filled) script on the next tick, unless this was the last try.
          await fail(`render: ${p.error}`, "scripted");
        } else if (p.done) await db.run("UPDATE social_videos SET status = 'ready' WHERE day = $1", [day]);
      }
    } catch (e) {
      if (/^video \d{4}/.test((e as Error).message)) throw e;
      await fail(String((e as Error).message ?? e));
    }
    return;
  }
}

/** Videos whose post time has come: the day at hour `VIDEO_HOUR` UTC, due for 24 hours, and only once rendered. */
export const VIDEO_HOUR = 16;
export async function dueVideos(env: Env, now: Date): Promise<{ id: string; day: string; url: string; script: Script }[]> {
  const rows = await env.db.all<Row>("SELECT * FROM social_videos WHERE status = 'ready' ORDER BY day DESC LIMIT 3");
  return rows.filter((r) => { const t = Date.parse(`${r.day}T${String(VIDEO_HOUR).padStart(2, "0")}:00:00Z`); return t <= now.getTime() && now.getTime() < t + 24 * 3600_000; })
    .map((r) => ({ id: `video-${r.day}`, day: r.day, url: r.url!, script: JSON.parse(r.script!) as Script }));
}
