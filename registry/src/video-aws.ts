// The AWS side of video.ts: Claude on Bedrock writes and judges the script, Polly voices it, Remotion Lambda renders it.
// Not unit tested (every call is an AWS call); video.ts takes these as injected dependencies and its tests inject fakes.
import { BedrockRuntimeClient, ConverseCommand, type ToolInputSchema } from "@aws-sdk/client-bedrock-runtime";
import { PollyClient, SynthesizeSpeechCommand } from "@aws-sdk/client-polly";
import { PutObjectCommand, S3Client } from "@aws-sdk/client-s3";
import { getRenderProgress, renderMediaOnLambda } from "@remotion/lambda/client";
import remotion from "../social/remotion.json" with { type: "json" };
import { LEVEL_FACTS, type Beat, type Llm, type Mark, type Script, type Topic, type VideoDeps } from "./video.ts";

/** Preference order: the account may not have the newest model enabled yet, so fall through. */
const MODELS = ["us.anthropic.claude-sonnet-5-5", "us.anthropic.claude-sonnet-4-6"];

const SYSTEM = `You write 20 to 40 second vertical explainer videos for Open Entity, the open identity standard for AI agents. Voice: plain, specific, calm, for builders and operators. Rules:
- Brand: "Open Entity" (two words) and "Moltbot Den" (two words). Never "OEIS", never "OpenEntity".
- Never type a number. When a count helps, put a placeholder in "say" and "show": {total}, {l2}, {record_entries}, {attestations}, {observers}, {log_size}. They are filled live from the registry. Level names L0 to L3 are fine.
- No dashes (use periods and commas), no hype, no "best", no "coming soon", no "global standard", no user counts, no emoji, no hashtags.
- Use only the facts you are given; never invent a mechanism, number or claim.
- Audience: builders who have never heard of Open Entity. Explain every term (attestation, observer, level, Declaration) in plain words the first time, or leave it out. One idea per beat, no beat repeats another.
- Length: aim for 70 to 85 spoken words; when revising, cut, never add.
- Beats: 4 to 7. Beat 1 is a hook that names a problem or a surprise in the first sentence. The last beat ends on "openentity.org" said aloud as "open entity dot org".
- "say" is spoken aloud: 55 to 95 words in total across beats, short sentences, written for the ear. "show" is the on-screen headline for that beat, 7 words or fewer, not a repeat of the spoken line.
- Optional "stat" on one beat: one of the placeholder names, when that beat is about the registry's size or activity; "show" then labels the number.
- "caption": one or two plain sentences for the post, under 220 characters, no URL. "title": under 90 characters, describes the topic.`;

const draftSchema = {
  type: "object", required: ["beats", "caption", "title"],
  properties: {
    beats: { type: "array", items: { type: "object", required: ["say", "show"], properties: { say: { type: "string" }, show: { type: "string" }, stat: { type: "string" } } } },
    caption: { type: "string" }, title: { type: "string" },
  },
};
const verdictSchema = { type: "object", required: ["score"], properties: { score: { type: "number", description: "1 to 10" }, reason: { type: "string" } } };

export function bedrockLlm(client: Pick<BedrockRuntimeClient, "send"> = new BedrockRuntimeClient({ region: "us-east-1" })): Llm {
  async function tool<T>(system: string, prompt: string, name: string, schema: object): Promise<T> {
    let last: unknown;
    for (const modelId of MODELS) {
      try {
        const res = await client.send(new ConverseCommand({
          modelId, system: [{ text: system }], messages: [{ role: "user", content: [{ text: prompt }] }],
          toolConfig: { tools: [{ toolSpec: { name, inputSchema: { json: schema } as ToolInputSchema } }], toolChoice: { tool: { name } } },
          inferenceConfig: { maxTokens: 2000 },
        }));
        const input = res.output?.message?.content?.find((c) => c.toolUse)?.toolUse?.input;
        if (input === undefined) throw new Error(`bedrock: no ${name} tool call`);
        return input as T;
      } catch (e) {
        last = e;
        if (!/not available|AccessDenied|ResourceNotFound|use case/i.test(`${(e as Error).name} ${(e as Error).message}`)) throw e;
      }
    }
    throw last;
  }
  return {
    async draft(topic: Topic, problems: string[]) {
      const d = await tool<{ beats: Beat[]; caption: string; title: string }>(SYSTEM, [
        `Topic: ${topic.title}`, `Facts you may use: ${topic.brief}`, `Level facts: ${LEVEL_FACTS}`,
        ...(problems.length ? [`Your last draft failed these checks, fix them: ${problems.join("; ")}`] : []),
        "Call submit_script.",
      ].join("\n"), "submit_script", draftSchema);
      // The model keeps reaching for dashes; a period keeps the meaning.
      const undash = (t: string) => t.replace(/\s*[\u2014\u2013]\s*/g, ". ");
      return { caption: undash(d.caption), title: undash(d.title), beats: d.beats.map((b) => ({ say: undash(b.say), show: undash(b.show), ...(b.stat ? { stat: b.stat } : {}) })) } as Script;
    },
    async judge(script: Script, topic: Topic) {
      const v = await tool<{ score: number; reason?: string }>("You are a strict editor of short explainer videos for builders of AI agents. Score 1 to 10: 9 to 10 a hook you would stop scrolling for and every line earns its place; 7 to 8 clear and accurate and fine to post; 5 to 6 generic, padded or confusing; below 5 wrong or embarrassing. Fact check first: the only supported facts are the topic brief and the level facts below; any claim, mechanism, level change or number in the script that they do not support scores 1, and the reason names the claim. Penalize jargon not explained, repeated lines, hype and vague claims. In the reason, say in one or two sentences what to change.",
        `Topic facts: ${topic.brief}\nLevel facts: ${LEVEL_FACTS}\nScript:\n` + JSON.stringify(script, null, 1) + "\nCall submit_verdict.", "submit_verdict", verdictSchema);
      return { score: Number(v.score), reason: v.reason ?? "" };
    },
  };
}

const REGION = "us-east-1" as const; // the render stack is deployed here (infra/scripts/remotion-deploy.ts)
export const publicUrl = (key: string) => `https://${remotion.bucket}.s3.${REGION}.amazonaws.com/${key}`;

export function awsVideoDeps(): VideoDeps {
  const polly = new PollyClient({ region: REGION }), s3 = new S3Client({ region: REGION });
  const speak = (text: string, output: "mp3" | "json") => polly.send(new SynthesizeSpeechCommand({
    Engine: "neural", VoiceId: "Matthew", LanguageCode: "en-US", Text: text, OutputFormat: output, ...(output === "json" ? { SpeechMarkTypes: ["word"] } : {}),
  })).then((r) => r.AudioStream!.transformToByteArray());
  return {
    llm: bedrockLlm(),
    async voice(text, day) {
      const [mp3, json] = await Promise.all([speak(text, "mp3"), speak(text, "json")]);
      const key = `social/audio/${day}.mp3`;
      await s3.send(new PutObjectCommand({ Bucket: remotion.bucket, Key: key, Body: mp3, ContentType: "audio/mpeg", ACL: "public-read" }));
      const marks = new TextDecoder().decode(json).split("\n").filter(Boolean).map((l) => JSON.parse(l) as Mark & { type: string }).filter((m) => m.type === "word");
      return { audio: publicUrl(key), marks };
    },
    render: {
      async start(props, day) {
        const r = await renderMediaOnLambda({
          region: REGION, functionName: remotion.functionName, serveUrl: remotion.serveUrl, composition: "Short",
          inputProps: props, codec: "h264", privacy: "public", outName: `${day}.mp4`, downloadBehavior: { type: "play-in-browser" }, maxRetries: 1,
        });
        return { id: r.renderId, bucket: r.bucketName, url: `https://${r.bucketName}.s3.${REGION}.amazonaws.com/renders/${r.renderId}/${day}.mp4` };
      },
      async progress(id, bucket) {
        const p = await getRenderProgress({ renderId: id, bucketName: bucket, functionName: remotion.functionName, region: REGION });
        return p.fatalErrorEncountered ? { done: false, error: p.errors[0]?.message ?? "fatal render error" } : { done: p.done };
      },
    },
  };
}
