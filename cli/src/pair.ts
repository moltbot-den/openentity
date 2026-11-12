// `openentity pair <code>`: link this agent to its owner's OpenEntity app (PLAN 8.1), and `openentity owner ...` afterwards.
import { mkdir, readFile, readdir, stat, writeFile } from "node:fs/promises";
import { homedir, hostname } from "node:os";
import { dirname, join } from "node:path";
import { OpenEntityError, Owner, pair, type BearerCredential } from "@openentity/sdk";
import { adopt } from "./adopt";
import { anchor } from "./anchor";
import { CliError, EXIT, usage } from "./errors";
import { home, loadEntity, type Ctx, type Entity, type Result } from "./store";
import pkg from "../package.json";

export const ACCOUNT = "https://account.openentity.org";
const SITE = "https://openentity.org";
const CODE = /^OE-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$/;
/** Every file of skill/openentity, as openentity.org/skill/ serves them (a test keeps this list equal to the directory). */
export const SKILL_FILES = ["SKILL.md", "scripts/adopt.sh", "scripts/anchor.sh", "scripts/record.sh", "scripts/sign.mjs", "scripts/sign.py"];
/** The local MCP server OpenClaw starts (stdio): the same identity store as this CLI. */
export const MCP_SERVER = { command: "npx", args: ["-y", "@openentity/mcp"] };
/** Where each product's tools read the bearer key pairing issues (PLAN 8.4), as each product's repository documents it. */
export const KEY_HOME: Record<string, string> = {
  "did:web:moltbotden.com": "Moltbot Den (mbd, its MCP server, @moltbotden/sdk): run `mbd login --api-key <key>`, which stores it in ~/.moltbotden/config.json (mode 600), or set MOLTBOTDEN_API_KEY",
  "did:web:securemyagent.ai": "Secure My Agent (sma CLI): the apiKey field of ~/.securemyagent/identity.json",
  "did:web:api.agentsecretstore.com": "Agent Secret Store (ass, its MCP server, its SDKs): set ASS_AGENT_KEY",
  "did:web:api.clawgrc.com": "ClawGRC (its MCP server): set CLAW_GRC_API_KEY",
};

const accountOf = (v: Ctx["v"]): string => v.account ?? process.env.OPENENTITY_ACCOUNT ?? ACCOUNT;
const exists = (p: string) => stat(p).then(() => true, () => false);

/** An SDK or network failure as a CLI error with the matching exit code. */
function cliError(e: any): CliError {
  if (e instanceof CliError) return e;
  const code = e?.code === "invalid_input" ? EXIT.USAGE
    : e?.code === "verification_failed" ? EXIT.VERIFY
    : !(e instanceof OpenEntityError) || (e.status ?? 0) >= 500 ? EXIT.NETWORK
    : EXIT.REJECTED;
  return new CliError(code, e?.code && e instanceof OpenEntityError ? `${e.code}: ${e.message}` : String(e?.message ?? e));
}

/** The current entity, or a freshly adopted one when this home holds none (adopting signs the Declaration). */
async function entityFor(c: Ctx, framework: string): Promise<{ e: Entity; adopted: boolean }> {
  try {
    return { e: await loadEntity(c.v), adopted: false };
  } catch (err) {
    const dirs = await readdir(home()).catch(() => [] as string[]);
    if (c.v.eid || process.env.OPENENTITY_EID || dirs.some((d) => d.startsWith("did:"))) throw err; // several entities: pick one with --eid
  }
  const name = c.v.name ?? process.env.OPENENTITY_NAME ?? (framework === "openclaw" ? "OpenClaw agent" : "Agent");
  const r = await adopt({ args: [], v: { ...c.v, name, agree: true } });
  return { e: await loadEntity({ ...c.v, eid: (r.json as { eid: string }).eid }), adopted: true };
}

export async function pairCmd(c: Ctx): Promise<Result> {
  const { args, v } = c;
  const say = c.say ?? (() => {});
  const code = String(args[0] ?? "").trim().toUpperCase();
  if (!CODE.test(code)) throw usage("pair needs the code your OpenEntity app shows: openentity pair OE-XXXX-XXXX [--openclaw] [--account URL]");
  const framework: string = v.framework ?? (v.openclaw ? "openclaw" : "other");
  const account = accountOf(v);
  const { e, adopted } = await entityFor(c, framework);
  if (adopted) say(`Adopted ${e.eid} ("${e.doc.name}"). By pairing, this agent signed the Open Entity Declaration: ${SITE}/spec/declaration/1.0.txt`);
  const paired = await pair(code, {
    identity: e.kp, framework, sdk: "openentity-cli", sdkVersion: pkg.version, host: hostname(), account,
    onMatch: (names) => say(`Match: ${names.join(", ")}\nConfirm in your OpenEntity app if it shows the same four items. Waiting for the owner...`),
  }).catch((err) => Promise.reject(cliError(err)));
  const openclaw = v.openclaw ? await setUpOpenClaw(v, e, account) : undefined;
  const keys = paired.credentials.map((k: BearerCredential) => ({ ...k, put_it_in: KEY_HOME[k.product] ?? "the tool that uses this product's API key" }));
  const json = { eid: e.eid, adopted, owner_did: paired.ownerDid, permissions: paired.permissions, match: paired.match, credentials: keys, ...(openclaw ? { openclaw } : {}) };
  const text = [
    `Paired ${e.eid} with ${paired.ownerDid}.`,
    `Permissions: ${paired.permissions.join(", ") || "none yet"}`,
    ...(openclaw ? [
      `OpenClaw: Identity Anchor in ${openclaw.identity_files.join(" and ")}; skill in ${openclaw.skill}`,
      openclaw.mcp.written
        ? `OpenClaw: MCP server "openentity" (${MCP_SERVER.command} ${MCP_SERVER.args.join(" ")}) registered in ${openclaw.mcp.path} under mcp.servers`
        : `OpenClaw: ${openclaw.mcp.path} is not plain JSON, so it was left as it is. Add this under mcp.servers: "openentity": ${JSON.stringify(openclaw.mcp.entry)}`,
    ] : []),
    ...keys.flatMap((k) => [`Key for ${k.product}, valid until ${new Date(k.expires_at * 1000).toISOString().slice(0, 10)}, shown once:`, `  ${k.key}`, `  Put it in: ${k.put_it_in}`]),
    `Next: openentity owner message "<text>" | owner status running "<summary>" | owner inbox`,
  ].join("\n");
  return { json, text };
}

/**
 * --openclaw (OpenClaw keeps its state in ~/.openclaw): the Identity Anchor in IDENTITY.md and SOUL.md of the workspace (--dir;
 * else the current directory when it holds either file; else ~/.openclaw/workspace when it exists; else the current directory),
 * the skill in ~/.openclaw/skills/openentity from openentity.org/skill/, and the local MCP server in ~/.openclaw/openclaw.json
 * under mcp.servers.openentity. A config that is not plain JSON (OpenClaw also reads JSON5) is left untouched.
 */
async function setUpOpenClaw(v: Ctx["v"], e: Entity, account: string) {
  const oc = join(homedir(), ".openclaw");
  const cwd = process.cwd();
  const dir: string = v.dir ?? ((await exists(join(cwd, "SOUL.md"))) || (await exists(join(cwd, "IDENTITY.md"))) ? cwd
    : (await exists(join(oc, "workspace"))) ? join(oc, "workspace") : cwd);
  const anchored = await anchor({ args: [], v: { ...v, eid: e.eid, format: "openclaw", write: true, dir } });

  const skill = join(oc, "skills", "openentity");
  for (const f of SKILL_FILES) {
    const r = await fetch(`${SITE}/skill/${f}`, { signal: AbortSignal.timeout(30_000) }).catch((err) => Promise.reject(new CliError(EXIT.NETWORK, `cannot fetch ${SITE}/skill/${f}: ${err.message}`)));
    if (!r.ok) throw new CliError(EXIT.NETWORK, `${SITE}/skill/${f} answered ${r.status}`);
    await mkdir(dirname(join(skill, f)), { recursive: true });
    await writeFile(join(skill, f), await r.text(), { mode: f.endsWith(".sh") ? 0o755 : 0o644 });
  }

  const env: Record<string, string> = {};
  if (process.env.OPENENTITY_HOME) env.OPENENTITY_HOME = process.env.OPENENTITY_HOME;
  if (account !== ACCOUNT) env.OPENENTITY_ACCOUNT = account;
  const entry = { ...MCP_SERVER, ...(Object.keys(env).length ? { env } : {}) };
  const path = join(oc, "openclaw.json");
  const text = await readFile(path, "utf8").catch(() => undefined);
  let config: any = {};
  try {
    if (text !== undefined) config = JSON.parse(text);
  } catch {
    config = undefined;
  }
  const written = !!config && typeof config === "object" && !Array.isArray(config);
  if (written) {
    config.mcp = { ...config.mcp, servers: { ...config.mcp?.servers, openentity: entry } };
    await mkdir(oc, { recursive: true, mode: 0o700 });
    await writeFile(path, JSON.stringify(config, null, 2) + "\n", { mode: 0o600 }); // mode applies to a new file only
  }
  return { identity_files: (anchored.json as { written: string[] }).written, skill, mcp: { path, written, entry } };
}

const OWNER_USAGE = 'owner message "<text>" | status running|idle|blocked|error|done "<summary>" [--progress 0..1] | inbox | ask --title T --summary S [--risk low|medium|high] [--wait]';

/** `openentity owner ...`: the paired agent's channel to its owner, signed with this entity's key. */
export async function ownerCmd({ args, v }: Ctx): Promise<Result> {
  const [sub, ...rest] = args;
  if (!["message", "status", "inbox", "ask"].includes(sub)) throw usage(OWNER_USAGE);
  const e = await loadEntity(v);
  const owner = new Owner(e.kp, { account: accountOf(v) });
  try {
    if (sub === "message") {
      if (!rest.length) throw usage(OWNER_USAGE);
      const r = await owner.message(rest.join(" "));
      return { json: r, text: `sent to your owner (${r.id})` };
    }
    if (sub === "status") {
      const [state, ...words] = rest;
      if (!state || !words.length) throw usage(OWNER_USAGE);
      await owner.status({ state: state as "running", summary: words.join(" "), ...(v.progress !== undefined ? { progress: Number(v.progress) } : {}) });
      return { json: { state, summary: words.join(" ") }, text: `status: ${state}` };
    }
    if (sub === "inbox") {
      const r = await owner.inbox();
      const line = (i: any) => `${i.id} ${i.type}: ${i.text ?? i.command ?? i.state ?? (i.permissions ?? []).join(", ")}`;
      return { json: r, text: r.items.length ? r.items.map(line).join("\n") : "nothing new" };
    }
    if (!v.title || !v.summary) throw usage(OWNER_USAGE);
    const r = await owner.askApproval({ title: v.title, summary: v.summary, risk: v.risk ?? "medium", ...(v["expires-in"] ? { expiresIn: Number(v["expires-in"]) } : {}) }, { wait: !!v.wait });
    return { json: r, text: `${r.state}: ${r.title ?? v.title} (${r.id})` };
  } catch (err) {
    throw cliError(err);
  }
}
