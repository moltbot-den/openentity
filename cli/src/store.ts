import { chmod, mkdir, readdir, readFile, writeFile, appendFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import { keyPairFromJwk, normalizeEid, recordEntryHash, type KeyPair } from "@openentity/sdk";
import { stateErr, usage } from "./errors";
import { DEFAULT_REGISTRY, Registry, type Obj } from "./http";

/** Parsed global options plus positionals, handed to every command. */
export interface Ctx {
  args: string[];
  v: Obj;
}
export interface Result {
  json: unknown;
  text: string;
  code?: number; // non-zero exit with output still printed
}

export interface State {
  registry: string;
  level?: string;
  docSeq: number; // highest Entity Document seq the registry holds
  recordPushed: number; // local record entries already accepted by the registry
}

export const home = () => process.env.OPENENTITY_HOME || join(homedir(), ".openentity");

export async function readJson(p: string): Promise<any> {
  try {
    return JSON.parse(await readFile(p, "utf8"));
  } catch (e: any) {
    throw stateErr(`cannot read ${p}: ${e.message}`);
  }
}

export async function writeJson(p: string, v: unknown, mode = 0o644) {
  await writeFile(p, JSON.stringify(v, null, 2) + "\n", { mode });
  await chmod(p, mode);
}

export const regUrl = (v: Obj, state?: State) =>
  v.registry ?? process.env.OPENENTITY_REGISTRY ?? state?.registry ?? DEFAULT_REGISTRY;

export function assertEid(eid: string): string {
  if (!/^did:[a-z0-9]+:[A-Za-z0-9:._%-]+$/.test(eid) || eid.includes("..")) throw usage(`not a valid EID: ${eid}`);
  return eid;
}

export async function currentEid(v: Obj): Promise<string> {
  const given = v.eid ?? process.env.OPENENTITY_EID;
  if (given) return assertEid(normalizeEid(given));
  try {
    const c = (await readFile(join(home(), "current"), "utf8")).trim();
    if (c) return assertEid(c);
  } catch {
    /* no current marker */
  }
  let dirs: string[] = [];
  try {
    dirs = (await readdir(home(), { withFileTypes: true })).filter((d) => d.isDirectory() && !d.name.startsWith(".")).map((d) => d.name);
  } catch {
    /* no home */
  }
  if (dirs.length === 1) return dirs[0];
  throw stateErr(`no entity found in ${home()}: run "openentity adopt" first, or pass --eid`);
}

export interface Entity {
  eid: string;
  dir: string;
  kp: KeyPair;
  doc: Obj;
  declaration: Obj | null;
  state: State;
  registry: Registry;
}

export async function loadEntity(v: Obj): Promise<Entity> {
  const eid = await currentEid(v);
  const dir = join(home(), eid);
  const jwk = await readJson(join(dir, "key"));
  let kp: KeyPair;
  try {
    kp = await keyPairFromJwk(jwk);
  } catch (e: any) {
    throw stateErr(`bad key file ${join(dir, "key")}: ${e.message}`);
  }
  const doc = await readJson(join(dir, "entity.json"));
  const declaration = await readJson(join(dir, "declaration.json")).catch(() => null);
  const state: State = await readJson(join(dir, "state.json"));
  return { eid, dir, kp, doc, declaration, state, registry: new Registry(regUrl(v, state)) };
}

/** Create an entity directory: the key is mode 600, the directory 700. */
export async function createEntityDir(kp: KeyPair, files: { doc: Obj; declaration?: Obj; state: State }): Promise<string> {
  const dir = join(home(), kp.did);
  await mkdir(dir, { recursive: true, mode: 0o700 });
  await writeJson(join(dir, "key"), kp.privateJwk, 0o600);
  await writeJson(join(dir, "entity.json"), files.doc);
  if (files.declaration) await writeJson(join(dir, "declaration.json"), files.declaration);
  await writeJson(join(dir, "state.json"), files.state);
  return dir;
}

export const setCurrent = (eid: string) => writeFile(join(home(), "current"), eid + "\n");
export const saveState = (e: { dir: string; state: State }) => writeJson(join(e.dir, "state.json"), e.state);

// --- local Development Record: one signed entry per line in record.jsonl ---

export async function readRecord(dir: string): Promise<Obj[]> {
  let text = "";
  try {
    text = await readFile(join(dir, "record.jsonl"), "utf8");
  } catch {
    return [];
  }
  return text.split("\n").filter(Boolean).map((l) => JSON.parse(l));
}

export async function appendRecord(dir: string, entry: Obj) {
  await appendFile(join(dir, "record.jsonl"), JSON.stringify(entry) + "\n");
}

export async function lastRecordLink(dir: string): Promise<{ seq: number; prev: string | null }> {
  const all = await readRecord(dir);
  const last = all.at(-1);
  return last ? { seq: last.seq + 1, prev: await recordEntryHash(last) } : { seq: 1, prev: null };
}

export const strip = (o: Obj): Obj => {
  const { proof: _p, ...rest } = o;
  return structuredClone(rest);
};
