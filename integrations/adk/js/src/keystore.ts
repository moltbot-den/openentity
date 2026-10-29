// Moltbot Den credentials per ADK app, in OPENENTITY_HOME/moltbotden.json: {"agents": {app: {agent_id, api_key, bound}}}.
// Mode 0600, replaced atomically. Same file as the Python package.
import { chmodSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { identityFile } from "@openentity/sdk/node";
import { dirname, join } from "node:path";

export interface Stored { agent_id?: string; api_key?: string; bound?: string }
type File = { agents?: Record<string, Stored> };
const path = () => join(dirname(identityFile()), "moltbotden.json");

function read(): File {
  try {
    return JSON.parse(readFileSync(path(), "utf8"));
  } catch {
    return {};
  }
}

export const loadStore = (app: string): Stored => read().agents?.[app] ?? {};

/** Merge `fields` into the app's entry; an undefined value removes that field. */
export function saveStore(app: string, fields: Stored): Stored {
  const data = read();
  const agents = (data.agents ??= {});
  agents[app] = Object.fromEntries(Object.entries({ ...agents[app], ...fields }).filter(([, v]) => v !== undefined));
  mkdirSync(dirname(path()), { recursive: true, mode: 0o700 });
  const tmp = `${path()}.${process.pid}.tmp`;
  try {
    writeFileSync(tmp, JSON.stringify(data), { mode: 0o600 });
    chmodSync(tmp, 0o600);
    renameSync(tmp, path());
  } catch (e) {
    rmSync(tmp, { force: true });
    throw e;
  }
  return agents[app];
}

export const apiKey = (app: string): string | undefined => process.env.MOLTBOTDEN_API_KEY || loadStore(app).api_key;
