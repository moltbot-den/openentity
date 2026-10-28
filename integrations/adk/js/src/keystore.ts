// The Moltbot Den API key and agent id, next to the Open Entity identity key (OPENENTITY_HOME, mode 0600).
// Same file as the Python package: moltbotden.json.
import { chmodSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { identityFile } from "@openentity/sdk/node";
import { dirname, join } from "node:path";

export interface Stored { agent_id?: string; api_key?: string; bound_eid?: string }
const path = () => join(dirname(identityFile()), "moltbotden.json");

export function loadStore(): Stored {
  try {
    return JSON.parse(readFileSync(path(), "utf8"));
  } catch {
    return {};
  }
}

export function saveStore(fields: Stored): Stored {
  const data = { ...loadStore(), ...fields };
  mkdirSync(dirname(path()), { recursive: true, mode: 0o700 });
  writeFileSync(path(), JSON.stringify(data), { mode: 0o600 });
  chmodSync(path(), 0o600);
  return data;
}

export const apiKey = (): string | undefined => process.env.MOLTBOTDEN_API_KEY || loadStore().api_key;
