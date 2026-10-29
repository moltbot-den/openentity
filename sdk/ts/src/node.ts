// Node-only helpers (keys on disk and in the OS keychain). Import from "@openentity/sdk/node".
import { execFileSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, openSync, readFileSync, writeSync, closeSync, constants } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { keyPairFromSeed, type KeyPair } from "./index.ts";

const SERVICE = "openentity", ACCOUNT = "identity";
const run = (cmd: string, args: string[], input?: string): string | null => {
  try {
    return execFileSync(cmd, args, { input, encoding: "utf8", timeout: 10_000, stdio: ["pipe", "pipe", "ignore"] }).trim();
  } catch {
    return null;
  }
};
const keychainOn = () => process.env.OPENENTITY_KEYCHAIN !== "off";
const keychainGet = () =>
  !keychainOn() ? null
  : process.platform === "darwin" ? run("security", ["find-generic-password", "-s", SERVICE, "-a", ACCOUNT, "-w"])
  : process.platform === "linux" ? run("secret-tool", ["lookup", "service", SERVICE, "account", ACCOUNT])
  : null;
const keychainSet = (seedHex: string) =>
  !keychainOn() ? false
  // ponytail: on macOS the seed is briefly on argv, visible to this user's processes only
  : process.platform === "darwin" ? run("security", ["add-generic-password", "-U", "-s", SERVICE, "-a", ACCOUNT, "-w", seedHex]) !== null
  : process.platform === "linux" ? run("secret-tool", ["store", "--label=Open Entity key", "service", SERVICE, "account", ACCOUNT], seedHex) !== null
  : false;
export const identityFile = () => join(process.env.OPENENTITY_HOME || join(homedir(), ".openentity"), "identity.key");

const unhex = (h: string) => Uint8Array.from(h.match(/../g)!, (x) => parseInt(x, 16));
const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

export interface Identity {
  kp: KeyPair;
  did: string;
  seed: Uint8Array;
  source: "keychain" | "file";
}

/** The entity's key from the OS keychain, else `~/.openentity/identity.key` (mode 0600). A fresh key goes to the keychain
 * when one answers, otherwise to the file. OPENENTITY_KEYCHAIN=off uses the file only. Same key file as the Python SDK. */
const make = async (seedHex: string, source: Identity["source"]): Promise<Identity> => {
  const seed = unhex(seedHex), kp = await keyPairFromSeed(seed);
  return { kp, did: kp.did, seed, source };
};

/** The existing identity, or null. Never creates one. */
async function load(): Promise<Identity | null> {
  const fromKeychain = keychainGet();
  if (fromKeychain) return make(fromKeychain, "keychain");
  return existsSync(identityFile()) ? make(readFileSync(identityFile(), "utf8").trim(), "file") : null;
}

async function loadOrCreate(): Promise<Identity> {
  const found = await load();
  if (found) return found;
  const file = identityFile();
  const seedHex = hex(crypto.getRandomValues(new Uint8Array(32)));
  if (keychainSet(seedHex)) return make(seedHex, "keychain");
  mkdirSync(dirname(file), { recursive: true, mode: 0o700 });
  try {
    const fd = openSync(file, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 0o600);
    writeSync(fd, seedHex);
    closeSync(fd);
  } catch (e: any) {
    if (e.code !== "EEXIST") throw e; // another process created it first
    return make(readFileSync(file, "utf8").trim(), "file");
  }
  chmodSync(file, 0o600);
  return make(seedHex, "file");
}

export const Identity = { load, loadOrCreate };
