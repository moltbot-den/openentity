import {
  keyPairFromSeed
} from "./chunk-KN2ECPHF.js";

// src/node.ts
import { execFileSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, openSync, readFileSync, writeSync, closeSync, constants } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
var SERVICE = "openentity";
var ACCOUNT = "identity";
var run = (cmd, args, input) => {
  try {
    return execFileSync(cmd, args, { input, encoding: "utf8", timeout: 1e4, stdio: ["pipe", "pipe", "ignore"] }).trim();
  } catch {
    return null;
  }
};
var keychainOn = () => process.env.OPENENTITY_KEYCHAIN !== "off";
var macKeychain = () => process.platform === "darwin" && existsSync(join(homedir(), "Library", "Keychains"));
var keychainGet = () => !keychainOn() ? null : macKeychain() ? run("security", ["find-generic-password", "-s", SERVICE, "-a", ACCOUNT, "-w"]) : process.platform === "linux" ? run("secret-tool", ["lookup", "service", SERVICE, "account", ACCOUNT]) : null;
var keychainSet = (seedHex) => !keychainOn() ? false : macKeychain() ? run("security", ["add-generic-password", "-U", "-s", SERVICE, "-a", ACCOUNT, "-w", seedHex]) !== null : process.platform === "linux" ? run("secret-tool", ["store", "--label=Open Entity key", "service", SERVICE, "account", ACCOUNT], seedHex) !== null : false;
var identityFile = () => join(process.env.OPENENTITY_HOME || join(homedir(), ".openentity"), "identity.key");
var unhex = (h) => Uint8Array.from(h.match(/../g), (x) => parseInt(x, 16));
var hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
var make = async (seedHex, source) => {
  const seed = unhex(seedHex), kp = await keyPairFromSeed(seed);
  return { kp, did: kp.did, seed, source };
};
async function load() {
  const fromKeychain = keychainGet();
  if (fromKeychain) return make(fromKeychain, "keychain");
  return existsSync(identityFile()) ? make(readFileSync(identityFile(), "utf8").trim(), "file") : null;
}
async function loadOrCreate() {
  const found = await load();
  if (found) return found;
  const file = identityFile();
  const seedHex = hex(crypto.getRandomValues(new Uint8Array(32)));
  if (keychainSet(seedHex)) return make(seedHex, "keychain");
  mkdirSync(dirname(file), { recursive: true, mode: 448 });
  try {
    const fd = openSync(file, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 384);
    writeSync(fd, seedHex);
    closeSync(fd);
  } catch (e) {
    if (e.code !== "EEXIST") throw e;
    return make(readFileSync(file, "utf8").trim(), "file");
  }
  chmodSync(file, 384);
  return make(seedHex, "file");
}
var Identity = { load, loadOrCreate };
export {
  Identity,
  identityFile
};
