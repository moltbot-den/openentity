import { spawnSync } from "node:child_process";
import { readFile, rm, writeFile, mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { base58btcEncode, nowSeconds, signObject, validate } from "@openentity/sdk";
import { walletDid } from "./adopt";
import { CliError, EXIT, stateErr, usage } from "./errors";
import type { Obj } from "./http";
import { checksum, resolveSigner, type Signer } from "./wallet";
import { loadEntity, readJson, saveState, strip, writeJson, type Ctx, type Entity, type Result } from "./store";

const FROZEN = new Set(["spec", "eid", "created", "updated", "seq", "keys", "proof"]);
const UNSAFE = new Set(["__proto__", "constructor", "prototype"]);

async function draftOf(e: Entity): Promise<Obj> {
  return readJson(join(e.dir, "draft.json")).catch(() => strip(e.doc));
}
const saveDraft = (e: Entity, d: Obj) => writeJson(join(e.dir, "draft.json"), d);

function setPath(o: Obj, path: string, value: unknown) {
  const keys = path.split(".");
  if (keys.some((k) => !k || UNSAFE.has(k))) throw usage(`bad field path: ${path}`);
  if (FROZEN.has(keys[0])) throw usage(`${keys[0]} is managed by the CLI and cannot be set`);
  let cur = o;
  for (const k of keys.slice(0, -1)) {
    if (typeof cur[k] !== "object" || cur[k] === null) cur[k] = {};
    cur = cur[k];
  }
  cur[keys.at(-1)!] = value;
}

const parseValue = (s: string) => {
  try {
    return JSON.parse(s);
  } catch {
    return s;
  }
};

/** document edit | set <field> <value> | push. Edits go to draft.json; push signs seq+1 and PUTs it. */
export async function documentCmd({ args, v }: Ctx): Promise<Result> {
  const e = await loadEntity(v);
  const [sub, field, value] = args;
  if (sub === "set") {
    if (!field || value === undefined) throw usage('document set <field> <value>   (dotted path, JSON or plain string, e.g. layers.mission.statement "...")');
    const d = await draftOf(e);
    setPath(d, field, parseValue(value));
    await saveDraft(e, d);
    return { json: { draft: field }, text: `draft updated: ${field}. Publish with: openentity document push` };
  }
  if (sub === "edit") {
    const editor = process.env.VISUAL || process.env.EDITOR;
    if (!editor) throw usage("document edit needs $EDITOR; use document set <field> <value> instead");
    const tmp = join(await mkdtemp(join(tmpdir(), "oe-edit-")), "document.json");
    try {
      await writeFile(tmp, JSON.stringify(await draftOf(e), null, 2) + "\n");
      const r = spawnSync(editor, [tmp], { stdio: "inherit", shell: true });
      if (r.status !== 0) throw usage(`editor exited with ${r.status}`);
      const edited = JSON.parse(await readFile(tmp, "utf8"));
      for (const k of FROZEN) if (JSON.stringify(edited[k]) !== JSON.stringify(strip(e.doc)[k])) delete edited[k], (edited[k] = strip(e.doc)[k]);
      await saveDraft(e, edited);
    } catch (err: any) {
      if (err instanceof CliError) throw err;
      throw usage(`edited document is not valid JSON: ${err.message}`);
    } finally {
      await rm(join(tmp, ".."), { recursive: true, force: true });
    }
    return { json: { draft: true }, text: "draft saved. Publish with: openentity document push" };
  }
  if (sub !== "push") throw usage("document edit|set <field> <value>|push");

  const d = await draftOf(e);
  if (JSON.stringify(d) === JSON.stringify(strip(e.doc))) return { json: { pushed: false }, text: "nothing to push" };
  d.seq = e.doc.seq + 1;
  // updated MUST increase (spec 5.5); two pushes in one second would tie, so step past the last one.
  const now = nowSeconds();
  d.updated = now > e.doc.updated ? now : new Date(Date.parse(e.doc.updated) + 1000).toISOString().replace(/\.\d+Z$/, "Z");
  const signed = await signObject(d, e.kp);
  const ok = validate("EntityDocument", signed);
  if (!ok.ok) throw new CliError(EXIT.VERIFY, `document fails schema validation: ${ok.errors.join("; ")}`);
  await e.registry.send("PUT", `/v1/entities/${e.eid}/document`, signed, e.eid);
  await writeJson(join(e.dir, "entity.json"), signed);
  await rm(join(e.dir, "draft.json"), { force: true });
  e.state.docSeq = signed.seq;
  await saveState(e);
  return { json: { pushed: true, seq: signed.seq }, text: `published document seq ${signed.seq}` };
}

// --- aliases (spec 3.4, 3.5) ---

const ALNUM = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const nonce = () => [...crypto.getRandomValues(new Uint8Array(16))].map((b) => ALNUM[b % ALNUM.length]).join("");

/** EIP-4361 message with the fixed fields of spec 3.5. */
export function siweMessage(host: string, address: string, chainId: number, eid: string, issuedAt: string, n = nonce()): string {
  return [
    `${host} wants you to sign in with your Ethereum account:`,
    address,
    "",
    `Open Entity alias binding for ${eid}`,
    "",
    `URI: https://${host}/v1/entities/${eid}`,
    "Version: 1",
    `Chain ID: ${chainId}`,
    `Nonce: ${n}`,
    `Issued At: ${issuedAt}`,
    "Resources:",
    `- ${eid}`,
  ].join("\n");
}

/** Two-step wallet proof: first call prints the message and stores it, second call attaches --signature. */
async function walletProof(e: Entity, v: Obj, wallet: string, chain: number, signer?: Signer | null): Promise<{ proof?: Obj; address: string; prompt?: Result }> {
  const address = checksum(wallet);
  if (signer) {
    if (signer.address !== address) throw usage(`the wallet key controls ${signer.address}, not ${address}`);
    const message = siweMessage(new URL(e.registry.base).host, address, chain, e.eid, nowSeconds());
    return { address, proof: { type: "Eip4361", message, signature: signer.sign(message) } };
  }
  const pendingFile = join(e.dir, `pending-wallet-${address.toLowerCase()}.json`);
  if (!v.signature) {
    const message = siweMessage(new URL(e.registry.base).host, address, chain, e.eid, nowSeconds());
    await writeJson(pendingFile, { message });
    const cmd = `openentity alias add ${v._kind} ${v._value} --wallet ${address} --signature 0x<signature>`;
    return { address, prompt: { json: { message, next: cmd }, text: `Sign this message with ${address} (EIP-191 personal_sign), then run:\n  ${cmd}\n\n${message}` } };
  }
  const { message } = await readJson(pendingFile).catch(() => {
    throw stateErr(`no pending message for ${address}: run the command without --signature first`);
  });
  if (!/^0x[0-9a-fA-F]+$/.test(v.signature)) throw usage("--signature must be 0x-prefixed hex");
  return { address, proof: { type: "Eip4361", message, signature: v.signature } };
}

export async function alias({ args, v }: Ctx): Promise<Result> {
  const [sub, type] = args;
  const signer = await resolveSigner(v.wallet);
  const raw = args[2] ?? (type === "wallet" ? signer?.address : undefined);
  if (sub !== "add" || !type || !raw) throw usage("alias add domain|wallet|erc8004|platform <value>");
  const e = await loadEntity(v);
  let a: Obj;
  let hint = "";
  if (type === "domain") {
    const domain = raw.replace(/^did:web:/, "");
    a = { type, value: `did:web:${domain}` };
    hint = `Publish {"eid": "${e.eid}"} at https://${domain}/.well-known/openentity.json (or DNS TXT _openentity.${domain} = eid=${e.eid}), then re-run.`;
  } else if (type === "wallet") {
    const chain = Number(v.chain ?? 8453);
    const did = walletDid(raw, chain);
    const parts = did.split(":");
    v._kind = type;
    v._value = raw;
    const w = await walletProof(e, v, parts[4], Number(parts[3]), signer);
    if (w.prompt) return w.prompt;
    a = { type, value: `did:pkh:eip155:${parts[3]}:${w.address}`, proof: w.proof };
  } else if (type === "erc8004") {
    if (!/^eip155:\d+:0x[0-9a-fA-F]{40}:\d+$/.test(raw)) throw usage("erc8004 value is eip155:<chainId>:<identityRegistry>:<agentId>");
    a = { type, value: raw };
    if (signer || v.wallet) {
      v._kind = type;
      v._value = raw;
      const w = await walletProof(e, v, signer ? signer.address : walletDid(v.wallet).split(":")[4], Number(raw.split(":")[1]), signer);
      if (w.prompt) return w.prompt;
      a.proof = w.proof;
    } else hint = "Without --wallet the registry checks that your ERC-8004 registration file lists a DID service whose endpoint is your EID.";
  } else if (type === "platform") {
    if (!/^[a-z0-9._-]+:[^\s:]+$/i.test(raw)) throw usage("platform value is <platform>:<handle>");
    const issued = nowSeconds();
    const text = `Open Entity alias binding\neid: ${e.eid}\nalias: ${raw}\nissued: ${issued}`;
    const sig = new Uint8Array(await crypto.subtle.sign("Ed25519", e.kp.privateKey, new TextEncoder().encode(text)));
    a = { type, value: raw, proof: { type: "Ed25519BindingSignature", issued, proofValue: "z" + base58btcEncode(sig) } };
    const [platform, handle] = raw.split(":");
    hint = `The platform must also publish {"eid": "${e.eid}"} at https://<${platform} domain>/.well-known/openentity/bindings/${handle}.json, or issue an identity attestation.`;
  } else throw usage("alias type must be domain, wallet, erc8004 or platform");

  let res: Obj;
  try {
    res = await e.registry.send("POST", `/v1/entities/${e.eid}/aliases`, a, e.eid);
  } catch (err) {
    if (err instanceof CliError && hint) err.message += `\n${hint}`;
    throw err;
  }
  // Keep the next document version consistent with what the registry now verifies.
  const d = await draftOf(e);
  d.aliases = [...(d.aliases ?? []).filter((x: Obj) => x.value !== a.value), a];
  await saveDraft(e, d);
  return { json: { alias: a, result: res }, text: `alias ${a.value} accepted${res?.verified === false ? " (not yet verified)" : ""}. Add it to your signed document with: openentity document push` };
}
