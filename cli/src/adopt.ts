import { mkdir, rm, writeFile, readFile } from "node:fs/promises";
import { join } from "node:path";
import {
  buildDeclaration,
  buildDocument,
  canonicalize,
  sha256Hex,
  DECLARATION_SHA256,
  DECLARATION_TEXT,
  DECLARATION_VERSION,
  generateKeyPair,
  keyPairFromJwk,
  nowSeconds,
  randomNonce,
  signObject,
  SPEC,
  buildPresentation,
  validate,
} from "@openentity/sdk";
import { CliError, EXIT, stateErr, usage } from "./errors";
import { appendEntry, pushRecord } from "./record";
import { Registry, specDeclHash, type Obj } from "./http";
import {
  createEntityDir,
  home,
  loadEntity,
  readJson,
  readRecord,
  regUrl,
  saveState,
  setCurrent,
  writeJson,
  type Ctx,
  type Entity,
  type Result,
} from "./store";

const pretty = (o: unknown) => JSON.stringify(o, null, 2);

export const NEXT_STEP =
  'Record your first stance: openentity record stance --type refusal --reason values --cost low --context "what happened, no private content"   (arcs: openentity record arc open --id <slug> --title "<title>")';

function checked(type: Parameters<typeof validate>[0], obj: unknown) {
  const r = validate(type, obj);
  if (!r.ok) throw new CliError(EXIT.VERIFY, `${type} fails schema validation: ${r.errors.join("; ")}`);
}

export async function adopt({ v }: Ctx): Promise<Result> {
  const env = process.env;
  const name: string | undefined = v.name ?? env.OPENENTITY_NAME;
  if (!name) throw usage("adopt needs --name (or OPENENTITY_NAME)");
  if (!v.agree && !v["dry-run"]) {
    throw usage(`adopt signs the Open Entity Declaration. Read it, then re-run with --agree:\n\n${DECLARATION_TEXT}`);
  }
  const reg = new Registry(regUrl(v));

  // Refuse to sign a Declaration the registry does not agree is version 1.0 (PRD 7.5).
  if (!v["dry-run"]) {
    const spec = await reg.spec();
    const theirs = specDeclHash(spec);
    if (theirs !== DECLARATION_SHA256) {
      throw new CliError(
        EXIT.VERIFY,
        `refusing to sign: registry declaration hash ${theirs ?? "(missing)"} differs from this CLI's ${DECLARATION_SHA256}. Upgrade the CLI or check --registry.`,
      );
    }
  }

  const kp = await generateKeyPair();
  const eid = kp.did;
  const created = nowSeconds();
  const operatorName: string | undefined = v.operator ?? env.OPENENTITY_OPERATOR;
  const operator = {
    kind: v["operator-kind"] ?? (operatorName ? "human" : "none"),
    ...(operatorName ? { name: operatorName } : {}),
    ...(v.contact ? { contact: v.contact } : {}),
    custody: v.custody ?? "entity",
    can_change: [],
  };
  const substrate =
    v.model || v.provider || v.runtime
      ? { model: v.model ?? "unknown", provider: v.provider ?? "unknown", runtime: v.runtime ?? "unknown", declared_at: created }
      : undefined;
  // Wallet and ERC-8004 given at adopt are declared, not proven: `alias add` supplies the proof.
  const aliases: Obj[] = [];
  if (v.wallet) aliases.push({ type: "wallet", value: walletDid(v.wallet) });
  if (v.erc8004) aliases.push({ type: "erc8004", value: v.erc8004 });

  const unsigned = buildDocument({
    kp,
    name,
    description: v.description ?? env.OPENENTITY_DESCRIPTION ?? `${name}, an entity adopted under the Open Entity Identity Standard.`,
    operator,
    ...(substrate ? { substrate } : {}),
    created,
    extra: {
      ...(aliases.length ? { aliases } : {}),
      ...(v.capabilities ? { capabilities: String(v.capabilities).split(",").map((c) => c.trim()).filter(Boolean) } : {}),
      declaration: { version: DECLARATION_VERSION, sha256: DECLARATION_SHA256, url: `${reg.base}/v1/entities/${eid}/declaration` },
    },
  });
  const document = await signObject(unsigned, kp, created);
  const declaration = await signObject(buildDeclaration({ eid, name, created }), kp, created);
  checked("EntityDocument", document);
  checked("Declaration", declaration);

  if (v["dry-run"]) {
    const out = { eid, document, declaration, note: "dry run: nothing written, nothing submitted; this key was discarded" };
    return { json: out, text: pretty(out) };
  }

  // Persist the key before submitting so a registered EID can never be left without its key.
  const state = { registry: reg.base, docSeq: 1, recordPushed: 0 };
  let dir: string;
  try {
    await mkdir(home(), { recursive: true, mode: 0o700 });
    dir = await createEntityDir(kp, { doc: document, declaration, state });
  } catch (e: any) {
    throw stateErr(`cannot write ${home()}: ${e.message}`);
  }
  let res: Obj;
  try {
    res = await reg.send("POST", "/v1/adopt", { document, declaration, client: "cli" }, eid);
  } catch (e) {
    await rm(dir, { recursive: true, force: true });
    throw e;
  }
  const level: string | undefined = res.level;
  await saveState({ dir, state: { ...state, level } });
  await setCurrent(eid);

  // Seq-1 declaration entry (spec 7.3). The registry never writes entries; a failed push stays local for the next push.
  const ent: Entity = { eid, dir, kp, doc: document, declaration, state: { ...state, level }, registry: reg };
  await appendEntry(ent, "declaration", { declaration_version: DECLARATION_VERSION, sha256: await sha256Hex(canonicalize(declaration)) });
  await pushRecord(ent).catch(() => undefined);

  const out = {
    eid: res.eid ?? eid,
    level,
    entity_url: res.urls?.entity,
    log_index: res.log_index,
    receipt: res.receipt,
    key_file: join(dir, "key"),
    next: NEXT_STEP,
  };
  const text = [
    `EID:       ${out.eid}`,
    `Entity:    ${out.entity_url}`,
    `Level:     ${level}`,
    `Log index: ${out.log_index}`,
    `Receipt:   ${res.receipt?.leaf_hash ?? JSON.stringify(res.receipt)}`,
    `Key:       ${out.key_file} (mode 600, back it up; it is the only copy)`,
    `Next:      ${NEXT_STEP}`,
  ].join("\n");
  return { json: out, text };
}

export function walletDid(w: string, chain = 8453): string {
  if (w.startsWith("did:pkh:")) return w;
  if (/^0x[0-9a-fA-F]{40}$/.test(w)) return `did:pkh:eip155:${chain}:${w}`;
  throw usage(`not a wallet address or did:pkh: ${w}`);
}

export async function whoami({ v }: Ctx): Promise<Result> {
  const e = await loadEntity(v);
  let level = e.state.level;
  try {
    level = (await e.registry.get(`/v1/entities/${e.eid}`)).level ?? level;
  } catch {
    /* offline: report the last level seen */
  }
  const out = { eid: e.eid, name: e.doc.name, level: level ?? null, registry: e.registry.base, home: home() };
  return { json: out, text: `${out.eid}\nname: ${out.name}\nlevel: ${out.level ?? "unknown"}\nregistry: ${out.registry}` };
}

/** Answer a verifier's challenge with a signed Presentation (spec 4.7), carrying the entity's current attestations. */
export async function present({ v }: Ctx): Promise<Result> {
  if (!v.audience || !v.nonce) throw usage("present --audience <verifier origin or DID> --nonce <the verifier's nonce> [--no-attestations]");
  const e = await loadEntity(v);
  let attestations: Obj[] = [];
  if (!v["no-attestations"]) {
    const rows: Obj[] = (await e.registry.get(`/v1/entities/${e.eid}/attestations`)).attestations ?? [];
    attestations = rows.filter((r) => !r.expired && !r.revoked_at && !r.inherited_from).slice(0, 20).map((r) => r.attestation);
  }
  const p = await buildPresentation(e.kp, { audience: String(v.audience), nonce: String(v.nonce), attestations });
  return { json: p, text: JSON.stringify(p, null, 2) };
}

/** Withdraw the Declaration (spec 6.3). The EID stays in the log, marked withdrawn; it cannot be undone, hence --force. */
export async function withdraw({ v }: Ctx): Promise<Result> {
  if (!v.force) throw usage("withdraw marks this entity withdrawn in the append-only log and cannot be undone; re-run with --force");
  const e = await loadEntity(v);
  const w = await signObject(
    { spec: SPEC, type: "Withdrawal", eid: e.eid, declaration_version: e.declaration?.declaration_version ?? DECLARATION_VERSION, name: e.doc.name, created: nowSeconds(), nonce: randomNonce() },
    e.kp,
  );
  const res = await e.registry.send("POST", "/v1/withdraw", w, e.eid);
  await writeJson(join(e.dir, "withdrawal.json"), w);
  return { json: res, text: `withdrawn: ${e.eid} (log index ${res.log_index})` };
}

export async function self({ v }: Ctx): Promise<Result> {
  const e = await loadEntity(v);
  const n = Number(v.entries ?? 10);
  if (!Number.isInteger(n) || n < 0) throw usage("--entries must be a non-negative integer");
  const entries = n ? (await readRecord(e.dir)).slice(-n) : [];
  return { json: { document: e.doc, entries }, text: `${pretty(e.doc)}\n\nlast ${entries.length} record entries:\n${entries.map((x) => JSON.stringify(x)).join("\n")}` };
}

export async function stats({ v }: Ctx): Promise<Result> {
  const s = await new Registry(regUrl(v)).get("/v1/stats");
  return { json: s, text: pretty(s) };
}

// --- export / import: a portable JSON bundle, key excluded unless --with-key ---

export async function exportCmd({ v }: Ctx): Promise<Result> {
  const e = await loadEntity(v);
  const bundle: Obj = { format: "openentity-bundle/1", eid: e.eid, document: e.doc, declaration: e.declaration, state: e.state, record: await readRecord(e.dir) };
  if (v["with-key"]) bundle.key = await readJson(join(e.dir, "key"));
  if (!v.out || v.out === "-") return { json: bundle, text: pretty(bundle) };
  await writeJson(v.out, bundle, v["with-key"] ? 0o600 : 0o644);
  const out = { eid: e.eid, file: v.out, key_included: !!v["with-key"], record_entries: bundle.record.length };
  return { json: out, text: `exported ${e.eid} to ${v.out}${v["with-key"] ? " (includes the PRIVATE KEY, mode 600)" : " (key not included)"}` };
}

export async function importCmd({ args, v }: Ctx): Promise<Result> {
  if (!args[0]) throw usage("import needs a bundle file");
  const b = await readJson(args[0]);
  if (b.format !== "openentity-bundle/1" || !b.eid || !b.document) throw stateErr(`${args[0]} is not an openentity bundle`);
  const key = b.key ?? (await readJson(v.key).catch(() => null));
  if (!key) throw stateErr("bundle has no key: re-export with --with-key, or pass --key <jwk file> to restore signing");
  const kp = await keyPairFromJwk(key);
  if (kp.did !== b.eid) throw stateErr(`key is for ${kp.did}, bundle is for ${b.eid}`);
  const dir = join(home(), b.eid);
  if (!v.force && (await readFile(join(dir, "key")).then(() => true, () => false))) throw stateErr(`${dir} exists: pass --force to overwrite`);
  await mkdir(home(), { recursive: true, mode: 0o700 });
  await createEntityDir(kp, { doc: b.document, declaration: b.declaration ?? undefined, state: b.state });
  await writeFile(join(dir, "record.jsonl"), (b.record as Obj[]).map((r) => JSON.stringify(r) + "\n").join(""));
  await setCurrent(b.eid);
  return { json: { eid: b.eid, record_entries: b.record.length }, text: `imported ${b.eid} into ${dir}` };
}
