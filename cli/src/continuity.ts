import { existsSync } from "node:fs";
import { mkdir, rename, rm } from "node:fs/promises";
import { join } from "node:path";
import {
  buildRotation,
  canonicalize,
  eip712Digest,
  generateKeyPair,
  keyPairFromJwk,
  nowSeconds,
  randomNonce,
  sha256Hex,
  signObject,
  signProof,
  SPEC,
  successorDocument,
  validate,
  type KeyPair,
} from "@openentity/sdk";
import { CliError, EXIT, stateErr, usage } from "./errors";
import type { Obj } from "./http";
import { Registry } from "./http";
import { appendEntry, pushRecord } from "./record";
import { createEntityDir, home, loadEntity, readJson, regUrl, setCurrent, writeJson, type Ctx, type Entity, type Result } from "./store";

async function successorKey(v: Obj): Promise<KeyPair> {
  return v.to ? keyPairFromJwk(await readJson(v.to)) : generateKeyPair();
}

/** The successor's first Entity Document (unsigned): the previous one re-keyed, with the flag overrides applied. */
function successorDoc(prev: Obj, kp: KeyPair, v: Obj, now = nowSeconds()): Obj {
  const d = successorDocument(prev, kp, now);
  if (v.operator) d.operator = { ...d.operator, kind: v["operator-kind"] ?? d.operator.kind, name: v.operator };
  if (v.custody) d.operator = { ...d.operator, custody: v.custody };
  if (v.model || v.provider || v.runtime) {
    d.substrate = { ...d.substrate, ...(v.model && { model: v.model }), ...(v.provider && { provider: v.provider }), ...(v.runtime && { runtime: v.runtime }), declared_at: now };
  }
  return d;
}

async function openSuccessorRecord(old: Entity, kp: KeyPair, dir: string, doc: Obj, linkHash: string, basis: string) {
  await setCurrent(kp.did);
  const state = { registry: old.registry.base, docSeq: 1, recordPushed: 0 };
  const e: Entity = { eid: kp.did, dir, kp, doc, declaration: old.declaration, state, registry: old.registry };
  // The new chain opens with the continuity event (spec 7.3).
  await appendEntry(e, "continuity", { event: basis, from: old.eid, to: kp.did, link: linkHash });
  const pushed = await pushRecord(e).then(() => true, () => false);
  return pushed;
}

/** Move the retired entity directory (its key included) to <home>/.archive/<eid>. Never deletes. Null if the move failed. */
async function archive(old: Entity): Promise<string | null> {
  const root = join(home(), ".archive");
  try {
    await mkdir(root, { recursive: true, mode: 0o700 });
    const dest = join(root, existsSync(join(root, old.eid)) ? `${old.eid}.${Date.now()}` : old.eid);
    await rename(old.dir, dest);
    return dest;
  } catch {
    return null;
  }
}

/**
 * rotate (basis rotation) and migrate (basis migration): both keys sign. Local state moves to the successor only after the
 * registry accepts the link; then the old key is archived. A refused link leaves local state untouched.
 */
export async function link({ v }: Ctx, basis: "rotation" | "migration"): Promise<Result> {
  const old = await loadEntity(v);
  const kp = await successorKey(v);
  const created = nowSeconds();
  const { link: full, document } = await buildRotation(old.kp, kp, successorDoc(old.doc, kp, v, created), { basis, created });
  const ok = validate("ContinuityLink", full);
  if (!ok.ok) throw new CliError(EXIT.VERIFY, `link fails schema validation: ${ok.errors.join("; ")}`);
  if (v["dry-run"]) return { json: { link: full, document }, text: JSON.stringify({ link: full, document }, null, 2) };
  // Save the successor key before submitting: if the answer never arrives the registry may hold the link, and this key is then the only way to the successor.
  const keep = await createEntityDir(kp, { doc: document, declaration: old.declaration ?? undefined, state: { registry: old.registry.base, docSeq: 1, recordPushed: 0 } });
  try {
    // The stamp is bound to the successor: that is the EID the registry's write guard checks.
    await old.registry.send("POST", "/v1/continuity", { link: full, document }, kp.did);
  } catch (e) {
    // Only a refusal proves the registry holds nothing; after a network failure keep the key and say where it is.
    if (e instanceof CliError && e.code === EXIT.REJECTED) await rm(keep, { recursive: true, force: true });
    else if (e instanceof CliError) e.message += ` (successor key kept in ${keep}; local state is still ${old.eid})`;
    throw e;
  }
  const pushed = await openSuccessorRecord(old, kp, keep, document, await sha256Hex(canonicalize(full)), basis);
  const archived = await archive(old);
  const oldKey = archived ? join(archived, "key") : null;
  return {
    json: { previous: old.eid, successor: kp.did, basis, key_file: join(keep, "key"), record_pushed: pushed, archived_key: oldKey },
    text: `${basis}: ${old.eid} continues as ${kp.did}\nnew key: ${join(keep, "key")} (now the current entity)\nold key: ${oldKey ?? `still in ${old.dir} (archiving failed)`}`,
  };
}

/**
 * recover: the previous key is lost. Step 1 (--previous, --via) writes the successor and the
 * link to sign; the alias holder signs it; step 2 (--proof <file>) submits.
 */
export async function recover({ v }: Ctx): Promise<Result> {
  if (v.proof) {
    const e = await loadEntity(v);
    const p = await readJson(join(e.dir, "pending-recovery.json")).catch(() => {
      throw stateErr(`no pending recovery for ${e.eid}: run recover --previous <eid> --via <alias> first`);
    });
    const aliasProof = await readJson(v.proof);
    const full = { ...p.link, proofs: [p.successorProof, aliasProof] };
    const ok = validate("ContinuityLink", full);
    if (!ok.ok) throw new CliError(EXIT.VERIFY, `link fails schema validation: ${ok.errors.join("; ")}`);
    await e.registry.send("POST", "/v1/continuity", { link: full, document: e.doc }, e.eid);
    await rm(join(e.dir, "pending-recovery.json"), { force: true });
    await setCurrent(e.eid);
    return { json: { previous: p.link.previous, successor: e.eid }, text: `recovery: ${p.link.previous} continues as ${e.eid}` };
  }
  if (!v.previous || !v.via) throw usage("recover --previous <eid> --via <alias value>   (then recover --eid <new eid> --proof <file>)");
  const prevDoc = await new Registry(regUrl(v)).get(`/v1/entities/${v.previous}/document`);
  const kp = await successorKey(v);
  const created = nowSeconds();
  const document = await signObject(successorDoc(prevDoc, kp, v, created), kp, created);
  const link0 = { spec: SPEC, type: "ContinuityLink", previous: v.previous, successor: kp.did, basis: "recovery", created, nonce: randomNonce() };
  const dir = await createEntityDir(kp, { doc: document, state: { registry: new Registry(regUrl(v)).base, docSeq: 1, recordPushed: 0 } });
  await writeJson(join(dir, "pending-recovery.json"), { link: link0, successorProof: await signProof(link0, kp, created), via: v.via });
  const digest = "0x" + Buffer.from(eip712Digest("ContinuityLink", await sha256Hex(canonicalize(link0)), created)).toString("hex");
  const text = [
    `Successor key saved: ${join(dir, "key")}`,
    `The holder of ${v.via} must sign this link (a proof object with verificationMethod = that alias DID):`,
    JSON.stringify(link0),
    `For a wallet alias, EIP-712 digest to sign: ${digest}`,
    `Then: openentity recover --eid ${kp.did} --proof <proof.json>`,
  ].join("\n");
  return { json: { successor: kp.did, link: link0, eip712_digest: digest }, text };
}
