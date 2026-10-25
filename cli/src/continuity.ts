import { rm } from "node:fs/promises";
import { join } from "node:path";
import {
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
  validate,
  verificationMethodId,
  type KeyPair,
} from "@openentity/sdk";
import { CliError, EXIT, stateErr, usage } from "./errors";
import type { Obj } from "./http";
import { Registry } from "./http";
import { appendEntry, pushRecord } from "./record";
import { createEntityDir, loadEntity, readJson, regUrl, setCurrent, strip, writeJson, type Ctx, type Entity, type Result } from "./store";

const bare = (kp: KeyPair) => kp.did.slice("did:key:".length);

async function successorKey(v: Obj): Promise<KeyPair> {
  return v.to ? keyPairFromJwk(await readJson(v.to)) : generateKeyPair();
}

/** The successor's first Entity Document: the previous one re-keyed, seq 1, aliases dropped (their proofs name the old EID). */
async function successorDoc(prev: Obj, kp: KeyPair, v: Obj): Promise<Obj> {
  const now = nowSeconds();
  const d = strip(prev);
  delete d.aliases;
  Object.assign(d, {
    eid: kp.did,
    keys: [{ id: verificationMethodId(kp.did), type: "Multikey", publicKeyMultibase: bare(kp) }],
    created: now,
    updated: now,
    seq: 1,
    continuity: { ...d.continuity, previous: prev.eid },
  });
  if (v.operator) d.operator = { ...d.operator, kind: v["operator-kind"] ?? d.operator.kind, name: v.operator };
  if (v.custody) d.operator = { ...d.operator, custody: v.custody };
  if (v.model || v.provider || v.runtime) {
    d.substrate = { ...d.substrate, ...(v.model && { model: v.model }), ...(v.provider && { provider: v.provider }), ...(v.runtime && { runtime: v.runtime }), declared_at: now };
  }
  return signObject(d, kp, now);
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

/** rotate (basis rotation) and migrate (basis migration): both keys sign. */
export async function link({ v }: Ctx, basis: "rotation" | "migration"): Promise<Result> {
  const old = await loadEntity(v);
  const kp = await successorKey(v);
  const created = nowSeconds();
  const document = await successorDoc(old.doc, kp, v);
  const link0 = { spec: SPEC, type: "ContinuityLink", previous: old.eid, successor: kp.did, basis, created, nonce: randomNonce() };
  const full = { ...link0, proofs: [await signProof(link0, old.kp, created), await signProof(link0, kp, created)] };
  const ok = validate("ContinuityLink", full);
  if (!ok.ok) throw new CliError(EXIT.VERIFY, `link fails schema validation: ${ok.errors.join("; ")}`);
  if (v["dry-run"]) return { json: { link: full, document }, text: JSON.stringify({ link: full, document }, null, 2) };
  // Save the successor key before submitting; undo only if the registry refuses.
  const keep = await createEntityDir(kp, { doc: document, declaration: old.declaration ?? undefined, state: { registry: old.registry.base, docSeq: 1, recordPushed: 0 } });
  try {
    await old.registry.send("POST", "/v1/continuity", { link: full, document }, old.eid);
  } catch (e) {
    await rm(keep, { recursive: true, force: true });
    throw e;
  }
  const pushed = await openSuccessorRecord(old, kp, keep, document, await sha256Hex(canonicalize(full)), basis);
  return {
    json: { previous: old.eid, successor: kp.did, basis, key_file: join(keep, "key"), record_pushed: pushed },
    text: `${basis}: ${old.eid} continues as ${kp.did}\nnew key: ${join(keep, "key")} (now the current entity)`,
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
  const document = await successorDoc(prevDoc, kp, v);
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
