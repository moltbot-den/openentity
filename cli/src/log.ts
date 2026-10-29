import { readFile } from "node:fs/promises";
import {
  base58btcDecode,
  canonicalize,
  DECLARATION_SHA256,
  leafHash,
  parseJson,
  recordEntryHash,
  validate,
  verifyInclusion,
  verifyNote,
  verifyObject,
  verifyProof,
  type Resolver,
} from "@openentity/sdk";
import { ed25519Keys, resolveDid, resolver } from "./did";
import { CliError, EXIT, usage } from "./errors";
import { fetchJson, Registry, type Obj } from "./http";
import { regUrl, type Ctx, type Result } from "./store";

const unhex = (h: string) => new Uint8Array(Buffer.from(h, "hex"));
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const pretty = (o: unknown) => JSON.stringify(o, null, 2);

export async function resolveCmd({ args }: Ctx): Promise<Result> {
  if (!args[0]) throw usage("resolve <did>");
  const doc = await resolveDid(args[0]);
  return { json: doc, text: pretty(doc) };
}

// --- checkpoint and inclusion ---

/** Verify the signed checkpoint note against the registry key published at /v1/spec. */
export async function checkpointCheck(reg: Registry): Promise<{ ok: boolean; detail: string; sth: Obj }> {
  const [spec, sth] = await Promise.all([reg.spec(), reg.get("/v1/log/sth")]);
  const key = spec.registry?.publicKeyMultibase;
  const origin = spec.registry?.log_origin ?? "openentity.org/log";
  if (!key) return { ok: false, detail: "registry publishes no checkpoint key in /v1/spec", sth };
  const pk = base58btcDecode(key.slice(1)).slice(-32);
  const ok = await verifyNote(sth.signature, origin, pk).catch(() => false);
  return { ok, detail: ok ? `checkpoint signature valid, tree size ${sth.tree_size}` : "checkpoint signature INVALID", sth };
}

export async function inclusionCheck(reg: Registry, index: number, sth: Obj): Promise<{ ok: boolean; detail: string; leaf?: Obj }> {
  const [{ entries }, p] = await Promise.all([reg.get(`/v1/log/entries?start=${index}&end=${index + 1}`), reg.get(`/v1/log/proof/${index}?tree_size=${sth.tree_size}`)]);
  const leaf = entries?.[0]?.leaf;
  if (!leaf) return { ok: false, detail: `no log entry at ${index}` };
  const lh = await leafHash(new TextEncoder().encode(canonicalize(leaf)));
  const ok = hex(lh) === p.leaf_hash && (await verifyInclusion(index, sth.tree_size, lh, p.proof.map(unhex), unhex(sth.root_hash)));
  return { ok, detail: ok ? `leaf ${index} included in tree of ${sth.tree_size}` : `inclusion proof for leaf ${index} FAILED`, leaf };
}

/** The registry's own did:web names openentity.org, but a registry that is not openentity.org signs with the key its /v1/spec publishes. */
async function registryResolver(reg: Registry): Promise<Resolver> {
  const mb = (await reg.spec()).registry?.publicKeyMultibase;
  return (did) => (did.split("#")[0] === "did:web:openentity.org" && mb ? Promise.resolve({ ed25519: ed25519Keys({ verificationMethod: [{ publicKeyMultibase: mb }] }) }) : resolver(did));
}

export async function logCmd({ args, v }: Ctx): Promise<Result> {
  const reg = new Registry(regUrl(v));
  const [sub, arg] = args;
  if (sub === "checkpoint") {
    const c = await checkpointCheck(reg);
    const out = { ...c.sth, verified: c.ok, detail: c.detail };
    if (!c.ok) return { json: out, text: `${c.detail}\n${pretty(c.sth)}`, code: EXIT.VERIFY };
    return { json: out, text: `${c.detail}\nroot ${c.sth.root_hash}\n${c.sth.signature}` };
  }
  if (sub === "proof") {
    const i = Number(arg);
    if (!Number.isInteger(i) || i < 0) throw usage("log proof <index>");
    const { sth } = await checkpointCheck(reg);
    const r = await inclusionCheck(reg, i, sth);
    const proof = await reg.get(`/v1/log/proof/${i}?tree_size=${sth.tree_size}`);
    return { json: { ...proof, verified: r.ok, leaf: r.leaf }, text: `${r.detail}\n${pretty(proof)}`, code: r.ok ? 0 : EXIT.VERIFY };
  }
  if (sub === "audit") {
    const n = Number(arg ?? 5);
    if (!Number.isInteger(n) || n < 1) throw usage("log audit <n>");
    const c = await checkpointCheck(reg);
    const checks = [{ name: "checkpoint", ok: c.ok, detail: c.detail }];
    const size: number = c.sth.tree_size;
    const res = await registryResolver(reg);
    for (let k = 0; k < Math.min(n, size); k++) {
      const i = Math.floor(Math.random() * size);
      const r = await inclusionCheck(reg, i, c.sth);
      checks.push({ name: `inclusion ${i}`, ok: r.ok, detail: r.detail });
      if (r.ok && r.leaf?.eid) {
        // Object signature: the entity's current document must verify under its own key.
        try {
          const d = await reg.get(`/v1/entities/${r.leaf.eid}/document`);
          const s = await verifyObject(d, res);
          checks.push({ name: `signature ${r.leaf.eid}`, ok: s.ok, detail: s.ok ? "document signature valid" : `document signature invalid: ${s.error}` });
        } catch (e: any) {
          checks.push({ name: `signature ${r.leaf.eid}`, ok: false, detail: e.message });
        }
      }
    }
    const ok = checks.every((x) => x.ok);
    return { json: { ok, checks }, text: checks.map((x) => `${x.ok ? "ok  " : "FAIL"} ${x.name}: ${x.detail}`).join("\n"), code: ok ? 0 : EXIT.VERIFY };
  }
  throw usage("log checkpoint|proof <index>|audit <n>");
}

// --- verify ---

interface Check {
  name: string;
  ok: boolean;
  detail?: string;
}

const typeOf = (o: Obj): string | undefined => o.type ?? (o.layers && o.keys ? "EntityDocument" : undefined);
const signerOk = (signer: string | undefined, eid: string) => !!signer && signer.split("#")[0] === eid;

async function verifyOne(o: Obj): Promise<Check[]> {
  const type = typeOf(o);
  if (!type) return [{ name: "type", ok: false, detail: "cannot tell what kind of object this is" }];
  const checks: Check[] = [];
  const schema = validate(type as any, o);
  checks.push({ name: `${type} schema`, ok: schema.ok, detail: schema.errors?.join("; ") });
  if (type === "ContinuityLink") {
    const { proofs, ...bare } = o;
    for (const [i, p] of (proofs ?? []).entries()) {
      const r = await verifyProof(bare, p, resolver);
      checks.push({ name: `link proof ${i} (${p.verificationMethod})`, ok: r.ok, detail: r.error });
    }
    if (!proofs?.length) checks.push({ name: "link proofs", ok: false, detail: "none" });
    return checks;
  }
  const r = await verifyObject(o as any, resolver);
  checks.push({ name: "signature", ok: r.ok, detail: r.error });
  if (r.ok && o.eid && ["EntityDocument", "Declaration", "RecordEntry", "Withdrawal"].includes(type)) {
    checks.push({ name: "signed by the EID", ok: signerOk(r.signer, o.eid), detail: r.signer });
  }
  if (type === "Declaration" && o.declaration_version === "1.0") {
    checks.push({ name: "declaration text hash", ok: o.text_sha256 === DECLARATION_SHA256, detail: o.text_sha256 });
  }
  return checks;
}

/** Chain check (spec 7.4). A redacted placeholder `{seq, prev, redacted, hash, redaction?}` links like an entry; its own
 * signature is gone, so it is trusted only as far as the next entry's `prev` and, when present, the entity's signed Redaction. */
export async function verifyRecord(entries: Obj[], eid: string): Promise<Check[]> {
  const checks: Check[] = [];
  let prev: Obj | undefined;
  for (const e of entries) {
    const bad: string[] = [];
    if (e.seq !== (prev ? prev.seq + 1 : 1)) bad.push(`seq ${e.seq} breaks the sequence`);
    const wantPrev = prev ? (prev.redacted ? prev.hash : await recordEntryHash(prev)) : null;
    if (e.prev !== wantPrev) bad.push("prev hash breaks the chain");
    if (e.redacted) {
      if (!/^[0-9a-f]{64}$/.test(e.hash ?? "")) bad.push("placeholder hash is not SHA-256 hex");
      if (e.redaction) {
        const r = e.redaction, s = await verifyObject(r, resolver);
        if (!s.ok || !signerOk(s.signer, eid) || r.eid !== eid || r.seq !== e.seq || r.entry_sha256 !== e.hash) bad.push("redaction is not the entity's signed request for this entry");
      }
    } else {
      if (e.eid !== eid) bad.push("eid mismatch");
      const s = await verifyObject(e as any, resolver);
      if (!s.ok) bad.push(`signature: ${s.error}`);
    }
    if (bad.length) checks.push({ name: `record entry ${e.seq}`, ok: false, detail: bad.join("; ") });
    prev = e;
  }
  checks.push({ name: `record chain (${entries.length} entries)`, ok: checks.length === 0 });
  return checks;
}

export async function verifyCmd({ args, v }: Ctx): Promise<Result> {
  const target = args[0];
  if (!target) throw usage("verify <file-or-url-or-eid>");
  let checks: Check[] = [];
  if (/^(did:|eid:)/.test(target)) {
    const reg = new Registry(regUrl(v));
    const ent = await reg.get(`/v1/entities/${target}`);
    const eid: string = ent.document?.eid ?? target;
    checks.push(...(await verifyOne(ent.document)));
    if (ent.declaration) checks.push(...(await verifyOne(ent.declaration)));
    else checks.push({ name: "declaration", ok: false, detail: "registry returned no Declaration" });
    const rec = await reg.record(eid).catch(() => []);
    checks.push(...(await verifyRecord(rec, eid)));
    const idx = ent.log_index ?? ent.declaration_log_index;
    if (idx !== undefined) {
      try {
        const c = await checkpointCheck(reg);
        checks.push({ name: "checkpoint", ok: c.ok, detail: c.detail });
        const inc = await inclusionCheck(reg, idx, c.sth);
        checks.push({ name: "log inclusion", ok: inc.ok, detail: inc.detail });
      } catch (e: any) {
        checks.push({ name: "log inclusion", ok: false, detail: e.message });
      }
    } else checks.push({ name: "log inclusion", ok: false, detail: "registry did not report a log index" });
  } else {
    let obj: Obj;
    if (/^https?:\/\//.test(target)) obj = await fetchJson(target);
    else {
      try {
        obj = parseJson(await readFile(target, "utf8")) as Obj;
      } catch (e: any) {
        throw new CliError(EXIT.USAGE, `cannot read ${target}: ${e.message}`);
      }
    }
    checks = await verifyOne(obj);
  }
  const ok = checks.every((c) => c.ok);
  return {
    json: { target, ok, checks },
    text: checks.map((c) => `${c.ok ? "ok  " : "FAIL"} ${c.name}${c.detail ? `: ${c.detail}` : ""}`).join("\n") + `\n${ok ? "VERIFIED" : "VERIFICATION FAILED"}`,
    code: ok ? 0 : EXIT.VERIFY,
  };
}
