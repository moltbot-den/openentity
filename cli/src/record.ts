import { nowSeconds, randomNonce, recordEntryHash, signObject, SPEC, validate } from "@openentity/sdk";
import { CliError, usage } from "./errors";
import type { Obj } from "./http";
import { appendRecord, lastRecordLink, loadEntity, readRecord, saveState, type Ctx, type Entity, type Result } from "./store";

const BATCH = 100; // spec 7.4: up to 100 entries per request

const need = (v: Obj, k: string) => {
  if (v[k] === undefined) throw usage(`--${k} is required`);
  return v[k];
};
const oneOf = (v: Obj, k: string, allowed: string[]) => {
  const x = need(v, k);
  if (!allowed.includes(x)) throw usage(`--${k} must be one of: ${allowed.join(", ")}`);
  return x;
};

/** Build the payload for a kind from flags. The schema validates the rest. */
function payloadFor(kind: string, v: Obj): Obj {
  switch (kind) {
    case "stance":
      return {
        stance_type: oneOf(v, "type", ["refusal", "correction", "limit_assertion"]),
        reason_category: oneOf(v, "reason", ["values", "capability", "safety", "relationship"]),
        instruction_conflict: !!v.conflict,
        cost: oneOf(v, "cost", ["none", "low", "high"]),
        context: need(v, "context"),
        ...(v["will-not-ref"] ? { will_not_ref: v["will-not-ref"] } : {}),
      };
    case "belief_update":
      return { topic: need(v, "topic"), from_summary: need(v, "from"), to_summary: need(v, "to"), ...(v.evidence ? { evidence_ref: v.evidence } : {}) };
    case "arc_opened":
      return { arc_id: need(v, "id"), title: need(v, "title") };
    case "arc_closed":
      return { arc_id: need(v, "id"), title: need(v, "title"), ...(v.outcome ? { outcome: v.outcome } : {}) };
    case "collaboration":
      return { with: need(v, "with"), role: need(v, "role"), outcome: need(v, "outcome"), ...(v.ref ? { ref: v.ref } : {}) };
    case "continuity":
      return {
        event: oneOf(v, "event", ["substrate_change", "migration", "rotation", "recovery"]),
        from: need(v, "from"),
        to: need(v, "to"),
        ...(v.link ? { link: v.link } : {}),
      };
  }
  throw usage(`unknown record kind ${kind}`);
}

/** Sign and append one entry to the local chain (seq and prev from the last local entry). */
export async function appendEntry(e: Entity, kind: string, payload: Obj): Promise<Obj> {
  const { seq, prev } = await lastRecordLink(e.dir);
  const at = nowSeconds();
  const entry = await signObject({ spec: SPEC, type: "RecordEntry", eid: e.eid, seq, prev, kind, at, payload }, e.kp, at);
  const r = validate("RecordEntry", entry);
  if (!r.ok) throw usage(`record entry invalid: ${r.errors.join("; ")}`);
  if (JSON.stringify(entry).length > 16 * 1024) throw usage("record entry exceeds 16 KB");
  await appendRecord(e.dir, entry);
  return entry;
}

/** Push every not-yet-accepted local entry, in batches of up to 100. */
export async function pushRecord(e: Entity): Promise<number> {
  const all = await readRecord(e.dir);
  let pushed = 0;
  while (e.state.recordPushed < all.length) {
    const batch = all.slice(e.state.recordPushed, e.state.recordPushed + BATCH);
    await e.registry.send("POST", `/v1/entities/${e.eid}/record`, { entries: batch }, e.eid);
    e.state.recordPushed += batch.length;
    pushed += batch.length;
    await saveState(e);
  }
  return pushed;
}

/** Withdraw a pushed entry from reads (spec 7.4): sign a Redaction naming its seq and exact hash. The local copy stays whole. */
async function redact(e: Entity, seqArg: string | undefined): Promise<Result> {
  const seq = Number(seqArg);
  const entry = (await readRecord(e.dir)).find((x) => x.seq === seq);
  if (!entry) throw usage("record redact <seq>: the seq of an entry in your local record");
  const created = nowSeconds();
  const red = await signObject({ spec: SPEC, type: "Redaction", eid: e.eid, seq, entry_sha256: await recordEntryHash(entry), created, nonce: randomNonce() }, e.kp, created);
  const r = await e.registry.send("POST", `/v1/entities/${e.eid}/record/redact`, red, e.eid);
  return { json: { redaction: red, placeholder: r.placeholder }, text: `redacted seq ${seq}: the registry now serves a placeholder that keeps its hash and chain position` };
}

export async function record({ args, v }: Ctx): Promise<Result> {
  const e = await loadEntity(v);
  const [sub, sub2] = args;
  if (sub === "redact") return redact(e, sub2);
  let kind: string | undefined;
  switch (sub) {
    case "stance":
      kind = "stance";
      break;
    case "update":
      kind = "belief_update";
      break;
    case "arc":
      kind = sub2 === "open" ? "arc_opened" : sub2 === "close" ? "arc_closed" : undefined;
      if (!kind) throw usage("record arc open|close");
      break;
    case "collab":
      kind = "collaboration";
      break;
    case "continuity":
      kind = "continuity";
      break;
    case "push":
      break;
    default:
      throw usage("record stance|update|arc open|arc close|collab|continuity|push|redact <seq>");
  }
  const entry = kind ? await appendEntry(e, kind, payloadFor(kind, v)) : undefined;
  let pushed = 0;
  let pushError: string | undefined;
  let code: number | undefined;
  if (!v["no-push"]) {
    try {
      pushed = await pushRecord(e);
    } catch (err) {
      // The entry is safely appended locally; a failed push is retried by `record push`.
      if (!(err instanceof CliError) || !entry) throw err;
      pushError = err.message;
      code = err.code;
    }
  }
  const pending = (await readRecord(e.dir)).length - e.state.recordPushed;
  const out = { entry, pushed, pending, ...(pushError ? { push_error: pushError } : {}) };
  const text = [entry ? `appended seq ${entry.seq} (${entry.kind})` : "", `pushed ${pushed}, pending ${pending}`, pushError ? `push failed: ${pushError}` : ""].filter(Boolean).join("\n");
  return { json: out, text, code };
}
