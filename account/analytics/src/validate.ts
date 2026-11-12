import { SCHEMA, type EventName, type Source } from "../generated/ts/events.ts";

export type Scalar = string | number | boolean;
export type QueuedEvent = {
  event: EventName;
  props: Record<string, Scalar>;
  event_id: string;
  ts_ms: number;
  user_id?: string;
  install_id?: string;
  platform: "ios" | "android" | "web" | "server";
  app_version?: string;
};
export type Result = { ok: true; event: QueuedEvent } | { ok: false; error: string };

const TOKEN = /^[A-Za-z0-9_.:-]{1,64}$/;
const DID = /^[A-Za-z0-9_.:-]{1,256}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const INT = 2147483647;

type Def = { type: string; optional?: boolean; values?: readonly string[] };

function valueOk(t: Def, v: unknown): boolean {
  switch (t.type) {
    case "token": return typeof v === "string" && TOKEN.test(v);
    case "did": return typeof v === "string" && DID.test(v);
    case "uuid": return typeof v === "string" && UUID.test(v);
    case "int": return Number.isInteger(v) && (v as number) >= 0 && (v as number) <= INT;
    case "int64": return Number.isSafeInteger(v) && (v as number) > 0;
    case "number": return typeof v === "number" && Number.isFinite(v);
    case "bool": return typeof v === "boolean";
    case "enum": return typeof v === "string" && !!t.values?.includes(v);
    default: return false;
  }
}

/** Source of an event, for the account service to enforce on /v1/events vs /v1/events/ingest. */
export const sourceOf = (name: string): Source | undefined =>
  (SCHEMA.events as Record<string, { source: Source }>)[name]?.source;

export function validateEvent(msg: unknown, opts: { allow?: readonly Source[] } = {}): Result {
  if (typeof msg !== "object" || msg === null || Array.isArray(msg)) return { ok: false, error: "not an object" };
  const m = msg as Record<string, unknown>;
  const name = m.event;
  if (typeof name !== "string" || !Object.hasOwn(SCHEMA.events, name)) return { ok: false, error: `undeclared event ${String(name)}` };
  const spec = (SCHEMA.events as Record<string, { source: Source; props: Record<string, Def> }>)[name];
  if (opts.allow && !opts.allow.includes(spec.source)) return { ok: false, error: `${name}: source ${spec.source} not allowed here` };

  const envelope = SCHEMA.envelope as Record<string, Def>;
  const envKeys = Object.keys(envelope);
  for (const k of Object.keys(m)) if (k !== "event" && k !== "props" && !envKeys.includes(k)) return { ok: false, error: `${name}: unknown envelope field ${k}` };
  for (const [k, t] of Object.entries(envelope)) {
    if (m[k] === undefined) { if (!t.optional) return { ok: false, error: `${name}: missing ${k}` }; continue; }
    if (!valueOk(t, m[k])) return { ok: false, error: `${name}: bad ${k}` };
  }
  if (m.user_id === undefined && m.install_id === undefined) return { ok: false, error: `${name}: need user_id or install_id` };

  const props = m.props ?? {};
  if (typeof props !== "object" || props === null || Array.isArray(props)) return { ok: false, error: `${name}: props not an object` };
  const allowed: Record<string, Def> = { ...spec.props, ...(SCHEMA.common as Record<string, Def>) };
  const p = props as Record<string, unknown>;
  for (const [k, v] of Object.entries(p)) {
    const t = Object.hasOwn(allowed, k) ? allowed[k] : undefined;
    if (!t) return { ok: false, error: `${name}: undeclared property ${k}` };
    if (!valueOk(t, v)) return { ok: false, error: `${name}.${k}: bad value` };
  }
  for (const [k, t] of Object.entries(spec.props)) if (p[k] === undefined && !t.optional) return { ok: false, error: `${name}: missing ${k}` };
  return { ok: true, event: m as unknown as QueuedEvent };
}
