// Response inspection shared by the middleware and the fetch guard. Rules and rule names mirror the
// Python package (`langchain-openentity`); ../fixtures holds the corpus both test suites run.
import { createHash } from "node:crypto";
import { Validator } from "@cfworker/json-schema";

export const EXCERPT = 500;
export const SAMPLE = 2048;

export class OpenEntitySchemaViolation extends Error {
  readonly tool: string;
  readonly errors: string[];
  readonly rule: string;
  readonly rawExcerpt: string;
  constructor(tool: string, errors: string[], rawExcerpt = "") {
    super(`${tool}: ${errors.slice(0, 3).join("; ")}`);
    this.name = "OpenEntitySchemaViolation";
    this.tool = tool;
    this.errors = errors;
    this.rule = errors[0]?.split(":", 1)[0] ?? "";
    this.rawExcerpt = scrub(rawExcerpt).slice(0, EXCERPT);
  }
}

export class OpenEntityLoopDetected extends Error {
  readonly tool: string;
  readonly argsHash: string;
  readonly count: number;
  constructor(tool: string, argsHash: string, count: number) {
    super(`${tool} failed ${count} times with identical arguments (${argsHash.slice(0, 12)})`);
    this.name = "OpenEntityLoopDetected";
    this.tool = tool;
    this.argsHash = argsHash;
    this.count = count;
  }
}

/** LangChain.js wraps errors thrown by middleware in a MiddlewareError; this finds ours in the `cause` chain. */
export function unwrap(e: unknown): OpenEntitySchemaViolation | OpenEntityLoopDetected | undefined {
  for (let x: any = e; x; x = x.cause) if (x instanceof OpenEntitySchemaViolation || x instanceof OpenEntityLoopDetected) return x;
  return undefined;
}

// ---- scrubbing (same list as the Python package) ----
const FULL = [
  /AKIA[0-9A-Z]{16}/g,
  /gh[pousr]_[A-Za-z0-9_]{36,255}/g,
  /xox[bpsa]-[0-9]+-[0-9A-Za-z-]+/g,
  /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+/g,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|(?![\s\S]))/g,
  /(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|mssql):\/\/[^:\s/]+:[^@\s]+@[^/\s"']+/g,
  /[sr]k_(?:live|test)_[A-Za-z0-9]{20,}/g,
  /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/g,
  /[Bb]earer\s+[A-Za-z0-9._~+/=-]{16,}/g,
  /https?:\/\/[^/\s:@]+:[^/\s@]+@[^\s/"']+/g,
  /sk-[A-Za-z0-9_-]{20,}/g,
  /AIza[0-9A-Za-z_-]{35}/g,
  /hf_[A-Za-z0-9]{30,}/g,
  /npm_[A-Za-z0-9]{36}/g,
  /glpat-[A-Za-z0-9_-]{20,}/g,
  /AccountKey=[A-Za-z0-9+/=]{20,}/g,
  /SK[0-9a-f]{32}/g,
  /[Bb]asic\s+[A-Za-z0-9+/=]{16,}/g,
];
const KV =
  /("?(?:api[_-]?key|api[_-]?secret|api[_-]?token|auth[_-]?token|access[_-]?token|refresh[_-]?token|secret[_-]?key|client[_-]?secret|private[_-]?key|x-api-key|authorization|set-cookie|cookie|session[_-]?(?:id|token)|password|passwd|token|secret)"?\s*[=:]\s*"?)[^\s"',}&]{4,}/gi;

export function scrub(text: string): string {
  for (const rx of FULL) text = text.replace(rx, "[REDACTED]");
  return text.replace(KV, (_m, p1: string) => `${p1}[REDACTED]`);
}

// ---- schemas ----
type Json = unknown;
export function stableJson(v: Json): string {
  if (typeof v === "bigint") return v.toString();
  if (Array.isArray(v)) return `[${v.map(stableJson).join(",")}]`;
  if (v && typeof v === "object")
    return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${stableJson((v as Record<string, Json>)[k])}`).join(",")}}`;
  return JSON.stringify(v);
}
export const sha256Hex = (s: string | Uint8Array): string => createHash("sha256").update(s).digest("hex");

export interface Schema {
  jsonSchema: Record<string, any>;
  hash: string;
  declared: Set<string>;
  validate(parsed: Json): string[];
}

function nullable(node: any): any {
  if (Array.isArray(node)) return node.map(nullable);
  if (!node || typeof node !== "object") return node;
  const out: any = Object.fromEntries(Object.entries(node).map(([k, v]) => [k, nullable(v)]));
  if (out.nullable === true && typeof out.type === "string") {
    out.type = [out.type, "null"];
    if (Array.isArray(out.enum) && !out.enum.includes(null)) out.enum = [...out.enum, null];
  }
  delete out.nullable;
  return out;
}

function declaredKeys(s: Record<string, any>): Set<string> {
  let node = s;
  if (typeof s.$ref === "string") {
    const name = s.$ref.split("/").pop() as string;
    node = s.$defs?.[name] ?? s.components?.schemas?.[name] ?? {};
  }
  const keys = new Set(Object.keys(node.properties ?? {}));
  for (const k of ["allOf", "anyOf", "oneOf"]) for (const sub of node[k] ?? []) for (const p of Object.keys(sub.properties ?? {})) keys.add(p);
  return keys;
}

const loc = (p: string) => p.replace(/^#\/?/, "") || "$";

const TYPES = new Set(["string", "number", "integer", "boolean", "object", "array", "null"]);
// ponytail: checks `type` keywords only (the common typo); Python runs the full metaschema check.
function assertTypes(node: any): void {
  if (Array.isArray(node)) return node.forEach(assertTypes);
  if (!node || typeof node !== "object") return;
  for (const t of [node.type].flat()) if (typeof t === "string" && !TYPES.has(t)) throw new Error(`invalid JSON Schema: unknown type ${JSON.stringify(t)}`);
  Object.values(node).forEach(assertTypes);
}

/** A JSON Schema object, or a zod v4 schema (anything with `safeParse` and `toJSONSchema`). */
export function compileSchema(obj: any): Schema {
  if (obj && typeof obj.safeParse === "function") {
    const js = obj.toJSONSchema?.() ?? { type: "zod" };
    return {
      jsonSchema: js, hash: sha256Hex(stableJson(js)), declared: declaredKeys(js),
      validate(parsed) {
        const r = obj.safeParse(parsed);
        return r.success ? [] : r.error.issues.slice(0, 10).map((i: any) => `schema: ${i.path.join("/") || "$"}: ${String(i.message).slice(0, 200)}`);
      },
    };
  }
  const js = nullable(obj);
  const v = new Validator(js, "2020-12", false);
  assertTypes(js); // fail at register(), not inside the user's fetch
  return {
    jsonSchema: js, hash: sha256Hex(stableJson(js)), declared: declaredKeys(js),
    validate(parsed) {
      const r = v.validate(parsed);
      return r.valid ? [] : r.errors.filter((e) => e.keyword !== "$ref").slice(0, 10).map((e) => `schema: ${loc(e.instanceLocation)}: ${e.error.slice(0, 200)}`);
    },
  };
}

// ---- routes ----
const esc = (s: string) => s.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, "[^/]+");
const split = (url: string) => {
  const m = /^([A-Za-z][\w+.-]*):\/\/([^/?#]*)([^?#]*)/.exec(url);
  if (!m) throw new Error(`not an absolute URL: ${url}`);
  return { scheme: m[1].toLowerCase(), host: m[2], path: m[3] };
};

const PORTS: Record<string, string> = { http: ":80", https: ":443" };
// Lower-cased host[:port] without userinfo or a default port, so https://h:443/x equals https://h/x.
const netloc = (scheme: string, host: string) => {
  const h = host.slice(host.lastIndexOf("@") + 1).toLowerCase();
  return h.endsWith(PORTS[scheme] ?? "\0") ? h.slice(0, -PORTS[scheme].length) : h;
};

function pattern(url: string): RegExp {
  const { scheme, host, path } = split(url);
  if (path.split("/").filter((s) => s === "**").length > 1) throw new Error("a route may contain at most one '**' segment");
  const segs = path.replace(/\/+$/, "").split("/").map((seg) => (seg === "**" ? ".*" : seg === "*" || /^\{[^}]*\}$/.test(seg) ? "[^/]+" : esc(seg)));
  return new RegExp(`^${scheme}://${esc(netloc(scheme, host))}${segs.join("/")}/?$`, "i");
}

export class Routes {
  readonly routes: { method: string; rx: RegExp; path: string; schema: Schema }[] = [];
  add(route: string, schema: Schema): void {
    const i = route.trim().indexOf(" ");
    if (i < 0) throw new Error(`route must look like 'GET https://host/path', got ${JSON.stringify(route)}`);
    const url = route.trim().slice(i + 1).trim();
    this.routes.push({ method: route.trim().slice(0, i).toUpperCase(), rx: pattern(url), path: split(url).path || "/", schema });
  }
  match(method: string, url: string): { schema: Schema; path: string } | undefined {
    const { scheme, host, path } = split(url);
    const bare = `${scheme}://${netloc(scheme, host)}${path}`;
    const m = method.toUpperCase();
    const r = this.routes.find((x) => (x.method === "*" || x.method === m) && x.rx.test(bare));
    return r && { schema: r.schema, path: r.path };
  }
}

const ID = /^(?:\d+|[0-9a-f]{8}-[0-9a-f-]{27}|[0-9a-f]{16,})$/i;
export const pathTemplate = (url: string): string => split(url).path.split("/").map((s) => (ID.test(s) ? "{id}" : s)).join("/") || "/";

// ---- inspection ----
const lstrip = (s: string) => s.replace(/^[ \t\n\r]+/, "");
const rstrip = (s: string) => s.replace(/[ \t\n\r]+$/, "");
const JSONP = /^[A-Za-z_$][\w$.]*\s*\(/;
const NOT_JSON_STREAM = /ndjson|jsonl|event-stream|octet-stream/i;

function unbalanced(t: string): boolean {
  let depth = 0, inStr = false, esc_ = false;
  for (const c of t) {
    if (inStr) {
      if (esc_) esc_ = false;
      else if (c === "\\") esc_ = true;
      else if (c === '"') inStr = false;
    } else if (c === '"') inStr = true;
    else if (c === "{" || c === "[") depth++;
    else if (c === "}" || c === "]") depth--;
  }
  return inStr || depth > 0;
}

const truthy = (v: Json): boolean =>
  !(v === null || v === false || v === 0 || v === "" || (Array.isArray(v) && v.length === 0) ||
    (typeof v === "object" && v !== null && !Array.isArray(v) && Object.keys(v).length === 0));

export function expectsJson(contentType: string, accept: string, hasSchema: boolean): boolean {
  if (NOT_JSON_STREAM.test(contentType)) return false;
  return hasSchema || contentType.toLowerCase().includes("json") || accept.toLowerCase().includes("json");
}


export interface InspectOptions { schema?: Schema; accept?: string; ignore?: ReadonlySet<string> }

/** Violations ("rule: detail") of a response; empty when it is fine or not checked. */
export function inspectResponse(status: number, contentType: string, text: string, o: InspectOptions = {}): string[] {
  const { schema, accept = "", ignore = new Set<string>() } = o;
  if (status < 200 || status >= 300 || status === 204 || status === 205 || status === 206) return [];
  if (!expectsJson(contentType, accept, schema !== undefined)) return [];
  if (text.startsWith("﻿")) return ["bom: body starts with a byte order mark"];
  const t = lstrip(text);
  if (!t) return ["empty: 2xx response with no body"];
  const ct = contentType.toLowerCase();
  if (t[0] === "<") {
    if (t.slice(0, 5).toLowerCase() === "<?xml" || (ct.includes("xml") && !ct.includes("html"))) return ["xml: body is XML, not JSON"];
    return ["html: body is HTML, not JSON"];
  }
  if (t.startsWith(")]}'")) return ["jsonp: XSSI guard prefix before JSON"];
  if (JSONP.test(t)) return ["jsonp: body is a function call (JSONP), not JSON"];
  let parsed: Json;
  try {
    parsed = JSON.parse(text);
  } catch {
    const tail = rstrip(t).slice(-1);
    if (unbalanced(t) || tail === "," || tail === ":") return ["truncated: JSON ends before it is complete"];
    return ["invalid_json: body does not parse as JSON"];
  }
  const errs: string[] = [];
  const declared = schema?.declared ?? new Set<string>();
  if (parsed && typeof parsed === "object" && !Array.isArray(parsed) && !ignore.has("error_envelope")) {
    const o2 = parsed as Record<string, Json>;
    for (const k of ["error", "errors"]) if (k in o2 && !declared.has(k) && truthy(o2[k])) errs.push(`error_envelope: 2xx body carries '${k}'`);
    for (const k of ["success", "ok"]) if (o2[k] === false && !declared.has(k)) errs.push(`error_envelope: 2xx body carries ${k}=false`);
  }
  if (schema && !ignore.has("schema")) errs.push(...schema.validate(parsed));
  return errs;
}
