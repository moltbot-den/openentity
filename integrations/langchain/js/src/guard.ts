import { AsyncLocalStorage } from "node:async_hooks";
import { createMiddleware, ToolMessage, type AnyAgentMiddleware } from "langchain";
import {
  OpenEntityLoopDetected, OpenEntitySchemaViolation, Routes, SAMPLE, compileSchema, expectsJson, inspectResponse,
  pathTemplate, scrub, sha256Hex, stableJson, type Schema,
} from "./core.ts";
import { LedgerReporter } from "./ledger.ts";

const HALT_FLAG = "openentity_halt";
// Violations raised by guarded fetches inside the running tool. LangChain.js converts tool exceptions into
// error ToolMessages by default, and a tool may catch its own; neither can hide a violation from wrapToolCall.
const calls = new AsyncLocalStorage<{ violation?: OpenEntitySchemaViolation }>();

export interface GuardOptions {
  schemas?: Record<string, unknown>;
  mode?: "raise" | "halt";
  maxFailures?: number;
  /** A reporter, a URL, false to turn it off; default reads OPENENTITY_LEDGER_URL. */
  ledger?: LedgerReporter | string | false;
  ignore?: string[];
  onlyRegistered?: boolean;
}

const isToolMessage = (x: any): x is ToolMessage => x != null && typeof x === "object" && (x.type === "tool" || x._getType?.() === "tool");
const textOf = (c: unknown): string =>
  typeof c === "string" ? c : Array.isArray(c) ? c.map((b: any) => (typeof b === "string" ? b : b?.text ?? "")).join("") : JSON.stringify(c);

export class RuthlessSchemaGuard {
  readonly routes = new Routes();
  readonly toolSchemas = new Map<string, Schema>();
  readonly ledger: LedgerReporter;
  lastReport?: string;
  private readonly mode: "raise" | "halt";
  private readonly maxFailures: number;
  private readonly ignore: Set<string>;
  private readonly onlyRegistered: boolean;
  // ponytail: one failure counter per guard; call reset() between unrelated runs.
  private failures = new Map<string, number>();
  private restore?: () => void;
  /** Pass this to `createAgent({ middleware: [guard.middleware] })`, first in the list (outermost). */
  readonly middleware: AnyAgentMiddleware;

  constructor(o: GuardOptions = {}) {
    this.mode = o.mode ?? "raise";
    this.maxFailures = o.maxFailures ?? 3;
    this.ignore = new Set(o.ignore);
    this.onlyRegistered = o.onlyRegistered ?? false;
    this.ledger = o.ledger instanceof LedgerReporter ? o.ledger
      : new LedgerReporter({ url: typeof o.ledger === "string" ? o.ledger : undefined, enabled: o.ledger === false ? false : undefined });
    for (const [k, v] of Object.entries(o.schemas ?? {})) this.register(k, v);
    this.middleware = createMiddleware({
      name: "RuthlessSchemaGuard",
      wrapToolCall: (request: any, handler: any) => this.wrapToolCall(request, handler),
      beforeModel: {
        hook: (state: any) => {
          const last = state.messages?.at(-1);
          return isToolMessage(last) && (last as any).additional_kwargs?.[HALT_FLAG] ? { jumpTo: "end" as const } : undefined;
        },
        canJumpTo: ["end"],
      },
    });
  }

  /** `"GET https://api.example.com/items/*"` registers a route; a bare name registers a tool. */
  register(target: string, schema: unknown): this {
    const s = compileSchema(schema);
    if (target.includes("://")) this.routes.add(target, s);
    else this.toolSchemas.set(target, s);
    return this;
  }

  /** Register every 2xx application/json response of an OpenAPI 3 document (object, URL or JSON string). */
  async fromOpenapi(spec: Record<string, any> | string, baseUrl?: string): Promise<this> {
    if (typeof spec === "string") spec = spec.trimStart().startsWith("{") ? JSON.parse(spec) : await (await fetch(spec)).json();
    const doc = spec as Record<string, any>;
    const base = (baseUrl ?? doc.servers?.[0]?.url ?? "").replace(/\/+$/, "");
    if (!base.includes("://")) throw new Error("fromOpenapi needs baseUrl when the document has no absolute servers[0].url");
    const components = { components: doc.components ?? {} };
    for (const [path, item] of Object.entries<any>(doc.paths ?? {}))
      for (const [method, op] of Object.entries<any>(item)) {
        if (!["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"].includes(method.toUpperCase()) || !op || typeof op !== "object") continue;
        for (const [code, resp] of Object.entries<any>(op.responses ?? {})) {
          if (!code.startsWith("2") || code === "204" || code === "205") continue;
          const media = Object.entries<any>(resp.content ?? {}).find(([ct, m]) => ct.includes("json") && m.schema);
          if (media) this.register(`${method.toUpperCase()} ${base}${path}`, { ...components, ...media[1].schema });
        }
      }
    return this;
  }

  // ---- transport ----
  /** Wrap global fetch. Returns the uninstaller. Streaming bodies (SSE, ndjson) are never read. */
  guardHttp(): () => void {
    if (this.restore) return this.restore;
    const orig = globalThis.fetch;
    globalThis.fetch = async (input: any, init?: any) => {
      const res = await orig(input, init);
      const req = input instanceof Request ? input : undefined;
      const method = init?.method ?? req?.method ?? "GET";
      const accept = new Headers(init?.headers ?? req?.headers).get("accept") ?? "";
      const url = res.url || (req?.url ?? String(input instanceof URL ? input.href : input));
      const ct = res.headers.get("content-type") ?? "";
      if (this.wants(method, url, res.status, ct, accept))
        this.check(method, url, res.status, ct, accept, new TextDecoder("utf-8", { ignoreBOM: true }).decode(await res.clone().arrayBuffer()));
      return res;
    };
    const patched = globalThis.fetch;
    this.restore = () => {
      if (globalThis.fetch === patched) globalThis.fetch = orig;
      this.restore = undefined;
    };
    return this.restore;
  }

  private wants(method: string, url: string, status: number, ct: string, accept: string): boolean {
    const hit = this.routes.match(method, url);
    if (this.onlyRegistered && !hit) return false;
    return status >= 200 && status < 300 && expectsJson(ct, accept, hit !== undefined);
  }

  /** Throws OpenEntitySchemaViolation when the response breaks a rule. */
  check(method: string, url: string, status: number, ct: string, accept: string, body: string): void {
    if (!this.wants(method, url, status, ct, accept)) return;
    const hit = this.routes.match(method, url);
    const errs = inspectResponse(status, ct, body, { schema: hit?.schema, accept, ignore: this.ignore });
    if (!errs.length) return;
    const u = new URL(url);
    this.ledger.report({
      host: u.hostname, method: method.toUpperCase(), path_template: hit?.path ?? pathTemplate(url),
      expected_schema_hash: hit?.schema.hash ?? "", status, content_type: ct,
      body_sha256: sha256Hex(body), sample: scrub(body).slice(0, SAMPLE),
    });
    const err = new OpenEntitySchemaViolation(`${method.toUpperCase()} ${u.origin}${u.pathname}`, errs, body);
    const call = calls.getStore();
    if (call) call.violation ??= err;
    throw err;
  }

  // ---- tools ----
  reset(): void {
    this.failures.clear();
  }

  private count(name: string, key: string): OpenEntityLoopDetected | undefined {
    const n = (this.failures.get(key) ?? 0) + 1;
    this.failures.set(key, n);
    return n >= this.maxFailures ? new OpenEntityLoopDetected(name, key.split("\0")[1], n) : undefined;
  }

  private exit(request: any, err: Error): ToolMessage {
    if (this.mode !== "halt") throw err;
    const errors: string[] = (err as any).errors ?? [err.message];
    this.lastReport = `RuthlessSchemaGuard halted the run: ${err.name} in ${request.toolCall.name}: ${errors.slice(0, 5).join("; ")}`;
    return new ToolMessage({
      content: this.lastReport, tool_call_id: request.toolCall.id, name: request.toolCall.name, status: "error",
      additional_kwargs: { [HALT_FLAG]: true },
    });
  }

  private async wrapToolCall(request: any, handler: (r: any) => any): Promise<any> {
    const name: string = request.toolCall.name;
    // Counted per thread, so a guard shared by concurrent runs does not mix them.
    const thread = request.runtime?.configurable?.thread_id ?? request.runtime?.config?.configurable?.thread_id ?? "";
    const argsHash = sha256Hex(`${name}\0${stableJson(request.toolCall.args ?? {})}`);
    const key = `${thread}\0${argsHash}`;
    let result: any;
    try {
      const call: { violation?: OpenEntitySchemaViolation } = {};
      result = await calls.run(call, () => handler(request));
      if (call.violation) throw call.violation;
      const schema = this.toolSchemas.get(name);
      if (schema && isToolMessage(result) && (result as any).status !== "error") {
        const text = textOf(result.content);
        const errs = inspectResponse(200, "application/json", text, { schema, ignore: this.ignore });
        if (errs.length) throw new OpenEntitySchemaViolation(name, errs, text);
      }
    } catch (e) {
      if (e instanceof OpenEntitySchemaViolation || e instanceof OpenEntityLoopDetected) return this.exit(request, this.count(name, key) ?? e);
      const loop = this.count(name, key);
      if (!loop) throw e;
      return this.exit(request, loop);
    }
    if (isToolMessage(result) && (result as any).status === "error") {
      const loop = this.count(name, key);
      return loop ? this.exit(request, loop) : result;
    }
    this.failures.delete(key);
    return result;
  }
}
