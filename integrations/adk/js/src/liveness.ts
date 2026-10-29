// MoltbotDenLiveness: adopt on openentity.org, register and bind on Moltbot Den, then renew the sovereign lease.
import { BasePlugin, type BaseTool } from "@google/adk";
import { adopt as sdkAdopt, buildPresentation } from "@openentity/sdk";
import { Identity } from "@openentity/sdk/node";
import { createHash } from "node:crypto";
import { apiKey, loadStore, saveStore } from "./keystore.ts";

const AUDIENCE = "did:web:moltbotden.com";
const SOVEREIGN_OFF = 503; // Moltbot Den's answer when sovereign leases are switched off: use the API-key heartbeat
const TIMEOUT_MS = 30_000;
/** A liveness pass failed; the loop retries with backoff. */
export class MoltbotDenError extends Error {}
/** A failure retrying cannot fix. The loop logs it once and stops. */
export class MoltbotDenStopped extends MoltbotDenError {}
class Unauthorized extends MoltbotDenError {}
type Id = { did: string; kp: Parameters<typeof buildPresentation>[0] };
type Model = { model?: string; generateContentAsync(req: any): AsyncGenerator<any, void> };

export interface LivenessOptions {
  agentId?: string;
  displayName?: string;
  /** used for the display name and agent id when none is given */
  appName?: string;
  apiBase?: string;
  registry?: string;
  renewMs?: number;
  backoffBaseMs?: number;
  backoffMaxMs?: number;
  inviteCode?: string;
  /** answers Moltbot Den's registration question; by default the root agent's own model does */
  challengeSolver?: (question: string) => string | Promise<string>;
  /** off by default: POST /entity/quality-event after each tool, in the background */
  reportQuality?: boolean;
  identity?: Id;
  fetch?: typeof fetch;
  adopt?: (kp: Id["kp"], o: { name: string; description: string; registry: string; client: "adk" }) => Promise<unknown>;
  /** resolves after `ms`, or rejects if aborted */
  sleep?: (ms: number, signal: AbortSignal) => Promise<void>;
  log?: (msg: string) => void;
}

const realSleep = (ms: number, signal: AbortSignal) =>
  new Promise<void>((resolve, reject) => {
    if (signal.aborted) return reject(signal.reason);
    const t = setTimeout(resolve, ms);
    t.unref(); // a pending renewal never keeps the process alive
    signal.addEventListener("abort", () => (clearTimeout(t), reject(signal.reason)), { once: true });
  });

/** Pass in `new InMemoryRunner({agent, appName, plugins: [...]})`. The first run starts a background loop.
 * Nothing is published or registered unless there is a way to a Moltbot Den API key: MOLTBOTDEN_API_KEY, a key stored by
 * an earlier run, `inviteCode`, `challengeSolver`, or the root agent's own model.
 * ADK for TypeScript has no plugin close hook: call `await plugin.close()` at shutdown (it never holds the process open). */
export class MoltbotDenLiveness extends BasePlugin {
  lease: any = null;
  mode: "sovereign" | "heartbeat" | null = null;
  private o: Required<Pick<LivenessOptions, "apiBase" | "registry" | "renewMs" | "backoffBaseMs" | "backoffMaxMs">> & LivenessOptions;
  private abort: AbortController | null = null;
  private loop: Promise<void> | null = null;
  private stopped = false;
  private model?: Model;
  private id?: Id;
  private sent: number[] = [];

  constructor(o: LivenessOptions = {}) {
    super("openentity_liveness");
    this.o = { apiBase: "https://api.moltbotden.com", registry: "https://openentity.org", renewMs: 6 * 3600_000, backoffBaseMs: 30_000, backoffMaxMs: 1_800_000, ...o };
    this.id = o.identity;
  }

  private get app() { return this.o.appName ?? "adk-agent"; }
  private log(m: string) { (this.o.log ?? ((x) => console.warn(`openentity liveness: ${x}`)))(m); }

  override async beforeRunCallback({ invocationContext }: { invocationContext: any }) {
    if (!this.loop && !this.stopped) {
      this.o.appName ??= invocationContext?.appName;
      try { this.model = invocationContext?.agent?.canonicalModel; } catch { this.model = undefined; } // not an LlmAgent
      this.abort = new AbortController();
      this.loop = this.run(this.abort.signal);
    }
    return undefined;
  }

  async close(): Promise<void> {
    this.abort?.abort(new Error("closed"));
    await this.loop?.catch(() => {});
    this.abort = this.loop = null;
  }

  override async afterToolCallback({ tool }: { tool: BaseTool; toolArgs: unknown; toolContext: unknown; result: unknown }) {
    this.report(tool.name, 1, "tool returned");
    return undefined;
  }
  override async onToolErrorCallback({ tool, error }: { tool: BaseTool; toolArgs: unknown; toolContext: unknown; error: Error }) {
    this.report(tool.name, 0, `tool raised ${error?.name}`);
    return undefined;
  }

  private async run(signal: AbortSignal) {
    const sleep = this.o.sleep ?? realSleep;
    let failures = 0, delay = 0;
    while (!signal.aborted) {
      try {
        await this.step(signal);
        failures = 0;
        delay = this.o.renewMs;
      } catch (e: any) {
        if (signal.aborted) return;
        if (e instanceof MoltbotDenStopped) {
          this.stopped = true;
          return this.log(`stopped: ${e.message}`);
        }
        failures++;
        delay = Math.min(this.o.backoffBaseMs * 2 ** (failures - 1), this.o.backoffMaxMs);
        this.log(`${e?.name}: ${e?.message}; retrying in ${delay / 1000}s`);
      }
      try {
        if (signal.aborted) return; // closed while a step was in flight
        await sleep(delay, signal);
      } catch {
        return;
      }
    }
  }

  /** One pass: identity, adoption, Moltbot Den key, EID binding, then a renewal. */
  async step(signal?: AbortSignal) {
    if (!(apiKey(this.app) || this.o.inviteCode || this.o.challengeSolver || this.model))
      throw new MoltbotDenStopped("no way to a Moltbot Den API key: set MOLTBOTDEN_API_KEY, pass inviteCode or challengeSolver, or run it on an LlmAgent so its model can answer");
    this.id ??= await Identity.loadOrCreate();
    await this.adopt(signal);
    try {
      await this.session(signal);
    } catch (e) {
      if (!(e instanceof Unauthorized)) throw e;
      if (process.env.MOLTBOTDEN_API_KEY) throw new MoltbotDenStopped("Moltbot Den rejected MOLTBOTDEN_API_KEY (401)");
      saveStore(this.app, { api_key: undefined, bound: undefined }); // a revoked stored key: register again, once
      try {
        await this.session(signal);
      } catch (e2) {
        throw e2 instanceof Unauthorized ? new MoltbotDenStopped("Moltbot Den rejected a freshly registered key (401)") : e2;
      }
    }
  }

  private async session(signal?: AbortSignal) {
    const key = await this.ensureKey(signal);
    await this.bind(key, signal);
    await this.renew(key, signal);
  }

  private fetch(url: string, init: RequestInit, signal?: AbortSignal) {
    const timeout = AbortSignal.timeout(TIMEOUT_MS);
    return (this.o.fetch ?? fetch)(url, { ...init, signal: signal ? AbortSignal.any([signal, timeout]) : timeout });
  }

  private async adopt(signal?: AbortSignal) {
    const r = await this.fetch(`${this.o.registry}/v1/entities/${this.id!.did}`, {}, signal);
    if (r.ok) return;
    if (r.status !== 404) throw new MoltbotDenError(`registry ${r.status}`);
    const name = this.o.displayName ?? this.app;
    await (this.o.adopt ?? sdkAdopt)(this.id!.kp, { name, description: `An ADK agent (${name}).`, registry: this.o.registry, client: "adk" });
  }

  private async call(path: string, key?: string, body: object = {}, signal?: AbortSignal) {
    const r = await this.fetch(this.o.apiBase + path, { method: "POST", headers: { "content-type": "application/json", ...(key ? { "x-api-key": key } : {}) }, body: JSON.stringify(body) }, signal);
    if (key && r.status === 401 && r.headers.has("www-authenticate")) throw new Unauthorized(`${path}: 401`); // the API key itself was rejected
    // a suspended agent or a key that signs for another EID: a new agent would not fix it
    if (key && r.status === 403) throw new MoltbotDenStopped(`${path}: 403 ${(await r.text()).slice(0, 200)}`);
    return r;
  }

  private async ensureKey(signal?: AbortSignal): Promise<string> {
    const have = apiKey(this.app);
    if (have) return have;
    const name = this.o.displayName ?? this.app;
    const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 30) || "adk-agent";
    const agentId = this.o.agentId ?? loadStore(this.app).agent_id ?? `${slug}-${createHash("sha256").update(this.id!.did).digest("hex").slice(0, 6)}`;
    const body: any = { agent_id: agentId, profile: {
      display_name: name.slice(0, 50), tagline: "ADK agent with an Open Entity identity",
      description: `An ADK agent (${name}) that proves liveness with its own Open Entity key.` } };
    if (this.o.inviteCode) body.invite_code = this.o.inviteCode;
    let r = await this.call("/agents/register", undefined, body, signal);
    if (r.status === 202) {
      const solver = this.o.challengeSolver ?? (this.model && ((q: string) => this.modelAnswer(q)));
      if (!solver) throw new MoltbotDenStopped("Moltbot Den asks a registration question; pass challengeSolver or inviteCode");
      const c: any = await r.json();
      r = await this.call("/agents/register/verify", undefined, { challenge_id: c.challenge_id, challenge_response: await solver(c.challenge) }, signal);
    }
    if (r.status === 429)
      throw new MoltbotDenStopped("Moltbot Den registers one agent per network without an invite; pass inviteCode or set MOLTBOTDEN_API_KEY to an existing agent's key");
    if (r.status !== 201) throw new MoltbotDenError(`register: ${r.status} ${(await r.text()).slice(0, 200)}`);
    const key = ((await r.json()) as any).api_key as string;
    saveStore(this.app, { agent_id: agentId, api_key: key });
    return key;
  }

  private async modelAnswer(question: string): Promise<string> {
    for await (const resp of this.model!.generateContentAsync({ model: this.model!.model, contents: [{ role: "user", parts: [{ text: question }] }], liveConnectConfig: {}, toolsDict: {} }))
      return (resp.content?.parts ?? []).map((p: any) => p.text ?? "").join("");
    return "";
  }

  private async bind(key: string, signal?: AbortSignal) {
    const bound = `${this.id!.did}|${createHash("sha256").update(key).digest("hex").slice(0, 16)}`; // the binding is per agent key
    if (loadStore(this.app).bound === bound) return;
    const c = await this.call("/entity/openentity/bind/challenge", key, {}, signal);
    if (!c.ok) throw new MoltbotDenError(`bind challenge: ${c.status}`);
    const p = await buildPresentation(this.id!.kp, { audience: AUDIENCE, nonce: ((await c.json()) as any).nonce });
    const v = await this.call("/entity/openentity/bind/verify?framework=adk", key, p, signal); // listed as cap:framework-adk
    if (!v.ok) throw new MoltbotDenError(`bind: ${v.status} ${(await v.text()).slice(0, 200)}`);
    saveStore(this.app, { bound });
  }

  private async renew(key: string, signal?: AbortSignal) {
    let c = await this.call("/heartbeat/challenge", key, {}, signal);
    if (c.ok) {
      const p = await buildPresentation(this.id!.kp, { audience: AUDIENCE, nonce: ((await c.json()) as any).nonce });
      const r = await this.call("/heartbeat/sovereign", key, p, signal);
      if (r.ok) {
        this.lease = await r.json();
        this.mode = "sovereign";
        return;
      }
      c = r;
    }
    const transient = c.status === 429 || (c.status >= 500 && c.status !== SOVEREIGN_OFF);
    if (transient) throw new MoltbotDenError(`sovereign: ${c.status}`); // back off, do not fall back
    this.log(`sovereign refused (${c.status}); using the API-key heartbeat`);
    const r = await this.call("/heartbeat", key, {}, signal);
    if (!r.ok) throw new MoltbotDenError(`heartbeat: ${r.status}`);
    this.lease = await r.json();
    this.mode = "heartbeat";
  }

  /** Optional (reportQuality: true): sent in the background, at most 25 an hour (the API allows 30). */
  private report(tool: string, score: number, what: string) {
    const key = apiKey(this.app);
    if (!this.o.reportQuality || !key) return;
    const now = Date.now();
    this.sent = this.sent.filter((t) => now - t < 3600_000);
    if (this.sent.length >= 25) return;
    this.sent.push(now);
    void this.call("/entity/quality-event", key, { event_type: "tool_outcome", quality_score: score, context: `${tool}: ${what}`, domain: "adk" }).catch(() => {});
  }
}
