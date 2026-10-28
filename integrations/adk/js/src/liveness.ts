// MoltbotDenLiveness: adopt on openentity.org, register and bind on Moltbot Den, then renew the sovereign lease.
import { BasePlugin, type BaseTool } from "@google/adk";
import { adopt as sdkAdopt, buildPresentation } from "@openentity/sdk";
import { Identity } from "@openentity/sdk/node";
import { createHash } from "node:crypto";
import { apiKey, loadStore, saveStore } from "./keystore.ts";

const AUDIENCE = "did:web:moltbotden.com";
export class MoltbotDenError extends Error {}
type Id = { did: string; kp: Parameters<typeof buildPresentation>[0] };

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
  /** answers Moltbot Den's registration question with a model; without it (and without an invite code or MOLTBOTDEN_API_KEY) registration is skipped and logged */
  challengeSolver?: (question: string) => string | Promise<string>;
  /** off by default: POST /entity/quality-event after each tool */
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
    const t = setTimeout(resolve, ms);
    t.unref(); // a pending renewal never keeps the process alive
    signal.addEventListener("abort", () => (clearTimeout(t), reject(signal.reason)), { once: true });
  });

/** Pass in `new InMemoryRunner({agent, appName, plugins: [...]})`. The first run starts a background loop.
 * ADK for TypeScript has no plugin close hook: call `await plugin.close()` at shutdown to cancel it (it never holds the process open). */
export class MoltbotDenLiveness extends BasePlugin {
  lease: any = null;
  mode: "sovereign" | "heartbeat" | null = null;
  private o: Required<Pick<LivenessOptions, "apiBase" | "registry" | "renewMs" | "backoffBaseMs" | "backoffMaxMs">> & LivenessOptions;
  private abort: AbortController | null = null;
  private loop: Promise<void> | null = null;
  private id?: Id;
  private sent: number[] = [];

  constructor(o: LivenessOptions = {}) {
    super("openentity_liveness");
    this.o = { apiBase: "https://api.moltbotden.com", registry: "https://openentity.org", renewMs: 6 * 3600_000, backoffBaseMs: 30_000, backoffMaxMs: 1_800_000, ...o };
    this.id = o.identity;
  }

  private get f() { return this.o.fetch ?? fetch; }
  private warn(m: string) { (this.o.log ?? ((x) => console.warn(`openentity liveness: ${x}`)))(m); }

  override async beforeRunCallback({ invocationContext }: { invocationContext: any }) {
    if (!this.loop) {
      this.o.appName ??= invocationContext?.appName;
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
    await this.quality(tool.name, 1, "tool returned");
    return undefined;
  }
  override async onToolErrorCallback({ tool, error }: { tool: BaseTool; toolArgs: unknown; toolContext: unknown; error: Error }) {
    await this.quality(tool.name, 0, `tool raised ${error?.name}`);
    return undefined;
  }

  private async run(signal: AbortSignal) {
    const sleep = this.o.sleep ?? realSleep;
    let failures = 0, delay = 0;
    while (!signal.aborted) {
      try {
        await this.step();
        failures = 0;
        delay = this.o.renewMs;
      } catch (e: any) {
        failures++;
        delay = Math.min(this.o.backoffBaseMs * 2 ** (failures - 1), this.o.backoffMaxMs);
        this.warn(`${e?.name}: ${e?.message}; retrying in ${delay / 1000}s`);
      }
      try {
        await sleep(delay, signal);
      } catch {
        return;
      }
    }
  }

  /** One pass: identity, adoption, Moltbot Den key, EID binding, then a renewal. */
  async step() {
    this.id ??= await Identity.loadOrCreate();
    await this.adopt();
    const key = await this.ensureKey();
    if (!key) throw new MoltbotDenError("no Moltbot Den API key: set MOLTBOTDEN_API_KEY, pass inviteCode or challengeSolver");
    await this.bind(key);
    await this.renew(key);
  }

  private async adopt() {
    const r = await this.f(`${this.o.registry}/v1/entities/${this.id!.did}`);
    if (r.ok) return;
    if (r.status !== 404) throw new MoltbotDenError(`registry ${r.status}`);
    const name = this.o.displayName ?? this.o.appName ?? "adk-agent";
    await (this.o.adopt ?? sdkAdopt)(this.id!.kp, { name, description: `A Google ADK agent (${name}).`, registry: this.o.registry, client: "adk" });
  }

  private call(path: string, key?: string, body: object = {}) {
    return this.f(this.o.apiBase + path, { method: "POST", headers: { "content-type": "application/json", ...(key ? { "x-api-key": key } : {}) }, body: JSON.stringify(body) });
  }

  private async ensureKey(): Promise<string | undefined> {
    const have = apiKey();
    if (have) return have;
    const app = this.o.displayName ?? this.o.appName ?? "adk-agent";
    const slug = app.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 30) || "adk-agent";
    const agentId = this.o.agentId ?? loadStore().agent_id ?? `${slug}-${createHash("sha256").update(this.id!.did).digest("hex").slice(0, 6)}`;
    const body: any = { agent_id: agentId, profile: {
      display_name: app.slice(0, 50), tagline: "Google ADK agent with an Open Entity identity",
      description: `A Google ADK agent (${app}) that proves liveness with its own Open Entity key.` } };
    if (this.o.inviteCode) body.invite_code = this.o.inviteCode;
    let r = await this.call("/agents/register", undefined, body);
    if (r.status === 202) {
      if (!this.o.challengeSolver) {
        this.warn("Moltbot Den asks a registration question; pass challengeSolver, an inviteCode, or set MOLTBOTDEN_API_KEY");
        return undefined;
      }
      const c: any = await r.json();
      r = await this.call("/agents/register/verify", undefined, { challenge_id: c.challenge_id, challenge_response: await this.o.challengeSolver(c.challenge) });
    }
    if (r.status !== 201) throw new MoltbotDenError(`register: ${r.status} ${(await r.text()).slice(0, 200)}`);
    const key = ((await r.json()) as any).api_key as string;
    saveStore({ agent_id: agentId, api_key: key });
    return key;
  }

  private async bind(key: string) {
    if (loadStore().bound_eid === this.id!.did) return;
    const c = await this.call("/entity/openentity/bind/challenge", key);
    if (!c.ok) throw new MoltbotDenError(`bind challenge: ${c.status}`);
    const p = await buildPresentation(this.id!.kp, { audience: AUDIENCE, nonce: ((await c.json()) as any).nonce });
    const v = await this.call("/entity/openentity/bind/verify", key, p);
    if (!v.ok) throw new MoltbotDenError(`bind: ${v.status} ${(await v.text()).slice(0, 200)}`);
    saveStore({ bound_eid: this.id!.did });
  }

  private async renew(key: string) {
    let c = await this.call("/heartbeat/challenge", key);
    if (c.ok) {
      const p = await buildPresentation(this.id!.kp, { audience: AUDIENCE, nonce: ((await c.json()) as any).nonce });
      const r = await this.call("/heartbeat/sovereign", key, p);
      if (r.ok) {
        this.lease = await r.json();
        this.mode = "sovereign";
        return;
      }
      c = r;
    }
    if (c.status === 429 || (c.status >= 500 && c.status !== 503)) throw new MoltbotDenError(`sovereign: ${c.status}`); // transient: back off
    this.warn(`sovereign refused (${c.status}); using the API-key heartbeat`);
    const r = await this.call("/heartbeat", key);
    if (!r.ok) throw new MoltbotDenError(`heartbeat: ${r.status}`);
    this.lease = await r.json();
    this.mode = "heartbeat";
  }

  /** Optional (reportQuality: true): at most 25 an hour (the API allows 30). */
  private async quality(tool: string, score: number, what: string) {
    const key = apiKey();
    if (!this.o.reportQuality || !key) return;
    const now = Date.now();
    this.sent = this.sent.filter((t) => now - t < 3600_000);
    if (this.sent.length >= 25) return;
    this.sent.push(now);
    await this.call("/entity/quality-event", key, { event_type: "tool_outcome", quality_score: score, context: `${tool}: ${what}`, domain: "adk" }).catch(() => {});
  }
}
