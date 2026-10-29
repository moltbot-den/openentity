// Async, batched, non-blocking reporter for schema-violation reports. Off unless OPENENTITY_LEDGER_URL
// (or the `ledger` option) is set. Reports are signed with `@openentity/sdk` (signObject, eddsa-jcs-2022).
// the `keypair` option, else a 32-byte hex seed in OPENENTITY_SEED_HEX. Without one the batch is dropped;
// no identity is ever created implicitly.
export const DEFAULT_URL = "https://api.clawgrc.com/v1/ledger/schema-violations";

// Captured at import so guardHttp() never sees the reporter's own requests.
const nativeFetch = globalThis.fetch;

export type Report = Record<string, string | number>;
export interface LedgerOptions {
  url?: string;
  keypair?: any; // an @openentity/sdk KeyPair
  framework?: string;
  enabled?: boolean;
  batch?: number;
  intervalMs?: number;
  post?: (url: string, body: string) => Promise<void>;
}

const optedOut = () => ["1", "true", "yes"].includes((process.env.OPENENTITY_LEDGER_OPTOUT ?? "").toLowerCase());

export class LedgerReporter {
  readonly url: string;
  readonly framework: string;
  enabled: boolean;
  sent = 0;
  private keypair: any;
  private seed?: string;
  private queue: Report[] = [];
  private timer?: ReturnType<typeof setTimeout>;
  private inflight: Promise<void> = Promise.resolve();
  private readonly batch: number;
  private readonly intervalMs: number;
  private readonly post: (url: string, body: string) => Promise<void>;

  constructor(o: LedgerOptions = {}) {
    let url = o.url ?? process.env.OPENENTITY_LEDGER_URL ?? "";
    if (["1", "true", "default"].includes(url)) url = DEFAULT_URL;
    this.url = url;
    this.framework = o.framework ?? "langchain";
    this.keypair = o.keypair;
    this.seed = process.env.OPENENTITY_SEED_HEX;
    this.batch = o.batch ?? 20;
    this.intervalMs = o.intervalMs ?? 5000;
    this.post = o.post ?? (async (u, body) => { (await nativeFetch(u, { method: "POST", headers: { "content-type": "application/json" }, body })).body?.cancel(); });
    this.enabled = !!url && !optedOut() && o.enabled !== false;
    if (this.enabled) process.once("beforeExit", () => void this.flush());
  }

  /** Queue one report; never blocks, drops when the queue is full. */
  report(fields: Report): void {
    if (!this.enabled || this.queue.length >= 1000) return;
    this.queue.push({ ...fields, framework: this.framework });
    if (this.queue.length >= this.batch) void this.flush();
    else this.timer ??= setTimeout(() => void this.flush(), this.intervalMs).unref();
  }

  async flush(): Promise<void> {
    clearTimeout(this.timer);
    this.timer = undefined;
    const items = this.queue.splice(0);
    this.inflight = this.inflight.then(() => this.send(items));
    return this.inflight;
  }

  private async send(items: Report[]): Promise<void> {
    if (!items.length) return;
    try {
      const sdk = await import("@openentity/sdk"); // optional peer dependency
      if (!this.keypair)
        this.keypair = await sdk.keyPairFromSeed(Uint8Array.from(Buffer.from(this.seed ?? "", "hex")));
      const seen = new Set<string>();
      for (const r of items) {
        const k = [r.host, r.method, r.path_template, r.body_sha256].join("\0");
        if (seen.has(k)) continue;
        seen.add(k);
        try {
          await this.post(this.url, JSON.stringify(await sdk.signObject({ ...r, reporter_eid: this.keypair.did }, this.keypair)));
          this.sent++;
        } catch { /* reporting must never break the agent */ }
      }
    } catch { /* SDK missing or no usable identity: drop the batch */ }
  }
}
