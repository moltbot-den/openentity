import { mintStamp } from "@openentity/sdk";
import { CliError, EXIT } from "./errors";
import pkg from "../package.json";

export type Obj = Record<string, any>;

export const DEFAULT_REGISTRY = "https://openentity.org";

// GET /v1/spec field names, read in one place.
export const specDeclHash = (s: Obj): string | undefined => s.declaration?.sha256 ?? s.declaration_sha256;
const specStampBits = (s: Obj): number => Number(s.stamp_bits ?? s.stamp?.bits ?? s.bits ?? 20);

export async function fetchJson(url: string, init: RequestInit = {}): Promise<any> {
  let res: Response;
  try {
    res = await fetch(url, {
      ...init,
      headers: { accept: "application/json", "user-agent": `openentity-cli/${pkg.version}`, ...(init.headers as Obj) },
      signal: AbortSignal.timeout(30_000),
    });
  } catch (e: any) {
    throw new CliError(EXIT.NETWORK, `network error: ${init.method ?? "GET"} ${url}: ${e?.cause?.message ?? e.message}`);
  }
  const text = await res.text();
  let data: any = text;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    /* non-JSON body stays text */
  }
  if (!res.ok) {
    const detail = data?.error ? `${data.error}: ${data.message ?? ""}` : String(text).slice(0, 200);
    // 5xx: the registry is unwell, a network-class failure. 4xx: it read the request and said no.
    throw new CliError(res.status >= 500 ? EXIT.NETWORK : EXIT.REJECTED, `registry ${res.status} for ${init.method ?? "GET"} ${url}: ${detail}`);
  }
  return data;
}

export class Registry {
  base: string;
  private specP?: Promise<Obj>;
  constructor(base: string) {
    this.base = base.replace(/\/+$/, "");
  }
  get(path: string) {
    return fetchJson(this.base + path);
  }
  /** Every Record entry of `eid` and the log index of each leaf, following `next` until the registry reports no more pages. */
  async record(eid: string): Promise<{ entries: Obj[]; log_indexes: (number | null)[] }> {
    const entries: Obj[] = [], log_indexes: (number | null)[] = [];
    for (let after = 0, rec; ; after = rec.next) {
      rec = await this.get(`/v1/entities/${eid}/record?after=${after}`);
      const page = Array.isArray(rec) ? rec : (rec.entries ?? []);
      entries.push(...page);
      log_indexes.push(...(rec.log_indexes ?? page.map(() => null)));
      if (rec.next == null) return { entries, log_indexes };
    }
  }
  async text(path: string): Promise<string> {
    let r: Response;
    try {
      r = await fetch(this.base + path, { signal: AbortSignal.timeout(30_000) });
    } catch (e: any) {
      throw new CliError(EXIT.NETWORK, `network error: GET ${this.base + path}: ${e.message}`);
    }
    if (!r.ok) throw new CliError(r.status >= 500 ? EXIT.NETWORK : EXIT.REJECTED, `registry ${r.status} for GET ${path}`);
    return r.text();
  }
  spec() {
    return (this.specP ??= this.get("/v1/spec"));
  }
  /** Write endpoint: mints the proof-of-work stamp for `eid` at the registry's published difficulty. */
  async send(method: "POST" | "PUT", path: string, body: unknown, eid: string) {
    const stamp = await mintStamp(specStampBits(await this.spec()), eid);
    return fetchJson(this.base + path, {
      method,
      headers: { "content-type": "application/json", "x-oe-stamp": stamp },
      body: JSON.stringify(body),
    });
  }
}
