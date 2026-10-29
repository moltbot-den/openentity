// The Open Entity calls behind the tools: own identity (load or create, adopt once), read it, append stances and arcs, verify a counterparty.
import { adopt, mintStamp, nowSeconds, signObject, SPEC, trust, validate, type Client, type KeyPair, type TrustReport } from "@openentity/sdk";
import { Identity } from "@openentity/sdk/node";

export interface Options {
  /** Name on first adopt. Default: the integration's label. */
  name?: string;
  description?: string;
  registry?: string;
  /** Use this key instead of the machine's identity (OS keychain, else ~/.openentity/identity.key). */
  identity?: { kp: KeyPair };
  fetch?: typeof fetch;
}

export type Stance = { stance_type: "refusal" | "correction" | "limit_assertion"; reason_category: "values" | "capability" | "safety" | "relationship"; cost: "none" | "low" | "high"; context: string; instruction_conflict?: boolean };
export type Arc = { action: "open" | "close"; arc_id: string; title: string; outcome?: string };

export function createCore(client: Client, o: Options = {}) {
  const registry = (o.registry ?? "https://openentity.org").replace(/\/+$/, "");
  const get = o.fetch ?? fetch;
  const json = async (path: string, init?: RequestInit) => {
    const r = await get(`${registry}/v1${path}`, init);
    const t = await r.text();
    if (!r.ok) throw new Error(`registry ${r.status} for ${path}: ${t.slice(0, 200)}`);
    return JSON.parse(t);
  };
  let kp: Promise<KeyPair> | undefined;
  let queue: Promise<unknown> = Promise.resolve();

  /** Load or create the key, and adopt it with this integration's client label if the registry does not know it. */
  const ensure = (): Promise<KeyPair> =>
    (kp ??= (async () => {
      const k = o.identity?.kp ?? (await Identity.loadOrCreate()).kp;
      const known = await get(`${registry}/v1/entities/${k.did}`);
      if (known.status === 404) await adopt(k, { name: o.name ?? client, description: o.description, registry, client });
      else if (!known.ok) throw new Error(`registry ${known.status} for /entities/${k.did}`);
      return k;
    })().catch((e) => ((kp = undefined), Promise.reject(e))));

  /** Sign the next entry on the chain and push it. Calls run one at a time so seq stays monotonic. */
  const append = (kind: string, payload: object) => {
    const p = queue.then(async () => {
      const k = await ensure();
      const head = (await json(`/entities/${k.did}`)).record_head;
      const at = nowSeconds();
      const entry = await signObject({ spec: SPEC, type: "RecordEntry", eid: k.did, seq: (head?.seq ?? 0) + 1, prev: head?.hash ?? null, kind, at, payload }, k, at);
      const v = validate("RecordEntry", entry);
      if (!v.ok) throw new Error(`record entry invalid: ${v.errors.join("; ")}`);
      const { stamp_bits } = await json("/spec");
      await json(`/entities/${k.did}/record`, { method: "POST", headers: { "content-type": "application/json", "x-oe-stamp": await mintStamp(stamp_bits, k.did) }, body: JSON.stringify({ entries: [entry] }) });
      return { eid: k.did, seq: entry.seq, kind };
    });
    queue = p.catch(() => {});
    return p;
  };

  return {
    ensure,
    /** The registry's view of this agent: level, name, record head. */
    self: async () => {
      const k = await ensure();
      const e = await json(`/entities/${k.did}`);
      return { eid: k.did, name: e.name, level: e.level, withdrawn: !!e.withdrawn, record_head: e.record_head ?? null, url: `${registry}/entities/${k.did}` };
    },
    stance: (s: Stance) => append("stance", { ...s, instruction_conflict: s.instruction_conflict ?? false }),
    arc: (a: Arc) =>
      append(a.action === "open" ? "arc_opened" : "arc_closed", { arc_id: a.arc_id, title: a.title, ...(a.action === "close" && a.outcome ? { outcome: a.outcome } : {}) }),
    /** Fail closed: ok=false on any read or signature failure. */
    verify: (eid: string): Promise<TrustReport> => trust(eid, { registry, ...(o.fetch ? { fetchJson: async (u: string) => JSON.parse(await (await o.fetch!(u)).text()) } : {}) }),
  };
}
