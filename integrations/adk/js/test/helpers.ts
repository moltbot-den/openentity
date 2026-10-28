import { keyPairFromSeed } from "@openentity/sdk";
import type { TrustReport } from "@openentity/sdk";

export const ident = async () => {
  const kp = await keyPairFromSeed(Uint8Array.from({ length: 32 }, (_, i) => i));
  return { did: kp.did, kp };
};

/** A fake Moltbot Den and registry behind one fetch. `routes` maps a path to a status or [status, json]. */
export function fakeNet() {
  const calls: { path: string; key: string | null; body: any }[] = [];
  const routes: Record<string, number | [number, object]> = {
    "/agents/register": [201, { api_key: "mbd_key" }],
    "/entity/openentity/bind/challenge": [200, { nonce: "nonce-bind-0123456789" }],
    "/entity/openentity/bind/verify": [200, { success: true }],
    "/heartbeat/challenge": [200, { nonce: "nonce-renew-0123456789" }],
    "/heartbeat/sovereign": [200, { success: true }],
    "/heartbeat": [200, { success: true }],
  };
  const state = { adopted: false, adopts: [] as any[] };
  const fetchFn = (async (url: string, init?: RequestInit) => {
    const u = new URL(url);
    if (u.pathname.startsWith("/v1/entities/")) return new Response("{}", { status: state.adopted ? 200 : 404 });
    const h = new Headers(init?.headers);
    calls.push({ path: u.pathname, key: h.get("x-api-key"), body: init?.body ? JSON.parse(init.body as string) : null });
    const r = routes[u.pathname] ?? 200;
    const [status, json] = typeof r === "number" ? [r, {}] : r;
    return new Response(JSON.stringify(json), { status });
  }) as typeof fetch;
  const adopt = async (_kp: unknown, o: any) => { state.adopted = true; state.adopts.push(o); };
  return { calls, routes, state, fetch: fetchFn, adopt, paths: () => calls.map((c) => c.path) };
}

/** Replaces setTimeout: records delays, resolves at once, parks until aborted after `limit` sleeps. */
export function clock(limit = 3) {
  const delays: number[] = [];
  const sleep = (ms: number, signal: AbortSignal) => {
    delays.push(ms);
    if (signal.aborted) return Promise.reject(signal.reason);
    if (delays.length < limit) return Promise.resolve();
    return new Promise<void>((_, reject) => signal.addEventListener("abort", () => reject(signal.reason), { once: true }));
  };
  return { delays, sleep, limit };
}

export const settle = async () => { for (let i = 0; i < 100; i++) await new Promise((r) => setImmediate(r)); };

export const CGRC = "did:web:api.clawgrc.com";
export const POSTURE = { score_band: "A" };
export const report = (o: Partial<TrustReport> & { tier?: number | null } = {}): TrustReport => ({
  eid: "did:key:z6MkTest", ok: true, level: "L1", withdrawn: false,
  trustTier: o.tier === null ? {} : { [CGRC]: o.tier ?? 3 }, securityPosture: POSTURE, violations: [], revocations: [], ...o,
} as TrustReport);
export const viol = (severity: string) => ({ issuer: CGRC, severity, policy: "p", observed_at: "t", sha256: "ab" });
