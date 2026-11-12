import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { mkdtempSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeyPair, pairSas, recordEntryHash, verifyObject, verifyRequest } from "@openentity/sdk";
import { openEntityTools, ownerTools, pair } from "../src/index.ts";

let home: string;
beforeEach(() => { home = mkdtempSync(join(tmpdir(), "oe-mastra-")); process.env.OPENENTITY_HOME = home; process.env.OPENENTITY_KEYCHAIN = "off"; });
afterEach(() => { vi.unstubAllGlobals(); rmSync(home, { recursive: true, force: true }); });

/** An in-memory registry: adopt, entity read, record chain check, no attestations. */
function fakeRegistry() {
  const entities = new Map<string, { name: string; head: { seq: number; hash: string } | null; entries: any[] }>();
  const adopts: any[] = [];
  const state = { failRecords: false };
  const fetchFn = (async (url: string, init?: RequestInit) => {
    const { pathname } = new URL(url);
    const body = init?.body ? JSON.parse(init.body as string) : null;
    const ok = (j: object, status = 200) => new Response(JSON.stringify(j), { status });
    if (pathname === "/v1/spec") return ok({ stamp_bits: 1 });
    if (pathname === "/v1/adopt") {
      adopts.push(body);
      entities.set(body.document.eid, { name: body.document.name, head: null, entries: [] });
      return ok({ eid: body.document.eid }, 201);
    }
    const m = pathname.match(/^\/v1\/entities\/([^/]+)(\/record|\/attestations)?$/);
    const e = m && entities.get(decodeURIComponent(m[1]));
    if (!e) return ok({ error: "not_found" }, 404);
    if (m![2] === "/attestations") return ok({ attestations: [] });
    if (m![2] === "/record") {
      if (state.failRecords) return ok({ error: "down" }, 503);
      for (const entry of body.entries) {
        if (entry.seq !== (e.head?.seq ?? 0) + 1 || entry.prev !== (e.head?.hash ?? null)) return ok({ error: "chain" }, 409);
        e.head = { seq: entry.seq, hash: await recordEntryHash(entry) };
        e.entries.push(entry);
      }
      return ok({ accepted: body.entries.length }, 201);
    }
    return ok({ eid: decodeURIComponent(m![1]), name: e.name, level: "L1", record_head: e.head });
  }) as typeof fetch;
  return { entities, adopts, fetch: fetchFn, get failRecords() { return state.failRecords; }, set failRecords(v: boolean) { state.failRecords = v; } };
}

const run = (t: any, input: unknown) => t.execute(input, {});
const stance = { stance_type: "refusal", reason_category: "values", cost: "low", context: "declined to share a customer list" };

test("self creates the key, adopts once with the vercel-ai label, and reuses it", async () => {
  const reg = fakeRegistry();
  vi.stubGlobal("fetch", reg.fetch);
  const tools = openEntityTools({ name: "Test Agent" });
  const a: any = await run(tools.openentity_self, {});
  const b: any = await run(openEntityTools().openentity_self, {}); // a second process on the same machine
  expect(a.eid).toMatch(/^did:key:/);
  expect(b.eid).toBe(a.eid);
  expect(existsSync(join(home, "identity.key"))).toBe(true);
  expect(reg.adopts).toHaveLength(1);
  expect(reg.adopts[0].client).toBe("mastra");
  expect(reg.adopts[0].document.name).toBe("Test Agent");
});

test("stances and arcs extend one signed chain, and concurrent calls get distinct seqs", async () => {
  const reg = fakeRegistry();
  vi.stubGlobal("fetch", reg.fetch);
  const t = openEntityTools();
  const rs: any[] = await Promise.all([
    run(t.openentity_record_stance, stance),
    run(t.openentity_record_arc, { action: "open", arc_id: "migrate", title: "Migrate billing" }),
    run(t.openentity_record_arc, { action: "close", arc_id: "migrate", title: "Migrate billing", outcome: "done" }),
  ]);
  expect(rs.map((r) => r.seq)).toEqual([2, 3, 4]); // seq 1 is the declaration entry from adopt
  const e = [...reg.entities.values()][0];
  expect(e.entries.map((x) => x.kind)).toEqual(["declaration", "stance", "arc_opened", "arc_closed"]);
  expect(e.entries[1].payload.instruction_conflict).toBe(false);
  for (const x of e.entries) expect((await verifyObject(x)).ok).toBe(true);
});

test("a record the registry rejects fails that call and does not poison the next", async () => {
  const reg = fakeRegistry();
  vi.stubGlobal("fetch", reg.fetch);
  const t = openEntityTools();
  await run(t.openentity_self, {});
  reg.failRecords = true;
  await expect(run(t.openentity_record_stance, stance)).rejects.toThrow(/503/);
  reg.failRecords = false;
  expect(((await run(t.openentity_record_stance, stance)) as any).seq).toBe(2);
});

test("verify fails closed for an unknown entity and passes a known one", async () => {
  const reg = fakeRegistry();
  vi.stubGlobal("fetch", reg.fetch);
  const t = openEntityTools();
  const stranger = await generateKeyPair();
  expect(((await run(t.openentity_verify, { eid: stranger.did })) as any).ok).toBe(false);
  reg.entities.set(stranger.did, { name: "Other", head: null, entries: [] });
  const r: any = await run(t.openentity_verify, { eid: stranger.did });
  expect([r.ok, r.level, r.violations]).toEqual([true, "L1", []]);
  expect(((await run(t.openentity_verify, { eid: "not-a-did" })) as any).ok).toBe(false);
});

/** The fake registry plus an account service at https://account.example that checks each signature and answers from `routes`. */
function withAccount(reg: ReturnType<typeof fakeRegistry>, routes: Record<string, (body: any) => object | null>) {
  const calls: { did: string; method: string; path: string; body: any }[] = [];
  vi.stubGlobal("fetch", (async (url: string, init: RequestInit = {}) => {
    if (!url.startsWith("https://account.example/")) return reg.fetch(url, init);
    const method = init.method ?? "GET", bytes = init.body as Uint8Array | undefined, path = new URL(url).pathname;
    const { did } = await verifyRequest({ method, url, headers: init.headers as Record<string, string>, body: bytes });
    const body = bytes ? JSON.parse(new TextDecoder().decode(bytes)) : undefined;
    calls.push({ did, method, path, body });
    const out = routes[`${method} ${path}`](body);
    return out && "error" in out ? new Response(JSON.stringify(out), { status: 423 }) : new Response(out ? JSON.stringify(out) : null, { status: out ? 200 : 204 });
  }) as typeof fetch);
  return calls;
}

test("pair adopts first with the mastra label, pairs under it and hands the match over before waiting", async () => {
  const reg = fakeRegistry();
  const calls = withAccount(reg, {
    "POST /v1/pair": (b) => ({ pairing_id: "pr_1", sas: { version: "pair-sas/1", names: pairSas(b.code, b.presentation.eid) }, expires_at: 9e9, poll_interval: 2 }),
    "GET /v1/pair/pr_1": () => ({ state: "confirmed", owner_did: "did:web:account.example:o:abc", permissions: ["owner.status"], credentials: [] }),
  });
  const log = vi.spyOn(console, "log").mockImplementation(() => {});
  const shown: string[][] = [];
  const r = await pair("OE-7K4M-Q2XP", { name: "Paired", account: "https://account.example", onMatch: (n) => void shown.push(n) });
  expect([r.adopted, r.ownerDid, r.permissions, reg.adopts.length, reg.adopts[0].client]).toEqual([true, "did:web:account.example:o:abc", ["owner.status"], 1, "mastra"]);
  expect(shown).toEqual([pairSas("OE-7K4M-Q2XP", r.eid)]);
  expect(log.mock.calls[0][0]).toContain("signed the Open Entity Declaration");
  log.mockRestore();
  expect(calls[0]).toMatchObject({ did: r.eid, path: "/v1/pair", body: { framework: "mastra", sdk: "@openentity/mastra" } });
});

test("the owner tools sign as this agent; a refusal comes back as ok=false", async () => {
  const reg = fakeRegistry();
  const calls = withAccount(reg, {
    "POST /v1/agent/messages": () => ({ id: "m1" }),
    "POST /v1/agent/status": () => null,
    "GET /v1/agent/messages": () => ({ items: [], more: false }),
    "POST /v1/agent/approvals": (b) => ({ id: "ap1", state: "pending", title: b.title }),
  });
  const t = ownerTools({ account: "https://account.example" });
  expect(await run(t.owner_message, { text: "hello" })).toEqual({ ok: true, id: "m1" });
  expect(await run(t.owner_status, { state: "running", summary: "indexing", progress: 0.5 })).toEqual({ ok: true });
  expect(await run(t.owner_inbox, {})).toEqual({ ok: true, items: [], more: false });
  expect(await run(t.owner_ask_approval, { title: "Deploy", summary: "Ship v2", risk: "high" })).toMatchObject({ ok: true, state: "pending" });
  expect(calls.map((c) => c.body)).toEqual([{ text: "hello" }, { state: "running", summary: "indexing", progress: 0.5 }, undefined, { title: "Deploy", summary: "Ship v2", risk: "high", expires_in: 600 }]);
  expect(new Set(calls.map((c) => c.did)).size).toBe(1);
  expect(reg.adopts).toHaveLength(0); // the owner tools never adopt
  withAccount(reg, { "POST /v1/agent/messages": () => ({ error: "agent_paused", message: "paused" }) });
  expect(await run(t.owner_message, { text: "x" })).toMatchObject({ ok: false, error: "agent_paused" });
});
