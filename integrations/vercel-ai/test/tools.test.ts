import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { mkdtempSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeyPair, recordEntryHash, verifyObject } from "@openentity/sdk";
import { openEntityTools } from "../src/index.ts";

let home: string;
beforeEach(() => { home = mkdtempSync(join(tmpdir(), "oe-vercel-ai-")); process.env.OPENENTITY_HOME = home; process.env.OPENENTITY_KEYCHAIN = "off"; });
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

const run = (t: any, input: unknown) => t.execute(input, { toolCallId: "t", messages: [] });
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
  expect(reg.adopts[0].client).toBe("vercel-ai");
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
