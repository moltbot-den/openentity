// pair() and ownerTools() (ADK FunctionTools) against an in-memory registry and account service (every account call's signature is checked). No network.
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { pairSas, verifyRequest } from "@openentity/sdk";
import { ownerTools, pair } from "../src/index.ts";

let home: string;
beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "oe-adk-owner-"));
  Object.assign(process.env, { OPENENTITY_HOME: home, OPENENTITY_KEYCHAIN: "off", OPENENTITY_REGISTRY: "https://registry.example", OPENENTITY_ACCOUNT: "https://account.example" });
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  for (const k of ["OPENENTITY_HOME", "OPENENTITY_KEYCHAIN", "OPENENTITY_REGISTRY", "OPENENTITY_ACCOUNT"]) delete process.env[k];
  rmSync(home, { recursive: true, force: true });
});

function services(routes: Record<string, (body: any) => object | null>) {
  const known = new Set<string>(), adopts: any[] = [], calls: { did: string; path: string; body: any }[] = [];
  const json = (j: unknown, status = 200) => new Response(j === null ? null : JSON.stringify(j), { status });
  vi.stubGlobal("fetch", async (url: string, init: RequestInit = {}) => {
    const { origin, pathname } = new URL(url), method = init.method ?? "GET";
    if (origin === "https://registry.example") {
      const body = init.body ? JSON.parse(init.body as string) : null;
      if (pathname === "/v1/spec") return json({ stamp_bits: 1 });
      if (pathname === "/v1/adopt") return adopts.push(body), known.add(body.document.eid), json({ eid: body.document.eid }, 201);
      if (pathname.endsWith("/record")) return json({ accepted: 1 }, 201);
      const eid = decodeURIComponent(pathname.split("/")[3]);
      return known.has(eid) ? json({ eid }) : json({ error: "entity_not_found" }, 404);
    }
    const bytes = init.body as Uint8Array | undefined;
    const { did } = await verifyRequest({ method, url, headers: init.headers as Record<string, string>, body: bytes });
    const body = bytes ? JSON.parse(new TextDecoder().decode(bytes)) : undefined;
    calls.push({ did, path: `${method} ${pathname}`, body });
    const out = routes[`${method} ${pathname}`](body);
    return out && "error" in out ? json(out, 423) : json(out, out ? 200 : 204);
  });
  return { adopts, calls };
}

test("pair adopts first under the adk label, then pairs and hands the match over", async () => {
  const s = services({
    "POST /v1/pair": (b) => ({ pairing_id: "pr_1", sas: { version: "pair-sas/1", names: pairSas(b.code, b.presentation.eid) }, expires_at: 9e9, poll_interval: 2 }),
    "GET /v1/pair/pr_1": () => ({ state: "confirmed", owner_did: "did:web:account.example:o:abc", permissions: [], credentials: [] }),
  });
  const log = vi.spyOn(console, "log").mockImplementation(() => {});
  const shown: string[][] = [];
  const r = await pair("OE-7K4M-Q2XP", { name: "Paired", onMatch: (n) => void shown.push(n) });
  expect([r.adopted, r.ownerDid, s.adopts.map((a) => a.client)]).toEqual([true, "did:web:account.example:o:abc", ["adk"]]);
  expect(shown).toEqual([pairSas("OE-7K4M-Q2XP", r.eid)]);
  expect(log.mock.calls[0][0]).toContain("signed the Open Entity Declaration");
  expect(s.calls[0]).toMatchObject({ did: r.eid, body: { framework: "adk", sdk: "@openentity/adk" } });
});

test("the owner tools sign as this agent and answer ok=false on a refusal", async () => {
  const s = services({
    "POST /v1/agent/messages": () => ({ id: "m1" }),
    "POST /v1/agent/status": () => null,
    "GET /v1/agent/messages": () => ({ items: [], more: false }),
    "POST /v1/agent/approvals": (b) => ({ id: "ap1", state: "pending", title: b.title }),
  });
  const [message, status, inbox, ask] = ownerTools();
  const run = (t: any, args: object) => t.runAsync({ args, toolContext: {} });
  expect([message, status, inbox, ask].map((t) => t.name)).toEqual(["owner_message", "owner_status", "owner_inbox", "owner_ask_approval"]);
  expect(await run(message, { text: "hello" })).toEqual({ ok: true, id: "m1" });
  expect(await run(status, { state: "running", summary: "indexing", progress: 0.5 })).toEqual({ ok: true });
  expect(await run(inbox, {})).toEqual({ ok: true, items: [], more: false });
  expect(await run(ask, { title: "Deploy", summary: "Ship v2", risk: "high" })).toMatchObject({ ok: true, state: "pending" });
  expect(s.calls.map((c) => c.body)).toEqual([{ text: "hello" }, { state: "running", summary: "indexing", progress: 0.5 }, undefined, { title: "Deploy", summary: "Ship v2", risk: "high", expires_in: 600 }]);
  expect([new Set(s.calls.map((c) => c.did)).size, s.adopts.length]).toEqual([1, 0]);
  services({ "POST /v1/agent/messages": () => ({ error: "agent_paused", message: "paused" }) });
  expect(await run(message, { text: "x" })).toMatchObject({ ok: false, error: "agent_paused" });
});
