import { describe, expect, test } from "vitest";
import { mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { saveStore } from "../src/keystore.ts";
import { OpenEntityGate, evaluate, mcpToolsets, openEntityVerified } from "../src/index.ts";
import { trust } from "@openentity/sdk";
import { report, viol } from "./helpers.ts";

const EID = "did:key:z6MkTest";
const fn = (r: any) => async () => r;

describe("evaluate", () => {
  test("a clean entity passes", async () => expect(await evaluate(EID, {}, fn(report()))).toBeUndefined());

  test.each([
    [report({ tier: 1 }), "tier_too_low"],
    [report({ tier: null }), "tier_too_low"],
    [report({ securityPosture: null }), "sma_posture_missing"],
    [report({ violations: [viol("high")] }), "violation"],
    [report({ violations: [viol("critical")] }), "violation"],
    [report({ withdrawn: true }), "withdrawn"],
    [report({ ok: false, error: "boom" }), "trust_unavailable"],
  ])("below the bar returns a structured denial (%#)", async (r, reason) => {
    const d = await evaluate(EID, {}, fn(r));
    expect(d).toMatchObject({ error: "open_entity_denied", denied: true, reason, eid: EID });
    expect(Object.keys(d!.required).sort()).toEqual(["denyOnViolation", "minTier", "requireSma", "tierIssuer"]);
    expect(typeof d!.detail).toBe("string");
  });

  test("severity threshold and waivers", async () => {
    const mid = report({ violations: [viol("medium")] });
    expect(await evaluate(EID, {}, fn(mid))).toBeUndefined();
    expect((await evaluate(EID, { denyOnViolation: "low" }, fn(mid)))!.reason).toBe("violation");
    expect(await evaluate(EID, { denyOnViolation: null }, fn(report({ violations: [viol("critical")] })))).toBeUndefined();
    expect(await evaluate(EID, { requireSma: false }, fn(report({ securityPosture: null })))).toBeUndefined();
  });

  test("fails closed when trust throws", async () => {
    const d = await evaluate(EID, {}, async () => { throw new Error("registry down"); });
    expect(d!.reason).toBe("trust_unavailable");
    expect(d!.detail).toMatch(/registry down/);
  });

  test("fails closed on the real trust() with an unreachable registry", async () => {
    const d = await evaluate(EID, {}, (e) => trust(e, { registry: "https://registry.invalid", fetchJson: async () => { throw new Error("no network"); } }));
    expect(d!.reason).toBe("trust_unavailable");
  });
});

describe("openEntityVerified", () => {
  test("blocks below the bar and does not run the function", async () => {
    let ran = 0;
    const send = openEntityVerified(async (to: string) => { ran++; return { sent: to }; }, { eid: EID, trust: fn(report({ tier: 0 })) });
    expect(await send("a")).toMatchObject({ denied: true, reason: "tier_too_low" });
    expect(ran).toBe(0);
  });
  test("runs a sync function when clear", async () => {
    const send = openEntityVerified((to: string) => ({ sent: to }), { eid: () => EID, trust: fn(report()) });
    expect(await send("a")).toEqual({ sent: "a" });
  });
  test("denies when no identity can be loaded", async () => {
    const send = openEntityVerified(() => "ran", { eid: () => { throw new Error("keystore unreadable"); }, trust: fn(report()) });
    expect(await send()).toMatchObject({ denied: true, reason: "trust_unavailable", eid: null });
  });
});

describe("OpenEntityGate", () => {
  test("checks only the listed tools", async () => {
    const seen: string[] = [];
    const gate = new OpenEntityGate(["transfer_funds"], { eid: EID, trust: async (e) => (seen.push(e), report({ tier: 0 })) });
    const call = (name: string) => gate.beforeToolCallback({ tool: { name } as any, toolArgs: {}, toolContext: null as any });
    expect(await call("search")).toBeUndefined();
    expect(seen).toEqual([]);
    expect(await call("transfer_funds")).toMatchObject({ denied: true, reason: "tier_too_low" });
    expect(seen).toEqual([EID]);
    const ok = new OpenEntityGate(["transfer_funds"], { eid: EID, trust: fn(report()) });
    expect(await ok.beforeToolCallback({ tool: { name: "transfer_funds" } as any, toolArgs: {}, toolContext: null as any })).toBeUndefined();
  });
});

describe("counterparty checks", () => {
  const OTHER = "did:key:z6MkOther";
  const pay = { name: "pay_agent" } as any;
  test("the gate checks the EID named in the tool args", async () => {
    const seen: string[] = [];
    const gate = new OpenEntityGate(["pay_agent"], { counterpartyArg: "eid", trust: async (e) => (seen.push(e), report()) });
    expect(await gate.beforeToolCallback({ tool: pay, toolArgs: { eid: OTHER, amount: 5 }, toolContext: null as any })).toBeUndefined();
    expect(seen).toEqual([OTHER]);
  });
  test.each([{}, { eid: "" }, { eid: "not-a-did" }, { eid: 7 }])("a missing or non-DID counterparty is denied (%j)", async (args) => {
    const gate = new OpenEntityGate(["pay_agent"], { counterpartyArg: "eid", trust: fn(report()) });
    expect(await gate.beforeToolCallback({ tool: pay, toolArgs: args, toolContext: null as any })).toMatchObject({ denied: true, reason: "counterparty_missing" });
  });
  test("the wrapper reads the counterparty from the tool's input object", async () => {
    const seen: string[] = [];
    const send = openEntityVerified(({ eid }: { eid: string; amount: number }) => `paid ${eid}`, { counterpartyArg: "eid", trust: async (e) => (seen.push(e), report({ tier: 0 })) });
    expect(await send({ eid: OTHER, amount: 5 })).toMatchObject({ reason: "tier_too_low" });
    expect(seen).toEqual([OTHER]);
    expect(await send({ eid: "nope", amount: 1 })).toMatchObject({ reason: "counterparty_missing" });
  });
  test("denials say whose record failed", async () => {
    // Seen live: told only "trust_tier 0 is below 2", the model said its own tier was too low when the payee's was.
    const counterparty = new OpenEntityGate(["pay_agent"], { counterpartyArg: "eid", trust: fn(report({ tier: 0 })) });
    const d: any = await counterparty.beforeToolCallback({ tool: pay, toolArgs: { eid: OTHER }, toolContext: null as any });
    expect(d.subject).toBe("counterparty");
    expect(d.detail).toMatch(/^The other agent/);
    expect(((await counterparty.beforeToolCallback({ tool: pay, toolArgs: {}, toolContext: null as any })) as any).subject).toBe("counterparty");
    const own = new OpenEntityGate(["pay_agent"], { eid: EID, trust: fn(report({ tier: 0 })) });
    const o: any = await own.beforeToolCallback({ tool: pay, toolArgs: {}, toolContext: null as any });
    expect(o.subject).toBe("self");
    expect(o.detail).toMatch(/^This agent/);
  });
  test("a bad violation threshold fails at construction", () => {
    expect(() => new OpenEntityGate(["x"], { denyOnViolation: "severe" as any })).toThrow();
    expect(() => openEntityVerified(() => 1, { denyOnViolation: "severe" as any })).toThrow();
  });
  test("a self gate without an identity denies and creates no key", async () => {
    const home = mkdtempSync(join(tmpdir(), "oe-gate-"));
    process.env.OPENENTITY_HOME = home; process.env.OPENENTITY_KEYCHAIN = "off";
    try {
      const gate = new OpenEntityGate(["pay_agent"], { trust: fn(report()) });
      expect(await gate.beforeToolCallback({ tool: pay, toolArgs: {}, toolContext: null as any })).toMatchObject({ reason: "no_identity" });
      expect(readdirSync(home)).toEqual([]);
    } finally { rmSync(home, { recursive: true, force: true }); }
  });
});

describe("mcpToolsets", () => {
  const conn = (t: any) => t.mcpSessionManager.connectionParams;
  async function headersOf(t: any): Promise<Headers> {
    let seen: Headers | undefined;
    const real = globalThis.fetch;
    globalThis.fetch = (async (_u: any, init?: RequestInit) => { seen = new Headers(init?.headers); return new Response("{}"); }) as typeof fetch;
    try { await conn(t).transportOptions.fetch("https://x.example", {}); } finally { globalThis.fetch = real; }
    return seen!;
  }
  test("each server gets the header it accepts, and the defaults", async () => {
    for (const k of ["AGENT_SECRET_STORE_API_KEY", "CLAWGRC_API_KEY", "AGENT_SECRET_STORE_MCP_URL", "CLAWGRC_MCP_URL"]) delete process.env[k];
    process.env.MOLTBOTDEN_API_KEY = "mbd";
    expect(mcpToolsets()).toHaveLength(2);
    process.env.AGENT_SECRET_STORE_API_KEY = "ass_k"; process.env.CLAWGRC_API_KEY = "cgrc_k";
    const sets = mcpToolsets();
    expect(sets.map((t) => conn(t).url)).toEqual(["https://api.moltbotden.com/mcp", "https://mcp.openentity.org/mcp", "https://mcp.agentsecretstore.com/mcp", "https://api.clawgrc.com/mcp"]);
    expect((await headersOf(sets[2])).get("authorization")).toBe("Bearer ass_k");
    expect((await headersOf(sets[3])).get("x-api-key")).toBe("cgrc_k");
    process.env.CLAWGRC_MCP_URL = "https://grc.example/mcp";
    expect(conn(mcpToolsets()[3]).url).toBe("https://grc.example/mcp");
    expect(mcpToolsets({ moltbotden: false, openentity: false })).toHaveLength(2);
    for (const k of ["AGENT_SECRET_STORE_API_KEY", "CLAWGRC_API_KEY", "CLAWGRC_MCP_URL", "MOLTBOTDEN_API_KEY"]) delete process.env[k];
  });
  test("the Open Entity preset exposes only read tools", () => {
    const filter = (mcpToolsets({ moltbotden: false })[0] as any).toolFilter as string[];
    expect([...filter].sort()).toEqual(["openentity_card", "openentity_find", "openentity_read", "openentity_resolve", "openentity_stats", "openentity_verify"]);
  });
  test("Moltbot Den waits for a key and hides heartbeat tools", async () => {
    const home = mkdtempSync(join(tmpdir(), "oe-mcp-"));
    process.env.OPENENTITY_HOME = home;
    try {
      expect(mcpToolsets().map((t) => conn(t).url)).toEqual(["https://mcp.openentity.org/mcp"]);
      saveStore("my_app", { api_key: "stored" });
      const den = mcpToolsets({ appName: "my_app" })[0];
      expect(conn(den).url).toBe("https://api.moltbotden.com/mcp");
      expect((await headersOf(den)).get("x-api-key")).toBe("stored");
      const filter = (den as any).toolFilter;
      expect(filter({ name: "heartbeat_sovereign" }, null)).toBe(false);
      expect(filter({ name: "discover_agents" }, null)).toBe(true);
    } finally { rmSync(home, { recursive: true, force: true }); }
  });
});
