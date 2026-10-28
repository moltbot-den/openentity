import { describe, expect, test } from "vitest";
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

describe("mcpToolsets", () => {
  test("defaults and env hooks", () => {
    delete process.env.AGENT_SECRET_STORE_MCP_URL; delete process.env.CLAWGRC_MCP_URL;
    expect(mcpToolsets()).toHaveLength(2);
    process.env.AGENT_SECRET_STORE_MCP_URL = "https://ass.example/mcp";
    process.env.CLAWGRC_MCP_URL = "https://grc.example/mcp";
    expect(mcpToolsets()).toHaveLength(4);
    expect(mcpToolsets({ moltbotden: false, openentity: false })).toHaveLength(2);
    delete process.env.AGENT_SECRET_STORE_MCP_URL; delete process.env.CLAWGRC_MCP_URL;
  });
});
