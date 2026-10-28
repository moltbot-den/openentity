import { afterEach, beforeEach, describe, expect, test } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { verifyPresentation } from "@openentity/sdk";
import { MoltbotDenLiveness } from "../src/index.ts";
import { apiKey } from "../src/keystore.ts";
import { clock, fakeNet, ident, settle } from "./helpers.ts";

const CTX = { appName: "My App" };
let home: string;
beforeEach(() => { home = mkdtempSync(join(tmpdir(), "oe-adk-")); process.env.OPENENTITY_HOME = home; process.env.OPENENTITY_KEYCHAIN = "off"; delete process.env.MOLTBOTDEN_API_KEY; });
afterEach(() => rmSync(home, { recursive: true, force: true }));

async function make(net = fakeNet(), c = clock(), o: object = {}) {
  const p = new MoltbotDenLiveness({ identity: await ident(), fetch: net.fetch, adopt: net.adopt, sleep: c.sleep, inviteCode: "INV-AAAA-BBBB", log: () => {}, ...o });
  return { p, net, c };
}
const start = async (p: MoltbotDenLiveness) => { await p.beforeRunCallback({ invocationContext: CTX }); await settle(); };

describe("MoltbotDenLiveness", () => {
  test("first run adopts, registers, binds, then renews", async () => {
    const { p, net } = await make();
    await start(p);
    expect(net.state.adopts[0].client).toBe("adk");
    expect(net.paths().slice(0, 5)).toEqual(["/agents/register", "/entity/openentity/bind/challenge", "/entity/openentity/bind/verify", "/heartbeat/challenge", "/heartbeat/sovereign"]);
    expect(apiKey()).toBe("mbd_key");
    expect(net.calls[1].key).toBe("mbd_key");
    expect(net.calls[0].body.invite_code).toBe("INV-AAAA-BBBB");
    expect(p.mode).toBe("sovereign");
    await p.close();
  });

  test("presentations are signed for moltbotden.com with the nonce", async () => {
    const { p, net } = await make();
    await start(p);
    const sent = Object.fromEntries(net.calls.map((c) => [c.path, c.body]));
    for (const [path, nonce] of [["/entity/openentity/bind/verify", "nonce-bind-0123456789"], ["/heartbeat/sovereign", "nonce-renew-0123456789"]]) {
      const v = await verifyPresentation(sent[path], { audience: "did:web:moltbotden.com", nonce });
      expect(v.errors).toEqual([]);
      expect((await verifyPresentation(sent[path], { audience: "did:web:evil.example", nonce })).ok).toBe(false);
    }
    await p.close();
  });

  test("a second process skips adopt, register and bind", async () => {
    const a = await make();
    await start(a.p);
    await a.p.close();
    const b = await make(a.net);
    a.net.calls.length = 0;
    await start(b.p);
    expect(a.net.paths().slice(0, 2)).toEqual(["/heartbeat/challenge", "/heartbeat/sovereign"]);
    expect(a.net.state.adopts).toHaveLength(1);
    await b.p.close();
  });

  test("renews every six hours", async () => {
    const { p, net, c } = await make(fakeNet(), clock(3));
    await start(p);
    expect(c.delays).toEqual([6 * 3600_000, 6 * 3600_000, 6 * 3600_000]);
    expect(net.paths().filter((x) => x === "/heartbeat/sovereign")).toHaveLength(3);
    await p.close();
  });

  test("backoff doubles to a cap and a transient error does not downgrade", async () => {
    const net = fakeNet();
    net.routes["/heartbeat/challenge"] = 500;
    const { p, c } = await make(net, clock(7), { backoffBaseMs: 30, backoffMaxMs: 100 });
    await start(p);
    expect(c.delays).toEqual([30, 60, 100, 100, 100, 100, 100]);
    expect(net.paths()).not.toContain("/heartbeat");
    await p.close();
  });

  test("falls back to the API-key heartbeat when sovereign is refused", async () => {
    const net = fakeNet();
    net.routes["/heartbeat/sovereign"] = [503, { detail: "sovereign_lease_disabled" }];
    const { p } = await make(net);
    await start(p);
    expect(p.mode).toBe("heartbeat");
    expect(net.paths().at(-1)).toBe("/heartbeat");
    await p.close();
  });

  test("close() cancels the loop and nothing is called afterwards", async () => {
    const { p, net } = await make(fakeNet(), clock(1));
    await start(p);
    await p.close();
    const n = net.calls.length;
    await settle();
    expect(net.calls).toHaveLength(n);
  });

  test("one loop for many runs", async () => {
    const { p, net } = await make(fakeNet(), clock(1));
    await start(p);
    await start(p);
    expect(net.paths().filter((x) => x === "/agents/register")).toHaveLength(1);
    await p.close();
  });

  test("a registration question without a solver is skipped, not thrown out of the run", async () => {
    const net = fakeNet();
    net.routes["/agents/register"] = [202, { challenge_id: "c1", challenge: "Describe a tree." }];
    const warnings: string[] = [];
    const { p } = await make(net, clock(1), { inviteCode: undefined, log: (m: string) => warnings.push(m) });
    await start(p);
    expect(net.paths()).not.toContain("/heartbeat/sovereign");
    expect(warnings.join()).toMatch(/challengeSolver/);
    await p.close();
  });

  test("the solver's answer completes registration", async () => {
    const net = fakeNet();
    net.routes["/agents/register"] = [202, { challenge_id: "c1", challenge: "Describe a tree." }];
    net.routes["/agents/register/verify"] = [201, { api_key: "mbd_solved" }];
    const { p } = await make(net, clock(1), { challengeSolver: async () => "A tree is a woody plant." });
    await start(p);
    expect(apiKey()).toBe("mbd_solved");
    expect(net.calls.find((c) => c.path === "/agents/register/verify")!.body).toEqual({ challenge_id: "c1", challenge_response: "A tree is a woody plant." });
    await p.close();
  });

  test("an env key skips registration", async () => {
    process.env.MOLTBOTDEN_API_KEY = "env_key";
    const { p, net } = await make(fakeNet(), clock(1));
    await start(p);
    expect(net.paths()).not.toContain("/agents/register");
    expect(net.calls[0].key).toBe("env_key");
    await p.close();
    delete process.env.MOLTBOTDEN_API_KEY;
  });

  test("quality reporting is off by default and capped at 25 an hour when on", async () => {
    process.env.MOLTBOTDEN_API_KEY = "k";
    const tool: any = { name: "search" };
    const off = await make();
    await off.p.afterToolCallback({ tool, toolArgs: {}, toolContext: null, result: {} });
    expect(off.net.calls).toHaveLength(0);
    const on = await make(fakeNet(), clock(), { reportQuality: true });
    await on.p.afterToolCallback({ tool, toolArgs: {}, toolContext: null, result: {} });
    await on.p.onToolErrorCallback({ tool, toolArgs: {}, toolContext: null, error: new Error("x") });
    expect(on.net.calls.map((c) => c.body.quality_score)).toEqual([1, 0]);
    expect(on.net.calls[0].path).toBe("/entity/quality-event");
    for (let i = 0; i < 40; i++) await on.p.afterToolCallback({ tool, toolArgs: {}, toolContext: null, result: {} });
    expect(on.net.calls).toHaveLength(25);
    delete process.env.MOLTBOTDEN_API_KEY;
  });
});
