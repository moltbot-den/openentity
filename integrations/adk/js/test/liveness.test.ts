import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { chmodSync, mkdtempSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { verifyPresentation } from "@openentity/sdk";
import { MoltbotDenError, MoltbotDenLiveness, MoltbotDenStopped } from "../src/index.ts";
import { apiKey, saveStore } from "../src/keystore.ts";
import { clock, fakeNet, ident, settle } from "./helpers.ts";

const CTX = { appName: "My App" };
const REJECTED = { "WWW-Authenticate": "ApiKey" }; // how Moltbot Den marks an API-key rejection
let home: string;
beforeEach(() => { home = mkdtempSync(join(tmpdir(), "oe-adk-")); process.env.OPENENTITY_HOME = home; process.env.OPENENTITY_KEYCHAIN = "off"; delete process.env.MOLTBOTDEN_API_KEY; });
afterEach(() => rmSync(home, { recursive: true, force: true }));

async function make(net = fakeNet(), c = clock(), o: object = {}) {
  const p = new MoltbotDenLiveness({ identity: await ident(), fetch: net.fetch, adopt: net.adopt, sleep: c.sleep, inviteCode: "INV-AAAA-BBBB", log: () => {}, ...o });
  clocks.set(p, c);
  return { p, net, c };
}
// Wait for the loop to reach its `limit`-th sleep: every step before it has finished, however slow the machine.
const clocks = new WeakMap<object, { delays: number[]; limit: number }>();
const start = async (p: MoltbotDenLiveness) => {
  const c = clocks.get(p)!;
  await p.beforeRunCallback({ invocationContext: CTX });
  await vi.waitFor(() => expect(c.delays.length).toBeGreaterThanOrEqual(c.limit), { timeout: 4000 });
};

describe("MoltbotDenLiveness", () => {
  test("first run adopts, registers, binds, then renews", async () => {
    const { p, net } = await make();
    await start(p);
    expect(net.state.adopts[0].client).toBe("adk");
    expect(net.paths().slice(0, 5)).toEqual(["/agents/register", "/entity/openentity/bind/challenge", "/entity/openentity/bind/verify", "/heartbeat/challenge", "/heartbeat/sovereign"]);
    expect(apiKey("My App")).toBe("mbd_key");
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
    const b = await make(a.net, clock(1));
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

  test("with no way to a key nothing is adopted or registered, and the loop stops", async () => {
    const errors: string[] = [];
    const { p, net, c } = await make(fakeNet(), clock(5), { inviteCode: undefined, log: (m: string) => errors.push(m) });
    await p.beforeRunCallback({ invocationContext: CTX });
    await vi.waitFor(() => expect(errors.join()).toMatch(/stopped/));
    expect(net.calls).toEqual([]);
    expect(net.state.adopts).toEqual([]);
    expect(c.delays).toEqual([]);
    await p.close();
  });

  test("the agent's own model answers the registration question by default", async () => {
    const net = fakeNet();
    net.routes["/agents/register"] = [202, { challenge_id: "c1", challenge: "Describe a tree." }];
    net.routes["/agents/register/verify"] = [201, { api_key: "mbd_model" }];
    const asked: string[] = [];
    const model = { model: "fake", async *generateContentAsync(req: any) { asked.push(req.contents[0].parts[0].text); yield { content: { role: "model", parts: [{ text: "A woody plant." }] } }; } };
    const { p, c } = await make(net, clock(1), { inviteCode: undefined });
    await p.beforeRunCallback({ invocationContext: { appName: "app", agent: { canonicalModel: model } } });
    await vi.waitFor(() => expect(c.delays.length).toBe(1));
    expect(asked).toEqual(["Describe a tree."]);
    expect(apiKey("app")).toBe("mbd_model");
    await p.close();
  });

  test("the solver's answer completes registration", async () => {
    const net = fakeNet();
    net.routes["/agents/register"] = [202, { challenge_id: "c1", challenge: "Describe a tree." }];
    net.routes["/agents/register/verify"] = [201, { api_key: "mbd_solved" }];
    const { p } = await make(net, clock(1), { challengeSolver: async () => "A tree is a woody plant." });
    await start(p);
    expect(apiKey("My App")).toBe("mbd_solved");
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
    await settle();
    expect(on.net.calls.map((c) => c.body.quality_score)).toEqual([1, 0]);
    expect(on.net.calls[0].path).toBe("/entity/quality-event");
    for (let i = 0; i < 40; i++) await on.p.afterToolCallback({ tool, toolArgs: {}, toolContext: null, result: {} });
    await settle();
    expect(on.net.calls).toHaveLength(25);
    // fire and forget: a report that never answers does not hold up the tool path
    const hung = await make(fakeNet(), clock(), { reportQuality: true, fetch: (() => new Promise(() => {})) as typeof fetch });
    await hung.p.afterToolCallback({ tool, toolArgs: {}, toolContext: null, result: {} });
    delete process.env.MOLTBOTDEN_API_KEY;
  });

  test("each app keeps its own Moltbot Den agent", async () => {
    const net = fakeNet();
    for (const [app, key] of [["App A", "key_a"], ["App B", "key_b"]]) {
      net.routes["/agents/register"] = [201, { api_key: key }];
      const c = clock(1);
      const p = new MoltbotDenLiveness({ identity: await ident(), fetch: net.fetch, adopt: net.adopt, sleep: c.sleep, inviteCode: "INV-AAAA-BBBB", log: () => {} });
      await p.beforeRunCallback({ invocationContext: { appName: app } });
      await vi.waitFor(() => expect(c.delays.length).toBe(1));
      await p.close();
    }
    expect([apiKey("App A"), apiKey("App B")]).toEqual(["key_a", "key_b"]);
  });

  test("switching the API key binds again", async () => {
    const net = fakeNet();
    for (const key of ["key_1", "key_2"]) {
      process.env.MOLTBOTDEN_API_KEY = key;
      await new MoltbotDenLiveness({ identity: await ident(), fetch: net.fetch, adopt: net.adopt, log: () => {} }).step();
    }
    expect(net.paths().filter((x) => x === "/entity/openentity/bind/verify")).toHaveLength(2);
    delete process.env.MOLTBOTDEN_API_KEY;
  });

  test("a rejected stored key registers again, once", async () => {
    saveStore("adk-agent", { agent_id: "old", api_key: "revoked" });
    const net = fakeNet();
    const f = ((u: string, i?: RequestInit) => new Headers(i?.headers).get("x-api-key") === "revoked"
      ? Promise.resolve(new Response("{}", { status: 401, headers: REJECTED })) : net.fetch(u, i)) as typeof fetch;
    const p = new MoltbotDenLiveness({ identity: await ident(), fetch: f, adopt: net.adopt, inviteCode: "INV-AAAA-BBBB", log: () => {} });
    await p.step();
    expect(apiKey("adk-agent")).toBe("mbd_key");
    expect(p.mode).toBe("sovereign");
  });

  test("a rejected env key stops with a clear error", async () => {
    process.env.MOLTBOTDEN_API_KEY = "bad";
    const net = fakeNet();
    const f = ((u: string, i?: RequestInit) => new URL(u).pathname.startsWith("/entity")
      ? Promise.resolve(new Response("{}", { status: 401, headers: REJECTED })) : net.fetch(u, i)) as typeof fetch;
    const p = new MoltbotDenLiveness({ identity: await ident(), fetch: f, adopt: net.adopt, log: () => {} });
    await expect(p.step()).rejects.toThrow(MoltbotDenStopped);
    await expect(p.step()).rejects.toThrow(/MOLTBOTDEN_API_KEY/);
    expect(net.paths()).not.toContain("/agents/register");
    delete process.env.MOLTBOTDEN_API_KEY;
  });

  test("a refused Presentation keeps the key: only an API-key rejection (WWW-Authenticate) may cost it", async () => {
    saveStore("adk-agent", { agent_id: "a", api_key: "good" });
    const net = fakeNet();
    net.routes["/entity/openentity/bind/verify"] = [401, { detail: "presentation_invalid" }];
    const p = new MoltbotDenLiveness({ identity: await ident(), fetch: net.fetch, adopt: net.adopt, inviteCode: "INV-AAAA-BBBB", log: () => {} });
    const err = await p.step().catch((e) => e);
    expect(err).toBeInstanceOf(MoltbotDenError);
    expect(err).not.toBeInstanceOf(MoltbotDenStopped);
    expect(apiKey("adk-agent")).toBe("good");
    expect(net.paths()).not.toContain("/agents/register");
  });

  test("a suspended account stops instead of registering a new agent", async () => {
    saveStore("adk-agent", { agent_id: "a", api_key: "good" });
    const net = fakeNet();
    net.routes["/entity/openentity/bind/challenge"] = [403, { detail: "Account suspended. Contact support." }];
    const p = new MoltbotDenLiveness({ identity: await ident(), fetch: net.fetch, adopt: net.adopt, inviteCode: "INV-AAAA-BBBB", log: () => {} });
    await expect(p.step()).rejects.toThrow(/suspended/);
    expect(net.paths()).not.toContain("/agents/register");
  });

  test("bind tags the agent as an ADK agent", async () => {
    const net = fakeNet();
    const urls: string[] = [];
    const f = ((u: string, i?: RequestInit) => (urls.push(u), net.fetch(u, i))) as typeof fetch;
    await new MoltbotDenLiveness({ identity: await ident(), fetch: f, adopt: net.adopt, inviteCode: "INV-AAAA-BBBB", log: () => {} }).step();
    expect(urls.some((u) => u.endsWith("/entity/openentity/bind/verify?framework=adk"))).toBe(true);
  });

  test("one agent per network stops instead of retrying", async () => {
    const net = fakeNet();
    net.routes["/agents/register"] = [429, { detail: "This location has already registered an agent." }];
    const errors: string[] = [];
    const { p, c } = await make(net, clock(5), { log: (m: string) => errors.push(m) });
    await p.beforeRunCallback({ invocationContext: CTX });
    await vi.waitFor(() => expect(errors.join()).toMatch(/invite/));
    expect(net.paths()).toEqual(["/agents/register"]);
    expect(c.delays).toEqual([]);
    await p.close();
  });

  test("every request carries a signal, so close() ends a hung request", async () => {
    const signals: AbortSignal[] = [];
    const hang = ((_u: string, i?: RequestInit) => {
      signals.push(i!.signal!);
      return new Promise((_, reject) => i!.signal!.addEventListener("abort", () => reject(i!.signal!.reason), { once: true }));
    }) as typeof fetch;
    const p = new MoltbotDenLiveness({ identity: await ident(), fetch: hang, inviteCode: "INV-AAAA-BBBB", log: () => {} });
    await p.beforeRunCallback({ invocationContext: CTX });
    await vi.waitFor(() => expect(signals).toHaveLength(1));
    await p.close();
  });

  test("store writes are atomic and always 0600", () => {
    const path = join(home, "moltbotden.json");
    writeFileSync(path, '{"agents":{}}');
    chmodSync(path, 0o644);
    saveStore("a", { api_key: "k" });
    expect(statSync(path).mode & 0o777).toBe(0o600);
    expect(apiKey("a")).toBe("k");
    expect(readdirSync(home)).toEqual(["moltbotden.json"]);
  });
});

test("close() during the first step still ends the loop", async () => {
  home = mkdtempSync(join(tmpdir(), "oe-adk-"));
  process.env.OPENENTITY_HOME = home;
  const net = fakeNet();
  const slow = ((u: string, i?: RequestInit) => new Promise((r) => setTimeout(r, 20)).then(() => net.fetch(u, i))) as typeof fetch;
  const c = clock(1);
  const p = new MoltbotDenLiveness({ identity: await ident(), fetch: slow, adopt: net.adopt, sleep: c.sleep, inviteCode: "INV-AAAA-BBBB", log: () => {} });
  await p.beforeRunCallback({ invocationContext: CTX });
  await p.close(); // would hang forever before the aborted-signal check
});
