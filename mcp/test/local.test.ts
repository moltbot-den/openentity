// The local stdio server's tools over an in-memory MCP transport, against an in-memory account service. No network.
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { buildDocument, generateKeyPair, pairSas, signObject, verifyRequest, type KeyPair } from "@openentity/sdk";
import { createEntityDir, setCurrent } from "../../cli/src/store.ts";
import { localServer } from "../src/local.ts";

const ACCOUNT = "https://account.example", CODE = "OE-7K4M-Q2XP";
let home: string, kp: KeyPair, client: Client;
let calls: { method: string; path: string; did: string; body: any }[] = [];
let routes: Record<string, (body: any) => { status?: number; json?: unknown }> = {};
const realFetch = globalThis.fetch;

beforeAll(async () => {
  home = await mkdtemp(join(tmpdir(), "oe-mcp-"));
  process.env.OPENENTITY_HOME = home;
  globalThis.fetch = (async (url: string, init: RequestInit = {}) => {
    const method = init.method ?? "GET", body = init.body as Uint8Array | undefined;
    const { did } = await verifyRequest({ method, url, headers: init.headers as Record<string, string>, body });
    const path = new URL(url).pathname;
    calls.push({ method, path, did, body: body ? JSON.parse(new TextDecoder().decode(body)) : undefined });
    const r = routes[`${method} ${path}`]?.(calls.at(-1)!.body) ?? { status: 404, json: { error: "not_found", message: "no route" } };
    return new Response(r.json === undefined ? null : JSON.stringify(r.json), { status: r.status ?? 200 });
  }) as typeof fetch;
  const [a, b] = InMemoryTransport.createLinkedPair();
  await localServer({ account: ACCOUNT }).connect(a);
  client = new Client({ name: "claude-code", version: "9" });
  await client.connect(b);
});
afterAll(async () => {
  globalThis.fetch = realFetch;
  await client.close();
  await rm(home, { recursive: true, force: true });
});
beforeEach(() => {
  calls = [];
});

async function tool(name: string, args: Record<string, unknown> = {}) {
  const r: any = await client.callTool({ name, arguments: args });
  const t = r.content[0].text as string;
  let json: any = t;
  try { json = JSON.parse(t); } catch { /* plain text */ }
  return { isError: !!r.isError, json, text: t };
}

describe("local MCP server", () => {
  it("lists the pairing and owner tools", async () => {
    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name).sort()).toEqual(["openentity_pair", "owner_ask_approval", "owner_inbox", "owner_message", "owner_status"]);
  });

  it("owner tools say how to start when this machine holds no key", async () => {
    const r = await tool("owner_message", { text: "hi" });
    expect([r.isError, r.text]).toEqual([true, expect.stringContaining("call openentity_pair")]);
    expect((await tool("openentity_pair", { wait: true })).isError).toBe(true);
  });

  it("pairs in two calls: the match items first, the owner's answer after wait=true", async () => {
    kp = await generateKeyPair();
    const doc = await signObject(buildDocument({ kp, name: "MCP Agent", description: "d" }), kp);
    await createEntityDir(kp, { doc, state: { registry: "https://openentity.org", docSeq: 1, recordPushed: 0 } });
    await setCurrent(kp.did);
    routes = {
      "POST /v1/pair": (b) => ({ status: 201, json: { pairing_id: "pr_1", sas: { version: "pair-sas/1", indexes: [1, 2, 3, 4], names: pairSas(b.code, kp.did) }, expires_at: Math.floor(Date.now() / 1000) + 600, poll_interval: 2 } }),
      "GET /v1/pair/pr_1": () => ({ json: { state: "confirmed", owner_did: "did:web:account.example:o:abc", permissions: ["owner.message"], credentials: [{ product: "did:web:api.clawgrc.com", kind: "bearer", key: "cgrc_test", expires_at: 1_800_000_000 }] } }),
    };
    const first = await tool("openentity_pair", { code: CODE });
    expect(first.isError).toBe(false);
    expect(first.text).toContain(`Match: ${pairSas(CODE, kp.did).join(", ")}`);
    expect(calls[0].body).toMatchObject({ code: CODE, framework: "claude-code", sdk: "@openentity/mcp" });
    expect((await tool("openentity_pair", { code: "OE-AAAA-BBBB" })).text).toContain("still waiting");
    const done = await tool("openentity_pair", { wait: true });
    expect(done.json).toMatchObject({ eid: kp.did, adopted: false, owner_did: "did:web:account.example:o:abc", credentials: [{ key: "cgrc_test", put_it_in: expect.stringContaining("CLAW_GRC_API_KEY") }] });
    expect(done.json.warning).toMatch(/^SECRET/);
  });

  it("owner_message, owner_status, owner_inbox and owner_ask_approval sign with the paired key", async () => {
    routes = {
      "POST /v1/agent/messages": () => ({ status: 201, json: { id: "m1" } }),
      "POST /v1/agent/status": () => ({ status: 204 }),
      "GET /v1/agent/messages": () => ({ json: { items: [], more: false } }),
      "POST /v1/agent/approvals": (b) => ({ status: 201, json: { id: "ap1", state: "pending", title: b.title, expires_at: 9e9 } }),
    };
    expect((await tool("owner_message", { text: "hello" })).text).toBe("sent (m1)");
    expect((await tool("owner_status", { state: "blocked", summary: "waiting for a key" })).text).toBe("status: blocked");
    expect((await tool("owner_inbox")).text).toBe("nothing new");
    expect((await tool("owner_ask_approval", { title: "Spend", summary: "Buy 10 credits", risk: "medium" })).json).toMatchObject({ id: "ap1", state: "pending" });
    expect(calls.every((c) => c.did === kp.did)).toBe(true);
    expect(calls.map((c) => c.body)).toEqual([{ text: "hello" }, { state: "blocked", summary: "waiting for a key" }, undefined, { title: "Spend", summary: "Buy 10 credits", risk: "medium", expires_in: 600 }]);
    routes["POST /v1/agent/messages"] = () => ({ status: 403, json: { error: "not_paired", message: "unlinked" } });
    expect(await tool("owner_message", { text: "x" })).toMatchObject({ isError: true, text: expect.stringMatching(/^not_paired: /) });
  });
});
