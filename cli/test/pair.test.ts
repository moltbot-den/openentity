// `openentity pair` and `openentity owner` against the fake registry plus an in-memory account service. No network.
import { execFileSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { pairSas, verifyRequest } from "@openentity/sdk";
import { run } from "../src/main";
import { KEY_HOME, SKILL_FILES } from "../src/pair";
import { startFake, type Fake } from "./fake-registry";

const ACCOUNT = "https://account.example", CODE = "OE-7K4M-Q2XP";
let fake: Fake, home: string, hostHome: string;
let calls: { method: string; path: string; did: string; body: any }[] = [];
let routes: Record<string, (body: any, did: string) => { status?: number; json?: unknown }> = {};
const realFetch = globalThis.fetch;
const realHome = process.env.HOME;

beforeAll(async () => {
  fake = await startFake();
  // The account service checks every signature; openentity.org/skill/ serves stand-ins; everything else is the fake registry.
  globalThis.fetch = (async (input: string | URL | Request, init: RequestInit = {}) => {
    const url = String(input instanceof Request ? input.url : input);
    if (url.startsWith("https://openentity.org/skill/")) return new Response(`stand-in for ${url.slice(29)}`);
    if (!url.startsWith(ACCOUNT)) return realFetch(input, init);
    const method = init.method ?? "GET", body = init.body as Uint8Array | undefined;
    const { did } = await verifyRequest({ method, url, headers: init.headers as Record<string, string>, body });
    const path = new URL(url).pathname, parsed = body ? JSON.parse(new TextDecoder().decode(body)) : undefined;
    calls.push({ method, path, did, body: parsed });
    const r = routes[`${method} ${path}`]?.(parsed, did) ?? { status: 404, json: { error: "not_found", message: "no route" } };
    return new Response(r.json === undefined ? null : JSON.stringify(r.json), { status: r.status ?? 200 });
  }) as typeof fetch;
});
afterAll(async () => {
  globalThis.fetch = realFetch;
  await fake.close();
});
beforeEach(async () => {
  home = await mkdtemp(join(tmpdir(), "oe-pair-"));
  hostHome = await mkdtemp(join(tmpdir(), "oe-pair-home-"));
  process.env.OPENENTITY_HOME = home;
  process.env.HOME = hostHome;
  delete process.env.OPENENTITY_NAME;
  calls = [];
  const claim = (body: any, did: string) => ({ status: 201, json: { pairing_id: "pr_1", sas: { version: "pair-sas/1", indexes: [1, 2, 3, 4], names: pairSas(body.code, did) }, expires_at: Math.floor(Date.now() / 1000) + 600, poll_interval: 2 } });
  routes = {
    "POST /v1/pair": claim,
    "GET /v1/pair/pr_1": () => ({ json: { state: "confirmed", owner_did: "did:web:account.example:o:abc", permissions: ["owner.message", "owner.status"], credentials: [{ product: "did:web:moltbotden.com", kind: "bearer", key: "moltbotden_sk_test", expires_at: 1_800_000_000 }] } }),
  };
});
afterEach(async () => {
  process.env.HOME = realHome;
  await rm(home, { recursive: true, force: true });
  await rm(hostHome, { recursive: true, force: true });
});

async function cli(...args: string[]) {
  let out = "", err = "";
  const code = await run(args, { out: (s) => void (out += s), err: (s) => void (err += s) });
  return { code, out, err };
}
const pairArgs = (...extra: string[]) => ["pair", CODE.toLowerCase(), "--registry", fake.url, "--account", ACCOUNT, ...extra];

describe("pair", () => {
  it("adopts when this home has no entity, says so, shows the match, waits and prints the keys once", async () => {
    const r = await cli(...pairArgs("--json"));
    expect(r.code, r.err).toBe(0);
    const out = JSON.parse(r.out);
    expect(out).toMatchObject({ adopted: true, owner_did: "did:web:account.example:o:abc", permissions: ["owner.message", "owner.status"] });
    expect(fake.entities.has(out.eid)).toBe(true);
    expect(out.credentials[0]).toMatchObject({ key: "moltbotden_sk_test", put_it_in: KEY_HOME["did:web:moltbotden.com"] });
    expect(r.err).toContain("signed the Open Entity Declaration");
    expect(r.err).toContain(`Match: ${pairSas(CODE, out.eid).join(", ")}`);
    expect(calls[0]).toMatchObject({ method: "POST", path: "/v1/pair", did: out.eid, body: { code: CODE, framework: "other", sdk: "openentity-cli" } });
    expect(calls[0].body.presentation).toMatchObject({ eid: out.eid, audience: "did:web:account.example", nonce: `pair:${CODE}` });
  });

  it("pairs the existing entity without adopting again; text output", async () => {
    expect((await cli("adopt", "--name", "Existing", "--agree", "--registry", fake.url)).code).toBe(0);
    const before = fake.entities.size;
    const r = await cli(...pairArgs());
    expect(r.code, r.err).toBe(0);
    expect(fake.entities.size).toBe(before);
    expect(r.out).toMatch(/^Match: /m);
    expect(r.out).toContain("Paired did:key:");
    expect(r.out).toContain("  moltbotden_sk_test\n  Put it in: Moltbot Den");
    expect(r.out).not.toContain("Declaration");
  });

  it("refuses a match the service did not compute from this agent's DID (exit 3)", async () => {
    routes["POST /v1/pair"] = (body) => ({ status: 201, json: { pairing_id: "pr_1", sas: { version: "pair-sas/1", indexes: [0, 0, 0, 0], names: pairSas(body.code, "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK") }, expires_at: 9e9, poll_interval: 2 } });
    const r = await cli(...pairArgs());
    expect(r.code).toBe(3);
    expect(r.out).not.toContain("Match:");
    expect(r.err).toContain("verification_failed");
  });

  it("checks the code before anything else, and never adopts next to entities it cannot choose between", async () => {
    expect((await cli("pair", "OE-12")).code).toBe(1);
    for (const n of ["One", "Two"]) await cli("adopt", "--name", n, "--agree", "--registry", fake.url);
    await rm(join(home, "current"));
    const before = fake.entities.size;
    const r = await cli(...pairArgs());
    expect([r.code, fake.entities.size, calls.length]).toEqual([5, before, 0]);
  });

  it("--openclaw writes the anchor into the workspace, installs the skill and registers the MCP server", async () => {
    const ws = join(hostHome, ".openclaw", "workspace");
    await mkdir(ws, { recursive: true });
    const r = await cli(...pairArgs("--openclaw", "--json"));
    expect(r.code, r.err).toBe(0);
    const out = JSON.parse(r.out);
    expect(calls[0].body.framework).toBe("openclaw");
    expect(out.openclaw.identity_files).toEqual([join(ws, "IDENTITY.md"), join(ws, "SOUL.md")]);
    expect(await readFile(join(ws, "SOUL.md"), "utf8")).toContain(out.eid);
    const skill = join(hostHome, ".openclaw", "skills", "openentity");
    expect(await readFile(join(skill, "SKILL.md"), "utf8")).toBe("stand-in for SKILL.md");
    expect((await stat(join(skill, "scripts", "adopt.sh"))).mode & 0o111).toBeTruthy();
    const config = JSON.parse(await readFile(join(hostHome, ".openclaw", "openclaw.json"), "utf8"));
    expect(config.mcp.servers.openentity).toEqual({ command: "npx", args: ["-y", "@openentity/mcp"], env: { OPENENTITY_HOME: home, OPENENTITY_ACCOUNT: ACCOUNT } });
    expect((await stat(join(hostHome, ".openclaw", "openclaw.json"))).mode & 0o777).toBe(0o600);
  });

  it("--openclaw keeps an existing config's settings and leaves a JSON5 config untouched", async () => {
    const oc = join(hostHome, ".openclaw");
    await mkdir(oc, { recursive: true });
    await writeFile(join(oc, "openclaw.json"), JSON.stringify({ gateway: { bind: "loopback" }, mcp: { servers: { fs: { command: "x" } } } }));
    const dir = await mkdtemp(join(tmpdir(), "oe-ws-"));
    expect((await cli(...pairArgs("--openclaw", "--dir", dir))).code).toBe(0);
    const config = JSON.parse(await readFile(join(oc, "openclaw.json"), "utf8"));
    expect([config.gateway.bind, Object.keys(config.mcp.servers)]).toEqual(["loopback", ["fs", "openentity"]]);
    const json5 = "{ // mine\n gateway: { bind: 'lan' }, }\n";
    await writeFile(join(oc, "openclaw.json"), json5);
    const r = await cli(...pairArgs("--openclaw", "--dir", dir));
    expect(r.code).toBe(0);
    expect(await readFile(join(oc, "openclaw.json"), "utf8")).toBe(json5);
    expect(r.out).toContain("is not plain JSON, so it was left as it is");
    await rm(dir, { recursive: true, force: true });
  });

  it("SKILL_FILES lists every tracked file of skill/openentity", () => {
    // From the repository root: under a git hook GIT_DIR is set, and git then takes the working directory for the top level.
    const files = execFileSync("git", ["ls-files", "skill/openentity"], { cwd: join(import.meta.dirname, "../.."), encoding: "utf8" }).trim().split("\n");
    expect(files.map((f) => f.slice("skill/openentity/".length)).sort()).toEqual([...SKILL_FILES].sort());
  });
});

describe("owner", () => {
  it("message, status, inbox and ask are signed by the current entity", async () => {
    const { eid } = JSON.parse((await cli("adopt", "--name", "Talker", "--agree", "--registry", fake.url, "--json")).out);
    routes = {
      "POST /v1/agent/messages": () => ({ status: 201, json: { id: "m1" } }),
      "POST /v1/agent/status": () => ({ status: 204 }),
      "GET /v1/agent/messages": () => ({ json: { items: [{ type: "command", id: "c1", created_at: 1, command: "checkup", args: {} }], more: false } }),
      "POST /v1/agent/messages/ack": () => ({ status: 204 }),
      "POST /v1/agent/approvals": (b) => ({ status: 201, json: { id: "ap1", state: "pending", title: b.title, expires_at: 9e9 } }),
    };
    const a = ["--account", ACCOUNT];
    expect((await cli("owner", "message", "hello", "there", ...a)).out).toBe("sent to your owner (m1)\n");
    expect((await cli("owner", "status", "running", "indexing", "docs", "--progress", "0.5", ...a)).code).toBe(0);
    expect((await cli("owner", "inbox", ...a)).out).toBe("c1 command: checkup\n");
    expect((await cli("owner", "ask", "--title", "Deploy", "--summary", "Ship v2", "--risk", "high", ...a)).out).toBe("pending: Deploy (ap1)\n");
    expect(calls.every((c) => c.did === eid)).toBe(true);
    expect(calls.map((c) => c.body)).toEqual([{ text: "hello there" }, { state: "running", summary: "indexing docs", progress: 0.5 }, undefined, { ids: ["c1"] }, { title: "Deploy", summary: "Ship v2", risk: "high", expires_in: 600 }]);
    routes["POST /v1/agent/messages"] = () => ({ status: 423, json: { error: "agent_paused", message: "paused by the owner" } });
    const r = await cli("owner", "message", "x", ...a);
    expect([r.code, r.err]).toEqual([4, "openentity: agent_paused: account 423 for POST /v1/agent/messages: paused by the owner\n"]);
    expect((await cli("owner", "dance", ...a)).code).toBe(1);
  });
});
