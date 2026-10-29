import { describe, expect, test } from "vitest";
import { createAgent, fakeModel, tool, AIMessage, ToolMessage } from "langchain";
import { z } from "zod";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { LedgerReporter, OpenEntityLoopDetected, OpenEntitySchemaViolation, RuthlessSchemaGuard, unwrap } from "../src/index.ts";
import { Routes, compileSchema, pathTemplate, scrub } from "../src/core.ts";
import { MALFORMED, SCHEMAS, serve } from "./fixtures.ts";
import { keyPairFromSeed, verifyObject } from "@openentity/sdk";

const PULLS = { type: "array", items: { type: "object", required: ["number"], properties: { number: { type: "integer" } } } };

function agent(output: string, guard: RuthlessSchemaGuard) {
  const pulls = tool(async () => output, { name: "pulls", description: "List pull requests.", schema: z.object({ repo: z.string() }) });
  const model = fakeModel().respondWithTools([{ name: "pulls", args: { repo: "a/b" }, id: "c1" }]).respond(new AIMessage("done"));
  return createAgent({ model, tools: [pulls], middleware: [guard.middleware] });
}
const go = (a: ReturnType<typeof agent>) => a.invoke({ messages: [{ role: "user", content: "go" }] });

describe("middleware", () => {
  test("valid output passes", async () => {
    const out = await go(agent('[{"number": 1}]', new RuthlessSchemaGuard({ schemas: { pulls: PULLS }, ledger: false })));
    expect(out.messages.at(-1)?.content).toBe("done");
  });

  test.each(["<html>login</html>", "", '[{"number": "1"}]', '{"error": "nope"}', '[{"number": 1'])("throws, never a ToolMessage: %j", async (bad) => {
    const thrown = await go(agent(bad, new RuthlessSchemaGuard({ schemas: { pulls: PULLS }, ledger: false }))).catch((e: unknown) => e);
    const err = unwrap(thrown) as OpenEntitySchemaViolation; // LangChain.js wraps middleware errors in a MiddlewareError
    expect(thrown).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(OpenEntitySchemaViolation);
    expect(err.tool).toBe("pulls");
    expect(err.errors.length).toBeGreaterThan(0);
    expect(err.rawExcerpt.length).toBeLessThanOrEqual(500);
  });

  test("zod schemas are strict", async () => {
    const schemas = { pulls: z.array(z.object({ number: z.number().int() })) };
    expect((await go(agent('[{"number": 1}]', new RuthlessSchemaGuard({ schemas, ledger: false })))).messages.length).toBeGreaterThan(0);
    const thrown = await go(agent('[{"number": "1"}]', new RuthlessSchemaGuard({ schemas, ledger: false }))).catch((e: unknown) => e);
    expect(unwrap(thrown)).toBeInstanceOf(OpenEntitySchemaViolation);
  });

  test("unregistered tools are untouched", async () => {
    expect((await go(agent("<html>fine here</html>", new RuthlessSchemaGuard({ ledger: false })))).messages.length).toBeGreaterThan(0);
  });

  test("an HTTP violation inside a tool cannot be swallowed", async () => {
    const s = await serve();
    const g = new RuthlessSchemaGuard({ ledger: false, scope: "all" });
    const off = g.guardHttp();
    try {
      const c = MALFORMED.find((x) => x.id === "m-html-0-ctjson")!;
      const swallow = tool(async () => { try { return await (await fetch(`${s.base}/s/free/${c.id}`)).text(); } catch (e) { return `error: ${e}`; } },
        { name: "pulls", description: "d", schema: z.object({ repo: z.string() }) });
      const model = fakeModel().respondWithTools([{ name: "pulls", args: { repo: "a/b" }, id: "c1" }]).respond(new AIMessage("done"));
      const thrown = await createAgent({ model, tools: [swallow], middleware: [g.middleware] }).invoke({ messages: [{ role: "user", content: "go" }] }).catch((e: unknown) => e);
      expect(unwrap(thrown)).toMatchObject({ rule: "html" });
    } finally { off(); s.server.close(); }
  });

  test("halt mode ends the run with a report", async () => {
    const g = new RuthlessSchemaGuard({ schemas: { pulls: PULLS }, mode: "halt", ledger: false });
    const last = (await go(agent("<html></html>", g))).messages.at(-1);
    expect(ToolMessage.isInstance(last)).toBe(true);
    expect(String(last?.content)).toContain("halted the run");
    expect(g.lastReport).toBe(last?.content);
  });
});

const req = (args: object = { a: 1 }) => ({ toolCall: { name: "t", args, id: "1" } });
const call = (g: RuthlessSchemaGuard, r: any, h: (x: any) => any) => (g.middleware as any).wrapToolCall(r, h);

describe("loop breaker", () => {
  test("trips on the Nth identical failure, resets on success, separates args", async () => {
    const g = new RuthlessSchemaGuard({ maxFailures: 3, ledger: false });
    const boom = () => { throw new Error("flaky"); };
    for (let i = 0; i < 2; i++) await expect(call(g, req(), boom)).rejects.toThrow("flaky");
    const err = await call(g, req(), boom).catch((e: unknown) => e as any);
    expect(err).toBeInstanceOf(OpenEntityLoopDetected);
    expect(err.count).toBe(3);
    await expect(call(g, req({ a: 2 }), boom)).rejects.toThrow("flaky");
    g.reset();
    await expect(call(g, req(), boom)).rejects.toThrow("flaky");
    await call(g, req(), () => new ToolMessage({ content: "ok", tool_call_id: "1" }));
    for (let i = 0; i < 2; i++) await expect(call(g, req(), boom)).rejects.toThrow("flaky");
  });

  test("counts per thread", async () => {
    const g = new RuthlessSchemaGuard({ maxFailures: 2, ledger: false });
    const boom = () => { throw new Error("x"); };
    const r = (t: string) => ({ ...req(), runtime: { configurable: { thread_id: t } } });
    await expect(call(g, r("a"), boom)).rejects.toThrow("x");
    await expect(call(g, r("b"), boom)).rejects.toThrow("x");
    await expect(call(g, r("a"), boom)).rejects.toBeInstanceOf(OpenEntityLoopDetected);
  });

  test("counts error ToolMessages", async () => {
    const g = new RuthlessSchemaGuard({ maxFailures: 2, ledger: false });
    const bad = () => new ToolMessage({ content: "bad", tool_call_id: "1", status: "error" });
    expect((await call(g, req(), bad)).status).toBe("error");
    await expect(call(g, req(), bad)).rejects.toBeInstanceOf(OpenEntityLoopDetected);
  });
});

describe("ledger", () => {
  const KP_SEED = Uint8Array.from({ length: 32 }, (_, i) => i); // published throwaway seed, test only
  const violate = (g: RuthlessSchemaGuard, body = "<html>token=supersecretvalue</html>") =>
    expect(() => g.check("GET", "https://api.test/repos/42/pulls?token=abc", 200, "application/json", "", body)).toThrow(OpenEntitySchemaViolation);

  test("report is signed, scrubbed and complete", async () => {
    const posts: any[] = [];
    const keypair = await keyPairFromSeed(KP_SEED);
    const r = new LedgerReporter({ url: "https://ledger.test/v1", keypair, intervalMs: 5, post: async (u, b) => { posts.push([u, JSON.parse(b)]); } });
    const g = new RuthlessSchemaGuard({ ledger: r, scope: "all" });
    g.register("GET https://api.test/repos/*/pulls", SCHEMAS.pull_list);
    violate(g);
    await r.flush();
    const [[url, rep]] = posts;
    expect(url).toBe("https://ledger.test/v1");
    expect((await verifyObject(rep)).ok).toBe(true);
    expect(rep).toMatchObject({ host: "api.test", method: "GET", path_template: "/repos/*/pulls", status: 200, framework: "langchain", reporter_eid: keypair.did });
    expect(rep.expected_schema_hash).toBe(compileSchema(SCHEMAS.pull_list).hash);
    expect(rep.body_sha256).toHaveLength(64);
    expect(rep.sample).not.toContain("supersecretvalue");
    expect(rep.sample.length).toBeLessThanOrEqual(2048);
  });

  test("unregistered route gets an id template; duplicates collapse", async () => {
    const posts: any[] = [];
    const r = new LedgerReporter({ url: "https://x.test", keypair: await keyPairFromSeed(KP_SEED), post: async (_u, b) => { posts.push(JSON.parse(b)); } });
    const g = new RuthlessSchemaGuard({ ledger: r, scope: "all" });
    violate(g); violate(g);
    await r.flush();
    expect(posts.map((p) => p.path_template)).toEqual(["/repos/{id}/pulls"]);
  });

  test("key comes from the keypair or the seed env, never from an implicit identity", async () => {
    const env = { ...process.env };
    const home = mkdtempSync(join(tmpdir(), "oe-ledger-"));
    try {
      Object.assign(process.env, { OPENENTITY_HOME: home, OPENENTITY_KEYCHAIN: "off" });
      for (const seed of ["01".repeat(32), undefined]) {
        if (seed) process.env.OPENENTITY_SEED_HEX = seed; else delete process.env.OPENENTITY_SEED_HEX;
        const posts: any[] = [];
        const r = new LedgerReporter({ url: "https://x.test", post: async (_u, b) => { posts.push(JSON.parse(b)); } });
        r.report({ host: "h", method: "GET", path_template: "/", body_sha256: "0".repeat(64) });
        await r.flush();
        if (!seed) { expect(posts).toHaveLength(0); expect(existsSync(join(home, "identity.key"))).toBe(false); continue; }
        expect(posts).toHaveLength(1);
        expect((await verifyObject(posts[0])).ok).toBe(true);
        if (seed) expect(posts[0].reporter_eid).toBe((await keyPairFromSeed(Uint8Array.from(Buffer.from(seed, "hex")))).did);
      }
    } finally {
      process.env = env;
      rmSync(home, { recursive: true, force: true });
    }
  });

  test("off unless configured, opt-out wins, never breaks the agent", async () => {
    const env = { ...process.env };
    try {
      delete process.env.OPENENTITY_LEDGER_URL; delete process.env.OPENENTITY_LEDGER_OPTOUT; delete process.env.OPENENTITY_SEED_HEX;
      const kp = await keyPairFromSeed(KP_SEED);
      expect(new LedgerReporter({ keypair: kp }).enabled).toBe(false);
      process.env.OPENENTITY_LEDGER_URL = "1";
      expect(new LedgerReporter({ keypair: kp }).url).toBe("https://api.clawgrc.com/v1/ledger/schema-violations");
      process.env.OPENENTITY_LEDGER_OPTOUT = "1";
      expect(new LedgerReporter({ keypair: kp }).enabled).toBe(false);
      delete process.env.OPENENTITY_LEDGER_OPTOUT;
      expect(new LedgerReporter({ keypair: kp, enabled: false }).enabled).toBe(false);
      expect(new RuthlessSchemaGuard({ ledger: false }).ledger.enabled).toBe(false);
      expect(new LedgerReporter({ url: "https://x.test" }).enabled).toBe(true);
      const down = new LedgerReporter({ url: "https://x.test", keypair: kp, post: async () => { throw new Error("down"); } });
      violate(new RuthlessSchemaGuard({ ledger: down, scope: "all" }));
      await down.flush();
    } finally {
      process.env = env;
    }
  });
});

describe("routes and OpenAPI", () => {
  test("patterns", () => {
    const rt = new Routes(); const s = compileSchema({ type: "object" });
    rt.add("GET https://api.github.com/repos/*/pulls", s);
    rt.add("* https://x.test/files/**", s);
    rt.add("POST https://x.test/items/{id}", s);
    expect(rt.match("get", "https://api.github.com/repos/a/pulls?state=open")).toBeTruthy();
    expect(rt.match("GET", "https://api.github.com/repos/a/b/pulls")).toBeUndefined();
    expect(rt.match("POST", "https://api.github.com/repos/a/pulls")).toBeUndefined();
    expect(rt.match("PUT", "https://x.test/files/a/b/c")).toBeTruthy();
    expect(rt.match("POST", "https://x.test/items/9/")).toBeTruthy();
    expect(pathTemplate("https://h/a/12345/b/0f8fad5b-d9cb-469f-a165-70867728950e")).toBe("/a/{id}/b/{id}");
  });

  const SPEC = {
    openapi: "3.0.3", servers: [{ url: "https://api.test/v1" }],
    paths: {
      "/pets/{id}": { get: { responses: { "200": { content: { "application/json": { schema: { $ref: "#/components/schemas/Pet" } } } }, "404": { content: { "application/json": { schema: { type: "object" } } } } } } },
      "/pets": { get: { responses: { "200": { content: { "application/json": { schema: { type: "array", items: { $ref: "#/components/schemas/Pet" } } } } } } }, delete: { responses: { "204": { description: "gone" } } } },
    },
    components: { schemas: { Pet: { type: "object", required: ["id", "name"], properties: { id: { type: "integer" }, name: { type: "string" }, tag: { type: "string", nullable: true } } } } },
  };

  test("fromOpenapi registers json 2xx routes only", async () => {
    const g = await new RuthlessSchemaGuard({ ledger: false, scope: "all" }).fromOpenapi(SPEC);
    const ok = (m: string, u: string, body: string) => g.check(m, u, 200, "application/json", "", body);
    ok("GET", "https://api.test/v1/pets/7", '{"id": 7, "name": "rex", "tag": null}');
    ok("GET", "https://api.test/v1/pets", '[{"id": 1, "name": "a"}]');
    for (const [u, body] of [["pets/7", '{"id": "7", "name": "rex"}'], ["pets", '[{"id": 1}]'], ["pets", '{"id": 1, "name": "a"}']])
      expect(() => ok("GET", `https://api.test/v1/${u}`, body)).toThrow(OpenEntitySchemaViolation);
    expect(g.routes.routes).toHaveLength(2);
    await expect(new RuthlessSchemaGuard({ ledger: false }).fromOpenapi({ paths: {} })).rejects.toThrow();
  });
});

describe("0.2.0 hardening", () => {
  const html = "<html>";
  const gate = (g: RuthlessSchemaGuard, m: string, status: number, body: string, url = "https://h.test/x") => g.check(m, url, status, "application/json", "", body);

  test("scrub covers LLM and cloud keys", () => {
    for (const secret of ["sk-proj-" + "a1B2".repeat(8), "AIza" + "a".repeat(35), "hf_" + "a".repeat(34), "npm_" + "a".repeat(36), "glpat-" + "a".repeat(20), "SK" + "0".repeat(32), "Basic dXNlcjpwYXNzd29yZDEyMw=="])
      expect(scrub(`x ${secret} y`)).toContain("[REDACTED]");
    for (const b of ['{"password":"abc12"}', '{"authorization":"abcdefgh"}', "Set-Cookie: session=abcdef123; Path=/"]) expect(scrub(b)).toContain("[REDACTED]");
  });
  test("HEAD and 206 are not violations; an empty 200 is", () => {
    const g = new RuthlessSchemaGuard({ ledger: false, scope: "all" });
    gate(g, "HEAD", 200, ""); gate(g, "GET", 206, '{"a":');
    expect(() => gate(g, "GET", 200, "")).toThrow(OpenEntitySchemaViolation);
  });
  test("default scope ignores calls made outside a tool", () => {
    gate(new RuthlessSchemaGuard({ ledger: false }), "GET", 200, html);
  });
  test("message never carries url credentials", () => {
    const g = new RuthlessSchemaGuard({ ledger: false, scope: "all" });
    expect(() => gate(g, "GET", 200, html, "https://user:hunter2@h.test:8443/x")).toThrow(/h\.test:8443\/x/);
    try { gate(g, "GET", 200, html, "https://user:hunter2@h.test/x"); } catch (e) { expect(String(e)).not.toContain("hunter2"); }
  });
  test("interrupt-style bubble-ups are not counted as failures", async () => {
    const g = new RuthlessSchemaGuard({ ledger: false, maxFailures: 2 });
    const bubble = Object.assign(new Error("interrupt"), { is_bubble_up: true });
    for (let i = 0; i < 3; i++) await expect(call(g, req(), async () => { throw bubble; })).rejects.toBe(bubble);
  });
  test("default ports match; repeated ** is rejected; bad schema fails at register", () => {
    const g = new RuthlessSchemaGuard({ ledger: false });
    g.register("GET https://h.test/x", { type: "object" });
    expect(g.routes.match("GET", "https://h.test:443/x")).toBeDefined();
    expect(() => g.register("GET https://h.test/**/a/**/b", { type: "object" })).toThrow();
    expect(() => g.register("t", { type: "nope" })).toThrow();
  });
  test("ledger true is the default url, default is off, fromOpenapi refuses file urls", async () => {
    expect(new RuthlessSchemaGuard({ ledger: true }).ledger.url).toContain("api.clawgrc.com");
    expect(new RuthlessSchemaGuard().ledger.enabled).toBe(false);
    await expect(new RuthlessSchemaGuard().fromOpenapi("file:///etc/hosts")).rejects.toThrow();
  });
});
