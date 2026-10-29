// The shared corpus (../fixtures): every malformed response must throw, no valid one may.
import { afterAll, beforeAll, describe, expect, test } from "vitest";
import { OpenEntitySchemaViolation, RuthlessSchemaGuard, inspectResponse, scrub } from "../src/index.ts";
import { compileSchema } from "../src/core.ts";
import { MALFORMED, SCHEMAS, VALID, VECTORS, serve, type Case } from "./fixtures.ts";

const compiled = Object.fromEntries(Object.entries(SCHEMAS).map(([k, v]) => [k, compileSchema(v)]));
const guard = () => {
  const g = new RuthlessSchemaGuard({ ledger: false, scope: "all" });
  for (const [n, s] of Object.entries(SCHEMAS)) g.register(`GET https://corpus.test/${n}`, s);
  return g;
};
const run = (g: RuthlessSchemaGuard, c: Case) => g.check("GET", `https://corpus.test/${c.schema ?? "free"}`, c.status, c.content_type, c.accept, c.body);

test("corpus is big enough", () => {
  expect(MALFORMED.length).toBeGreaterThanOrEqual(200);
  expect(VALID.length).toBeGreaterThanOrEqual(200);
});

describe("malformed", () => {
  test.each(MALFORMED)("$id", (c) => {
    const errs = inspectResponse(c.status, c.content_type, c.body, { schema: compiled[c.schema ?? ""], accept: c.accept });
    expect(errs[0]?.split(":")[0]).toBe(c.rule);
    let thrown: unknown;
    try { run(guard(), c); } catch (e) { thrown = e; }
    expect(thrown).toBeInstanceOf(OpenEntitySchemaViolation);
    expect((thrown as OpenEntitySchemaViolation).rule).toBe(c.rule);
    expect((thrown as OpenEntitySchemaViolation).rawExcerpt.length).toBeLessThanOrEqual(500);
  });
});

describe("valid", () => {
  test.each(VALID)("$id", (c) => {
    expect(inspectResponse(c.status, c.content_type, c.body, { schema: compiled[c.schema ?? ""], accept: c.accept })).toEqual([]);
    run(guard(), c);
  });
});

test("scrub and schema hashes agree with the Python package", () => {
  for (const v of VECTORS.scrub) expect(scrub(v.in.join(""))).toBe(v.out);
  expect(Object.fromEntries(Object.entries(compiled).map(([k, s]) => [k, s.hash]))).toEqual(VECTORS.schema_hash);
});

describe("global fetch", () => {
  let base = "", close = () => {}, off = () => {};
  beforeAll(async () => {
    const s = await serve();
    base = s.base;
    close = () => s.server.close();
    const g = new RuthlessSchemaGuard({ ledger: false, scope: "all" });
    for (const [n, sc] of Object.entries(SCHEMAS)) g.register(`GET ${base}/s/${n}/*`, sc);
    off = g.guardHttp();
  });
  afterAll(() => { off(); close(); });

  test("every case through fetch", async () => {
    const failures: string[] = [];
    for (const [cases, bad] of [[MALFORMED, true], [VALID, false]] as const)
      for (const c of cases) {
        let raised = false;
        try {
          const r = await fetch(`${base}/s/${c.schema ?? "free"}/${c.id}`, { headers: c.accept ? { accept: c.accept } : {} });
          await r.arrayBuffer().catch(() => {});
        } catch (e) {
          if (!(e instanceof OpenEntitySchemaViolation)) throw e;
          raised = true;
        }
        if (raised !== bad) failures.push(c.id);
      }
    expect(failures).toEqual([]);
  }, 30_000); // one local fetch per corpus case; the default 5s fails on a loaded machine

  test("the caller can still read the body of a valid response", async () => {
    const c = VALID.find((x) => x.id === "v-repo-0-compact")!;
    expect(await (await fetch(`${base}/s/repo/${c.id}`)).text()).toBe(c.body);
  });

  test("uninstall restores fetch", async () => {
    off();
    const c = MALFORMED.find((x) => x.id === "m-html-0-ctjson")!;
    expect((await fetch(`${base}/s/free/${c.id}`)).status).toBe(200);
  });
});
