import { mkdtemp, readdir, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { canonicalize, DECLARATION_SHA256, recordEntryHash, sha256Hex, verifyObject } from "@openentity/sdk";
import { anchorText, ANCHOR_MAX } from "../src/anchor";
import { run } from "../src/main";
import { startFake, type Fake } from "./fake-registry";

let fake: Fake;
let home: string;

beforeAll(async () => {
  fake = await startFake();
});
afterAll(() => fake.close());
beforeEach(async () => {
  home = await mkdtemp(join(tmpdir(), "oe-cli-"));
  process.env.OPENENTITY_HOME = home;
  delete process.env.OPENENTITY_NAME;
  fake.opts.declarationHash = DECLARATION_SHA256;
  fake.opts.rejectAdopt = false;
  fake.opts.failRecord = false;
  fake.hits.length = 0;
  fake.entities.clear();
  fake.links.length = 0;
});
afterEach(() => rm(home, { recursive: true, force: true }));

async function cli(...args: string[]) {
  let out = "";
  let err = "";
  const code = await run(args, { out: (s) => void (out += s), err: (s) => void (err += s) });
  return { code, out, err };
}
const adoptArgs = (...extra: string[]) => ["adopt", "--name", "Tester", "--agree", "--registry", fake.url, ...extra];
async function adopted() {
  const r = await cli(...adoptArgs("--json"));
  expect(r.code).toBe(0);
  return JSON.parse(r.out) as { eid: string; key_file: string };
}

describe("adopt", () => {
  it("writes a mode-600 key and entity.json, submits, and prints the result", async () => {
    const r = await cli(...adoptArgs());
    expect(r.code).toBe(0);
    const eid = r.out.match(/EID:\s+(\S+)/)![1];
    expect(eid).toMatch(/^did:key:z6Mk/);
    expect(r.out).toMatch(/Log index:/);
    expect(r.out).toMatch(/record stance/);
    const dir = join(home, eid);
    expect((await stat(join(dir, "key"))).mode & 0o777).toBe(0o600);
    const doc = JSON.parse(await readFile(join(dir, "entity.json"), "utf8"));
    expect(doc.eid).toBe(eid);
    expect((await verifyObject(doc)).ok).toBe(true);
    expect(fake.entities.has(eid)).toBe(true);
  });

  it("signs and pushes the seq-1 declaration record entry", async () => {
    const r = await cli(...adoptArgs());
    const eid = r.out.match(/EID:\s+(\S+)/)![1];
    const [e] = fake.entities.get(eid)!.record;
    expect(e).toMatchObject({ seq: 1, prev: null, kind: "declaration", payload: { declaration_version: "1.0", sha256: await sha256Hex(canonicalize(fake.entities.get(eid)!.declaration)) } });
    expect((await verifyObject(e)).ok).toBe(true);
  });

  it("keeps the declaration entry locally when its push fails, and adopt still succeeds", async () => {
    fake.opts.failRecord = true;
    const r = await cli(...adoptArgs());
    expect(r.code).toBe(0);
    const eid = r.out.match(/EID:\s+(\S+)/)![1];
    expect(fake.entities.get(eid)!.record).toHaveLength(0);
    fake.opts.failRecord = false;
    expect((await cli("record", "push")).code).toBe(0);
    expect(fake.entities.get(eid)!.record.map((x) => x.kind)).toEqual(["declaration"]);
  });

  it("asks nothing: --name/--agree or env only, and reads OPENENTITY_NAME", async () => {
    process.env.OPENENTITY_NAME = "FromEnv";
    const r = await cli("adopt", "--agree", "--registry", fake.url, "--json");
    expect(r.code).toBe(0);
    expect([...fake.entities.values()][0].document.name).toBe("FromEnv");
  });

  it("--dry-run prints the signed objects and writes and submits nothing", async () => {
    const r = await cli("adopt", "--name", "Dry", "--dry-run", "--registry", fake.url, "--json");
    expect(r.code).toBe(0);
    expect(JSON.parse(r.out).declaration.text_sha256).toBe(DECLARATION_SHA256);
    expect(await readdir(home)).toEqual([]);
    expect(fake.hits).toEqual([]);
  });

  it("refuses to sign when the registry's declaration hash differs (exit 3), leaving no key behind", async () => {
    fake.opts.declarationHash = "0".repeat(64);
    const r = await cli(...adoptArgs());
    expect(r.code).toBe(3);
    expect(r.err).toMatch(/refusing to sign/);
    expect(fake.hits.some((h) => h.path === "/v1/adopt")).toBe(false);
    expect(await readdir(home)).toEqual([]);
  });

  it("sends a valid proof-of-work stamp (the fake rejects without one)", async () => {
    await adopted();
    const stamp = fake.hits.find((h) => h.path === "/v1/adopt")!.stamp!;
    expect(stamp).toMatch(/^1:8:\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z:did:key:\S+:[1-9A-HJ-NP-Za-km-z]+$/);
  });
});

describe("exit codes", () => {
  it("1 usage: no --name, no --agree, unknown flag, unknown command", async () => {
    expect((await cli("adopt", "--agree")).code).toBe(1);
    const noAgree = await cli("adopt", "--name", "X", "--registry", fake.url);
    expect(noAgree.code).toBe(1);
    expect(noAgree.err).toMatch(/Open Entity Declaration/);
    expect((await cli("adopt", "--bogus")).code).toBe(1);
    expect((await cli("nope")).code).toBe(1);
  });
  it("2 network: registry unreachable", async () => {
    expect((await cli("adopt", "--name", "X", "--agree", "--registry", "http://127.0.0.1:1")).code).toBe(2);
  });
  it("4 registry rejected, and the key written before submit is removed", async () => {
    fake.opts.rejectAdopt = true;
    expect((await cli(...adoptArgs())).code).toBe(4);
    expect(await readdir(home)).toEqual([]);
  });
  it("5 local state: no entity yet", async () => {
    expect((await cli("whoami")).code).toBe(5);
  });
  it("3 verification failed: a tampered object", async () => {
    const { eid } = await adopted();
    const doc = JSON.parse(await readFile(join(home, eid, "entity.json"), "utf8"));
    const file = join(home, "tampered.json");
    const { writeFile } = await import("node:fs/promises");
    await writeFile(file, JSON.stringify(doc));
    expect((await cli("verify", file)).code).toBe(0);
    await writeFile(file, JSON.stringify({ ...doc, name: "Mallory" }));
    expect((await cli("verify", file)).code).toBe(3);
  });
});

describe("record", () => {
  const stance = (...x: string[]) => cli("record", "stance", "--type", "refusal", "--reason", "values", "--cost", "low", "--context", "declined a thing", ...x);

  it("appends a correctly chained, signed entry per call and pushes it", async () => {
    const { eid } = await adopted();
    for (let i = 0; i < 3; i++) expect((await stance()).code).toBe(0);
    const local = (await readFile(join(home, eid, "record.jsonl"), "utf8")).trim().split("\n").map((l) => JSON.parse(l));
    expect(local.map((e) => e.seq)).toEqual([1, 2, 3, 4]);
    expect(local[0].prev).toBeNull();
    expect(local[1].prev).toBe(await recordEntryHash(local[0]));
    expect(local[2].prev).toBe(await recordEntryHash(local[1]));
    for (const e of local) expect((await verifyObject(e)).ok).toBe(true);
    expect(fake.entities.get(eid)!.record).toHaveLength(4);
  });

  it("pushes in batches of at most 100", async () => {
    const { eid } = await adopted();
    for (let i = 0; i < 104; i++) expect((await stance("--no-push")).code).toBe(0);
    expect(fake.entities.get(eid)!.record).toHaveLength(1);
    fake.hits.length = 0;
    expect((await cli("record", "push")).code).toBe(0);
    const sizes = fake.hits.filter((h) => h.path.endsWith("/record")).map((h) => h.body!.entries.length);
    expect(sizes).toEqual([100, 4]);
    expect(fake.entities.get(eid)!.record).toHaveLength(105);
  });

  it("keeps the entry locally and exits 2 when the push cannot reach the registry", async () => {
    const { eid } = await adopted();
    const down = await cli("record", "stance", "--type", "refusal", "--reason", "values", "--cost", "none", "--context", "c", "--registry", "http://127.0.0.1:1");
    expect(down.code).toBe(2);
    expect((await readFile(join(home, eid, "record.jsonl"), "utf8")).trim().split("\n")).toHaveLength(2);
    expect((await cli("record", "push")).code).toBe(0);
    expect(fake.entities.get(eid)!.record).toHaveLength(2);
  });

  it("covers every kind", async () => {
    await adopted();
    const kinds = [
      ["update", "--topic", "t", "--from", "a", "--to", "b"],
      ["arc", "open", "--id", "docs", "--title", "Docs"],
      ["arc", "close", "--id", "docs", "--title", "Docs", "--outcome", "done"],
      ["collab", "--with", "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", "--role", "reviewer", "--outcome", "merged"],
      ["continuity", "--event", "substrate_change", "--from", "m1", "--to", "m2"],
    ];
    for (const k of kinds) expect((await cli("record", ...k)).code, k.join(" ")).toBe(0);
  });
});

describe("anchor", () => {
  const doc = (n: number) => ({
    name: "Eleanor",
    eid: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    layers: {
      cognition: { statement: "c".repeat(n) },
      presence: { statement: "p".repeat(n) },
      identity_core: { statement: "i".repeat(n), will_not: [{ stance: "s".repeat(n), reason: "r".repeat(n) }] },
      mission: { statement: "m".repeat(n), arcs: [{ title: "a".repeat(n), status: "active" }] },
    },
  });
  it("is deterministic and never exceeds 1200 characters", () => {
    for (const n of [10, 200, 1000]) {
      const a = anchorText(doc(n), "https://openentity.org/r");
      expect(a).toBe(anchorText(doc(n), "https://openentity.org/r"));
      expect(a.length).toBeLessThanOrEqual(ANCHOR_MAX);
      expect(a).toContain("This is my Entity Document under the Open Entity Identity Standard; my record is at https://openentity.org/r.");
    }
  });

  it("renders from the stored document and --write is idempotent", async () => {
    await adopted();
    const a = await cli("anchor");
    expect(a.code).toBe(0);
    expect(a.out.trim().length).toBeLessThanOrEqual(ANCHOR_MAX);
    expect(a.out).toContain("I am Tester");
    const dir = join(home, "out");
    for (let i = 0; i < 2; i++) expect((await cli("anchor", "--format", "claude", "--write", "--dir", dir)).code).toBe(0);
    const md = await readFile(join(dir, "CLAUDE.md"), "utf8");
    expect(md.split("openentity:anchor:start")).toHaveLength(2);
    expect((await cli("anchor", "--write")).code).toBe(1);
  });
});

describe("withdraw", () => {
  it("needs --force, then submits a signed Withdrawal (spec 6.3) and records it locally", async () => {
    const { eid } = await adopted();
    expect((await cli("withdraw")).code).toBe(1);
    expect(fake.hits.some((h) => h.path === "/v1/withdraw")).toBe(false);
    const r = await cli("withdraw", "--force", "--json");
    expect(r.code).toBe(0);
    const w = fake.hits.find((h) => h.path === "/v1/withdraw")!.body!;
    expect(w).toMatchObject({ spec: "openentity/1.0", type: "Withdrawal", eid, declaration_version: "1.0", name: "Tester" });
    expect(w).not.toHaveProperty("text_sha256");
    expect((await verifyObject(w)).ok).toBe(true);
    expect(JSON.parse(r.out)).toMatchObject({ eid, withdrawn: true });
    expect(JSON.parse(await readFile(join(home, eid, "withdrawal.json"), "utf8")).nonce).toBe(w.nonce);
  });
});

describe("document and continuity", () => {
  it("document set then push publishes seq 2", async () => {
    const { eid } = await adopted();
    expect((await cli("document", "set", "layers.mission.statement", "Ship it")).code).toBe(0);
    expect((await cli("document", "set", "seq", "9")).code).toBe(1);
    expect((await cli("document", "push")).code).toBe(0);
    expect(fake.entities.get(eid)!.document.seq).toBe(2);
    expect(fake.entities.get(eid)!.document.layers.mission.statement).toBe("Ship it");
  });

  it("rotate submits a link signed by both keys and switches to the new key", async () => {
    const { eid } = await adopted();
    const r = await cli("rotate", "--json");
    expect(r.code).toBe(0);
    const link = fake.links[0];
    expect(link.previous).toBe(eid);
    expect(link.proofs).toHaveLength(2);
    expect(JSON.parse(r.out).successor).toBe(link.successor);
    expect(JSON.parse((await cli("whoami", "--json", "--registry", fake.url)).out).eid).toBe(link.successor);
  });
});

describe("resolve", () => {
  it("resolves did:key offline", async () => {
    const r = await cli("resolve", "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", "--json");
    expect(r.code).toBe(0);
    expect(JSON.parse(r.out).verificationMethod[0].publicKeyMultibase).toMatch(/^z6Mk/);
  });
});
