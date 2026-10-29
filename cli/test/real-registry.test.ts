import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { run } from "../src/main";
import { resolveSigner } from "../src/wallet";
import { startReal, type Real } from "./real-registry";

// Published throwaway wallet key: it controls nothing and exists only for these tests.
const KEY = "0x" + "11".repeat(32);
const STRANGER = "0x" + "22".repeat(20);
const REGISTRY_8004 = "0x8004a169fb4a3325136eb29fa0ceb6d2e539a432";

let real: Real;
let home: string;
beforeAll(async () => {
  real = await startReal();
});
afterAll(() => real.close());
beforeEach(async () => {
  home = await mkdtemp(join(tmpdir(), "oe-real-"));
  process.env.OPENENTITY_HOME = home;
  delete process.env.OPENENTITY_WALLET_KEY;
  real.tamper.request = real.tamper.response = undefined;
  real.owner.address = (await resolveSigner(KEY))!.address;
});
afterEach(() => rm(home, { recursive: true, force: true }));

async function cli(...args: string[]) {
  let out = "";
  let err = "";
  const code = await run(args, { out: (s) => void (out += s), err: (s) => void (err += s) });
  return { code, out, err };
}
const adopt = (...extra: string[]) => cli("adopt", "--name", "Wallet Test", "--agree", "--registry", real.url, "--json", ...extra);
const level = async (eid: string) => (await (await fetch(`${real.url}/v1/entities/${eid}`)).json() as any).level;

describe("adopt --wallet --erc8004 lands at L1 in one command (PRD 7.2)", () => {
  it("a hex key proves the wallet and the ERC-8004 agent against a mocked Base RPC", async () => {
    const r = await adopt("--wallet", KEY, "--erc8004", `eip155:8453:${REGISTRY_8004}:42`);
    expect(r.err).toBe("");
    expect(r.code).toBe(0);
    const out = JSON.parse(r.out);
    expect(out.level).toBe("L1");
    expect(await level(out.eid)).toBe("L1");
    const aliases = (await (await fetch(`${real.url}/v1/entities/${out.eid}`)).json() as any).aliases;
    expect(aliases.map((a: any) => a.type).sort()).toEqual(["erc8004", "wallet"]);
  });

  it("a key file and OPENENTITY_WALLET_KEY work the same", async () => {
    const file = join(home, "wallet.key");
    await writeFile(file, KEY + "\n", { mode: 0o600 });
    const a = JSON.parse((await adopt("--wallet", file)).out);
    expect(a.level).toBe("L1");
    process.env.OPENENTITY_WALLET_KEY = KEY;
    const b = JSON.parse((await adopt("--erc8004", `eip155:8453:${REGISTRY_8004}:7`)).out);
    expect(b.level).toBe("L1");
  });

  it("fails loud when the wallet is not the ERC-8004 owner, and says what to retry", async () => {
    real.owner.address = STRANGER;
    const r = await adopt("--wallet", KEY, "--erc8004", `eip155:8453:${REGISTRY_8004}:9`);
    expect(r.code).not.toBe(0);
    expect(r.err).toMatch(/erc8004 proof failed/);
  });

  it("a bare address is declared only: the entity stays L0 (guard: the proof step is what raises the level)", async () => {
    const r = await adopt("--wallet", "0x" + "33".repeat(20));
    expect(JSON.parse(r.out).level).toBe("L0");
  });

  it("alias add wallet|erc8004 --wallet signs locally", async () => {
    const eid = JSON.parse((await adopt()).out).eid;
    expect(await level(eid)).toBe("L0");
    expect((await cli("alias", "add", "wallet", "--wallet", KEY, "--registry", real.url)).code).toBe(0);
    expect(await level(eid)).toBe("L1");
    expect((await cli("alias", "add", "erc8004", `eip155:8453:${REGISTRY_8004}:5`, "--wallet", KEY, "--registry", real.url)).code).toBe(0);
  });

  it("rejects a value that is neither a key, an address nor a readable file", async () => {
    expect((await adopt("--wallet", join(home, "missing"))).code).not.toBe(0);
  });
});

describe("log audit against a registry that is not openentity.org", () => {
  it("verifies the registry's own document with the key /v1/spec publishes (guard: no lookup of did:web:openentity.org)", async () => {
    await fetch(`${real.url}/v1/entities/did:web:openentity.org/document`); // the registry logs its own document on first read
    await adopt();
    await new Promise((r) => setTimeout(r, 700));
    const rnd = vi.spyOn(Math, "random").mockReturnValue(0); // always leaf 0
    const r = await cli("log", "audit", "1", "--registry", real.url, "--json");
    rnd.mockRestore();
    const checks = JSON.parse(r.out).checks as { name: string; ok: boolean }[];
    expect(checks.find((c) => c.name === "signature did:web:openentity.org")?.ok).toBe(true);
    expect(r.code).toBe(0);
  });
});

describe("verify <eid> proves every record entry is in the log", () => {
  it("passes, then fails when an entry's log index points at another leaf (guard: leaf must cover the entry hash)", async () => {
    const a = JSON.parse((await adopt()).out);
    await new Promise((r) => setTimeout(r, 700)); // the cron incorporates every 200ms
    const ok = await cli("verify", a.eid, "--registry", real.url);
    expect(ok.out).toMatch(/ok\s+record inclusion \(\d+ entries\)/);
    expect(ok.code).toBe(0);
    real.tamper.response = async (req, res) =>
      new URL(req.url).pathname.endsWith("/record") ? Response.json({ ...(await res.json()), log_indexes: [0] }) : res;
    const bad = await cli("verify", a.eid, "--registry", real.url);
    expect(bad.out).toMatch(/FAIL record inclusion/);
    expect(bad.code).toBe(3);
  });
});

describe("withdraw after continuity (spec 9.3)", () => {
  it.each(["rotate", "migrate"])("%s then withdraw: the successor withdraws the inherited Declaration, the predecessor stays active", async (cmd) => {
    const a = JSON.parse((await adopt()).out);
    const c = await cli(cmd, "--registry", real.url, "--json");
    expect(c.err).toBe("");
    expect(c.code).toBe(0);
    const next = JSON.parse(c.out).successor as string;
    const got = (await (await fetch(`${real.url}/v1/entities/${next}`)).json()) as any;
    expect(got.declaration).not.toBeNull();
    expect(got.declaration_inherited_from).toBe(a.eid);
    const w = await cli("withdraw", "--force", "--registry", real.url, "--json");
    expect(w.err).toBe("");
    expect(w.code).toBe(0);
    expect(((await (await fetch(`${real.url}/v1/entities/${next}`)).json()) as any).withdrawn).toBe(true);
    expect(((await (await fetch(`${real.url}/v1/entities/${a.eid}`)).json()) as any).withdrawn).toBe(false);
  });
});

describe("conformance against the real registry app", () => {
  const conf = async () => {
    const r = await cli("conformance", real.url, "--json");
    return { code: r.code, failed: (JSON.parse(r.out).checks as any[]).filter((c) => !c.ok).map((c) => c.name as string) };
  };
  beforeEach(async () => {
    // A few entities so the log has leaves to prove.
    for (let i = 0; i < 3; i++) await adopt();
    await new Promise((r) => setTimeout(r, 700));
  });

  it("passes the unbroken registry", async () => {
    expect(await conf()).toEqual({ code: 0, failed: [] });
  });

  it("passes the write-path checks and withdraws what it made", async () => {
    const r = await cli("conformance", real.url, "--writes", "--json");
    const j = JSON.parse(r.out);
    expect(j.checks.filter((c: any) => !c.ok)).toEqual([]);
    expect(r.code).toBe(0);
    expect(j.created).toBeGreaterThan(0);
  });

  it("fails when the stamp guard is removed (stampless writes reach the handler)", async () => {
    real.tamper.request = (req) => {
      if (req.method !== "POST" || req.headers.has("x-oe-stamp")) return req;
      const h = new Headers(req.headers);
      h.set("x-oe-stamp", "x");
      return new Request(req.url, { method: "POST", headers: h, body: "{}" });
    };
    const r = await conf();
    expect(r.code).toBe(3);
    expect(r.failed).toContain("no Turnstile on agent endpoints");
  });

  it("fails when the log tiles stop matching the leaves", async () => {
    real.tamper.response = async (req, res) => {
      if (!new URL(req.url).pathname.includes("/log/tile/0/")) return res;
      const b = Buffer.from(await res.arrayBuffer());
      b[0] ^= 1;
      return new Response(b, { status: res.status, headers: res.headers });
    };
    const r = await conf();
    expect(r.code).toBe(3);
    expect(r.failed).toContain("tiles match leaves");
  });
});
