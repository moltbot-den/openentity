import { describe, it, expect, afterAll } from "vitest";
import { existsSync, mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as oe from "../src/index.ts";
import { Identity, identityFile } from "../src/node.ts";

const home = mkdtempSync(join(tmpdir(), "oe-id-"));
process.env.OPENENTITY_HOME = home;
process.env.OPENENTITY_KEYCHAIN = "off";
afterAll(() => rmSync(home, { recursive: true, force: true }));

describe("Identity.loadOrCreate", () => {
  it("falls back to ~/.openentity/identity.key at 0600 and returns the same key next time", async () => {
    const a = await Identity.loadOrCreate();
    expect(a.source).toBe("file");
    expect(statSync(identityFile()).mode & 0o777).toBe(0o600);
    expect(statSync(home).mode & 0o777).toBe(0o700);
    const b = await Identity.loadOrCreate();
    expect([b.did, b.source]).toEqual([a.did, "file"]);
    expect(b.seed).toEqual(a.seed);
  });
});

describe("Identity.load", () => {
  it("never creates a key, so a read-only caller cannot mint an identity", async () => {
    const empty = mkdtempSync(join(tmpdir(), "oe-id-empty-"));
    process.env.OPENENTITY_HOME = empty;
    try {
      expect(await Identity.load()).toBeNull();
      expect(existsSync(identityFile())).toBe(false);
    } finally {
      process.env.OPENENTITY_HOME = home;
      rmSync(empty, { recursive: true, force: true });
    }
    const a = await Identity.loadOrCreate();
    expect((await Identity.load())!.did).toBe(a.did);
  });
});

describe("adopt with a client label", () => {
  it("sends the unsigned label beside the signed objects, and rejects one off the allowlist", async () => {
    const kp = await oe.generateKeyPair();
    const bodies: any[] = [];
    const real = globalThis.fetch;
    globalThis.fetch = (async (url: string, init?: RequestInit) => {
      const path = new URL(url).pathname;
      if (init?.body) bodies.push({ path, body: JSON.parse(init.body as string), stamp: (init.headers as any)["x-oe-stamp"] });
      return new Response(JSON.stringify(path === "/v1/spec" ? { stamp_bits: 4 } : { eid: kp.did, level: "L0" }), { status: 200 });
    }) as typeof fetch;
    try {
      const r = await oe.adopt(kp, { name: "T", registry: "https://reg.test", client: "adk" });
      const [adopt, record] = bodies;
      expect(adopt.path).toBe("/v1/adopt");
      expect(adopt.body.client).toBe("adk");
      expect(oe.validate("EntityDocument", adopt.body.document).ok && oe.validate("Declaration", adopt.body.declaration).ok).toBe(true);
      expect(await oe.checkStamp(adopt.stamp, 4, kp.did)).toBeNull();
      expect(record.body.entries[0].payload.sha256).toBe(await oe.sha256Hex(oe.canonicalize(adopt.body.declaration)));
      expect(r.recordPushed).toBe(true);
      await expect(oe.adopt(kp, { name: "T", registry: "https://reg.test", client: "nope" as any })).rejects.toThrow();
    } finally {
      globalThis.fetch = real;
    }
  });
});
