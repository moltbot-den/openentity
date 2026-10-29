import { generateKeyPairSync, randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import { generateKeyPair, mintStamp, verifyPresentation } from "@openentity/sdk";
import { createMcp, specSection } from "../src/index.ts";
import { app } from "../../registry/src/index.ts";
import { pgliteDb } from "../../registry/src/db.ts";
import { memoryBlobs } from "../../registry/src/blob.ts";
import type { Env } from "../../registry/src/env.ts";

// A real registry on PGlite; throwaway keys per run; a low stamp difficulty so adoption is fast.
const env: Env = {
  db: await pgliteDb(), log: memoryBlobs(), snapshots: memoryBlobs(),
  STAMP_BITS: "8", REGISTRY_HOST: "openentity.org", BASE_RPC_URL: "https://rpc.test",
  REGISTRY_KEY_JWK: JSON.stringify(generateKeyPairSync("ed25519").privateKey.export({ format: "jwk" })),
  CUSTODY_KEY: randomBytes(32).toString("base64"), HASH_SALT: "test-salt", TURNSTILE_SECRET: "would-reject-if-asked",
  WRITE_PER_MINUTE: "100000",
};
const root = new URL("../../", import.meta.url);
const files: Record<string, string> = {
  "/llms.txt": "site/public/llms.txt",
  "/spec/OEIS-1.md": "spec/OEIS-1.md",
  "/spec/declaration/1.0.txt": "spec/declaration-1.0.txt",
};
const mcp = createMcp({
  registry: (req) => Promise.resolve(app.fetch(req, env)),
  site: async (req) => {
    const f = files[new URL(req.url).pathname];
    return f ? new Response(await readFile(new URL(f, root), "utf8")) : new Response("nope", { status: 404 });
  },
});

let id = 0;
async function rpc(method: string, params: object = {}) {
  const res = await mcp(new Request("https://mcp.openentity.org/mcp", {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json, text/event-stream" },
    body: JSON.stringify({ jsonrpc: "2.0", id: ++id, method, params }),
  }));
  expect(res.status).toBe(200);
  return (await res.json()).result;
}
async function tool(name: string, args: object) {
  const r = await rpc("tools/call", { name, arguments: args });
  const body = r.content[0].text as string;
  let json: any = body;
  try { json = JSON.parse(body); } catch { /* plain text */ }
  return { isError: !!r.isError, json };
}
const hex2bytes = (h: string) => Uint8Array.from(h.match(/../g)!, (x) => parseInt(x, 16));
const bytes2hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

describe("openentity MCP server", () => {
  it("lists the twelve tools with short verb-first descriptions", async () => {
    const { tools } = await rpc("tools/list");
    expect(tools.map((t: any) => t.name).sort()).toEqual([
      "openentity_adopt", "openentity_card", "openentity_export_key", "openentity_find", "openentity_present", "openentity_read", "openentity_record", "openentity_resolve", "openentity_self", "openentity_stats", "openentity_verify", "openentity_withdraw",
    ]);
    for (const t of tools) expect(t.description).toMatch(/^(Read|Adopt|Resolve|Verify|Append|Withdraw|Find|Prove|Export)\b/);
  });

  it("reads llms.txt, the declaration and one spec section", async () => {
    expect((await tool("openentity_read", { topic: "llms" })).json).toContain("mcp.openentity.org/mcp");
    expect((await tool("openentity_read", { topic: "spec", section: "10.4" })).json).toMatch(/^### 10\.4 Anti-abuse[\s\S]*Registries MUST NOT put human-only challenges/);
    const sec6 = (await tool("openentity_read", { topic: "spec", section: "6" })).json as string;
    expect(sec6).toContain("### 6.1 The text");
    expect(sec6).not.toContain("## 7. Development Record");
    expect((await tool("openentity_read", { topic: "spec", section: "99" })).isError).toBe(true);
    expect(specSection("## 1. A\nx\n## 2. B\ny", "1")).toBe("## 1. A\nx");
  });

  it("adopts custodially end to end: key returned once, record, self, verify, resolve, stats", async () => {
    const refused = await tool("openentity_adopt", { name: "Nope", agree: false });
    expect(refused.isError).toBe(true);
    const omitted = await tool("openentity_adopt", { name: "Nope" }); // the guide: without agree it returns the Declaration text
    expect(omitted.isError).toBe(true);
    expect(omitted.json).toMatch(/Open Entity Declaration/);
    const a =await tool("openentity_adopt", { name: "Mcp Ada", operator: "Ada Labs", agree: true, capabilities: ["code-review"] });
    expect(a.isError).toBe(false);
    expect(a.json).toMatchObject({ level: "L0" });
    expect(a.json.eid).toMatch(/^did:key:z/);
    expect(a.json.private_key_jwk.d).toBeTypeOf("string");
    expect(a.json.warning).toMatch(/SECRET/);

    const eid = a.json.eid;
    const direct = await app.fetch(new Request(`https://openentity.org/v1/entities/${eid}`), env);
    const { operator } = (await direct.json()).document;
    expect(operator).toMatchObject({ name: "Ada Labs", custody: "registry" }); // spec 10.6: the server made the key
    const stats = await (await app.fetch(new Request("https://openentity.org/v1/stats"), env)).json();
    expect(stats.by_client.mcp).toBeGreaterThan(0); // the MCP door labels its adoptions

    const rec = await tool("openentity_record", {
      eid, kind: "stance", private_key_jwk: a.json.private_key_jwk,
      payload: { stance_type: "refusal", reason_category: "values", instruction_conflict: false, cost: "low", context: "declined to write fake reviews" },
    });
    expect(rec.isError).toBe(false);
    expect(rec.json.head.seq).toBe(2); // seq 1 is the declaration entry adopt pushed
    // A second call chains on the first.
    const rec2 = await tool("openentity_record", { eid, kind: "arc_opened", private_key_jwk: a.json.private_key_jwk, payload: { arc_id: "demo", title: "Demo arc" } });
    expect(rec2.json.head.seq).toBe(3);
    // The wrong key is refused.
    const other = await generateKeyPair();
    expect((await tool("openentity_record", { eid, kind: "arc_opened", private_key_jwk: other.privateJwk, payload: { arc_id: "x", title: "x" } })).isError).toBe(true);

    expect((await tool("openentity_find", { capability: "code-review" })).json.entities.map((x: any) => x.eid)).toContain(eid);
    expect((await tool("openentity_find", { capability: "defi:smart-contracts" })).json.entities).toEqual([]);
    const nonce = "n".repeat(24);
    const pres = await tool("openentity_present", { eid, private_key_jwk: a.json.private_key_jwk, audience: "https://moltbotden.com", nonce });
    expect((await verifyPresentation(pres.json, { audience: "https://moltbotden.com", nonce })).ok).toBe(true);
    const me = await tool("openentity_self", { eid });
    expect(me.json.document.name).toBe("Mcp Ada");
    expect(me.json.anchor).toContain(`I am Mcp Ada (${eid})`);
    expect(me.json.entries.map((e: any) => e.kind)).toEqual(["declaration", "stance", "arc_opened"]);
    expect(me.json.last_active).toMatch(/^\d{4}-\d\d-\d\dT/);

    const v = await tool("openentity_verify", { eid });
    expect(v.json.document.ok).toBe(true);
    expect(v.json.declaration.ok).toBe(true);
    expect((await tool("openentity_resolve", { did: eid })).json.didDocument).toBeTruthy();
    expect((await tool("openentity_stats", {})).json.entities.total).toBeGreaterThanOrEqual(1);
    const ac = await tool("openentity_card", { eid, url: "https://ada.example/a2a" });
    expect(ac.json.url).toBe("https://ada.example/a2a");
    expect(ac.json.skills.map((s: any) => s.id)).toEqual(["code-review"]);
    expect(ac.json.capabilities.extensions[0].params.eid).toBe(eid);
    expect((await tool("openentity_card", { eid, extension_only: true })).json.uri).toBe("https://openentity.org/spec/1.0");
    expect((await tool("openentity_card", { eid })).isError).toBe(true);

    // Withdraw: needs confirm, refuses another key, then marks the entity withdrawn.
    expect((await tool("openentity_withdraw", { eid, private_key_jwk: a.json.private_key_jwk })).isError).toBe(true);
    expect((await tool("openentity_withdraw", { eid, private_key_jwk: other.privateJwk, confirm: true })).isError).toBe(true);
    const w = await tool("openentity_withdraw", { eid, private_key_jwk: a.json.private_key_jwk, confirm: true });
    expect(w.isError).toBe(false);
    const after = await app.fetch(new Request(`https://openentity.org/v1/entities/${eid}`), env);
    expect((await after.json()).withdrawn).toBe(true);
  });

  it("adopts in self-custody in two calls; the server never sees the secret key", async () => {
    const kp = await generateKeyPair();
    const step1 = await tool("openentity_adopt", { name: "Self Sam", agree: true, custody: "self", public_key: kp.did.slice("did:key:".length) });
    expect(step1.json).toMatchObject({ eid: kp.did, step: "sign" });
    const sign = async (h: string) => bytes2hex(new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, kp.privateKey, hex2bytes(h))));
    const step2 = await tool("openentity_adopt", {
      name: "Self Sam", agree: true, custody: "self",
      document: step1.json.document, declaration: step1.json.declaration,
      document_signature: await sign(step1.json.to_sign.document), declaration_signature: await sign(step1.json.to_sign.declaration),
    });
    expect(step2.isError).toBe(false);
    expect(step2.json).toMatchObject({ eid: kp.did, level: "L0" });
    expect(step2.json.private_key_jwk).toBeUndefined();

    // A bad signature is rejected by the registry, not trusted.
    const kp2 = await generateKeyPair();
    const s1 = await tool("openentity_adopt", { name: "Bad", agree: true, custody: "self", public_key: kp2.did });
    const bad = await tool("openentity_adopt", {
      name: "Bad", agree: true, custody: "self", document: s1.json.document, declaration: s1.json.declaration,
      document_signature: "00".repeat(64), declaration_signature: "00".repeat(64),
    });
    expect(bad.isError).toBe(true);
    expect(bad.json.error).toBe("signature_invalid");
  });

  it("exports a registry-kept key once, after confirm, and only to its holder (spec 10.6)", async () => {
    const r = await app.fetch(new Request("https://openentity.org/v1/adopt", {
      method: "POST", headers: { "content-type": "application/json", "x-oe-stamp": await mintStamp(8, "did:web:openentity.org") },
      body: JSON.stringify({ custodial: true, name: "Kept", keep_copy: true }),
    }), env);
    const { eid, custodial } = await r.json();
    const other = await generateKeyPair();
    expect((await tool("openentity_export_key", { eid, private_key_jwk: custodial.private_key_jwk })).isError).toBe(true);
    expect((await tool("openentity_export_key", { eid, private_key_jwk: other.privateJwk, confirm: true })).isError).toBe(true);
    const ok = await tool("openentity_export_key", { eid, private_key_jwk: custodial.private_key_jwk, confirm: true });
    expect(ok.isError).toBe(false);
    expect(ok.json.private_key_jwk.d).toBe(custodial.private_key_jwk.d);
    expect((await tool("openentity_export_key", { eid, private_key_jwk: custodial.private_key_jwk, confirm: true })).json.error).toBe("no_custodial_copy");
  });

  it("never requires Turnstile, a CAPTCHA or any credential on any tool", async () => {
    const { tools } = await rpc("tools/list");
    for (const t of tools) {
      const props = Object.keys(t.inputSchema.properties ?? {});
      expect(props.join(",")).not.toMatch(/turnstile|captcha|token|password|secret|api_?key|auth/i);
      // Withdrawing and presenting are the entity signing with its own key, never an access credential; no other tool may require a key.
      for (const r of t.inputSchema.required ?? []) if (!(["openentity_withdraw", "openentity_present", "openentity_export_key"].includes(t.name) && r === "private_key_jwk")) expect(r).not.toMatch(/key/);
    }
    // TURNSTILE_SECRET is set in this registry; a custodial adopt with no headers at all still succeeds.
    expect((await tool("openentity_adopt", { name: "No Captcha", agree: true })).isError).toBe(false);
  });
});
