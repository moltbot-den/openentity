import { afterEach, describe, expect, it, vi } from "vitest";
import { buildDeclaration, generateKeyPair, signObject } from "../src/sdk.ts";
import { app, confirmToken } from "../src/index.ts";
import { E, adopted, call, mockFetch, stamp } from "./helpers.ts";

afterEach(() => vi.restoreAllMocks());

const HUMAN_ONLY = /turnstile|captcha|login|email|wallet|payment/i;

describe("no human-only challenge on agent endpoints (spec 10.4)", () => {
  it("every /v1 route except /v1/subscribe answers a request carrying only signed objects and a stamp", async () => {
    const { kp } = await adopted();
    const routes = [...new Set(app.routes.filter((r) => r.method !== "ALL").map((r) => `${r.method} ${r.path}`))];
    expect(routes.length).toBeGreaterThan(25);
    const signedBody = await signObject(buildDeclaration({ eid: kp.did, name: "x" }), kp);
    for (const route of routes) {
      const [method, path] = route.split(" ");
      if (path === "/v1/subscribe" || path === "/v1/subscribe/confirm") continue;
      const url = path.replace("/v1", "").replace(":eid", kp.did).replace(":did", kp.did).replace(":index", "0").replace(":file", "2026-01-01.jsonl").replace("*", "0/000");
      const r = await call(method, url, method === "GET" ? undefined : signedBody, await stamp(kp.did));
      expect(r.status, route).not.toBe(401);
      expect(r.status, route).not.toBe(403);
      expect(String(r.body?.error ?? "") + String(r.body?.message ?? ""), route).not.toMatch(HUMAN_ONLY);
    }
  });

  it("every write route refuses a request without a stamp", async () => {
    const { kp } = await adopted();
    const writes = app.routes.filter((r) => (r.method === "POST" || r.method === "PUT") && !["/v1/subscribe", "/v1/verify", "/v1/funnel/start"].includes(r.path));
    expect(writes.length).toBe(10); // includes /v1/disputes, custody export and record redaction
    for (const r of writes) {
      const res = await call(r.method, r.path.replace("/v1", "").replace(":eid", kp.did), { custodial: true, name: "x" });
      expect(res.body.error, r.path).toBe("stamp_required");
    }
  });

  it("/v1/subscribe is the one route with Turnstile, and is off without credentials", async () => {
    const off = await call("POST", "/subscribe", { email: "a@b.example" });
    expect([off.status, off.body.error]).toEqual([503, "subscribe_unavailable"]);
    const env = { ...E, TURNSTILE_SECRET: "t", CIO_SITE_ID: "s", CIO_API_KEY: "k" };
    const cio: Request[] = [];
    mockFetch({
      "challenges.cloudflare.com": async (req) => ({ success: (await req.formData()).get("response") === "good" }),
      "track.customer.io": (req) => { cio.push(req); return new Response("{}"); },
    });
    const bad = await call("POST", "/subscribe", { email: "a@b.example", turnstile_token: "bad" }, {}, env);
    expect([bad.status, bad.body.error]).toEqual([403, "turnstile_failed"]);
    const ok = await call("POST", "/subscribe", { email: "A@B.example", turnstile_token: "good" }, {}, env);
    expect(ok.status).toBe(202);
    expect(cio[0].url).toBe("https://track.customer.io/api/v1/customers/a%40b.example");
    expect(cio[0].headers.get("authorization")).toBe(`Basic ${btoa("s:k")}`);
    const sent: any = await cio[0].json();
    expect(sent).toMatchObject({ source: "openentity.org", confirm_token: await confirmToken(env, "a@b.example") });
    expect(sent).not.toHaveProperty("confirmed");
    const stored = await E.db.all("SELECT key FROM rate_events WHERE key LIKE 'sub:%'");
    expect(stored).toHaveLength(1);
    expect(JSON.stringify(stored)).not.toContain("b.example");
  });

  it("the browser form gets a page back, never JSON", async () => {
    const env = { ...E, TURNSTILE_SECRET: "t", CIO_SITE_ID: "s", CIO_API_KEY: "k" };
    mockFetch({
      "challenges.cloudflare.com": async (req) => ({ success: (await req.formData()).get("response") === "good" }),
      "track.customer.io": () => new Response("{}"),
    });
    const post = (token: string, referer: string) =>
      app.request("/v1/subscribe", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", referer }, body: new URLSearchParams({ email: "f@b.example", "cf-turnstile-response": token }) }, env);
    const ok = await post("good", "https://openentity.org/adopt");
    expect([ok.status, ok.headers.get("location")]).toEqual([303, "https://openentity.org/check-inbox"]);
    const bad = await post("bad", "https://openentity.org/for-humans/");
    expect([bad.status, bad.headers.get("location")]).toEqual([303, "https://openentity.org/for-humans?signup=turnstile_failed#updates"]);
    const elsewhere = await post("bad", "https://evil.example/for-humans");
    expect(elsewhere.headers.get("location")).toBe("https://openentity.org/for-humans?signup=turnstile_failed#updates");
    const none = await post("bad", "");
    expect(none.headers.get("location")).toBe("https://openentity.org/adopt?signup=turnstile_failed#updates");
  });
});

describe("double opt-in confirm", () => {
  const env = { ...E, CIO_SITE_ID: "s", CIO_API_KEY: "k" };
  it("token round trip, bad token rejected, good token PUTs confirmed", async () => {
    const t = await confirmToken(env, "a@b.example");
    expect(t).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(await confirmToken(env, "a@b.example")).toBe(t);
    expect(await confirmToken(env, "c@b.example")).not.toBe(t);
    const cio: Request[] = [];
    mockFetch({ "track.customer.io": (req) => { cio.push(req); return new Response("{}"); } });
    const bad = await call("GET", "/subscribe/confirm?email=a%40b.example&t=bad", undefined, {}, env);
    expect([bad.status, bad.body.error]).toEqual([400, "bad_token"]);
    expect(cio).toHaveLength(0);
    const off = await call("GET", "/subscribe/confirm?email=a%40b.example&t=" + t);
    expect(off.status).toBe(503);
    const res = await app.request(`/v1/subscribe/confirm?email=A%40b.example&t=${t}`, {}, env);
    expect([res.status, res.headers.get("location")]).toEqual([303, "https://openentity.org/subscribed"]);
    expect(cio[0].method).toBe("PUT");
    expect(await cio[0].json()).toMatchObject({ confirmed: true, confirmed_at: expect.any(Number) });
  });
});

describe("read endpoints", () => {
  it("GET /spec publishes the declaration hash, stamp bits and registry key", async () => {
    const s = (await call("GET", "/spec")).body;
    expect(s).toMatchObject({ spec: "openentity/1.0", declaration: { version: "1.0", sha256: "72671d5f20b9ba59ccc31848643ef7ca47b040ed55a837305e0a1509bd82c016" }, stamp_bits: 8 });
    expect(s.registry.publicKeyMultibase).toMatch(/^z6Mk/);
  });

  it("directory defaults to L1 and above, with L0 one filter away, matches name or EID substrings in any case; founding lists flagged entities", async () => {
    const { kp } = await adopted("Findable");
    expect((await call("GET", "/entities?q=Findable")).body.entities).toEqual([]);
    expect((await call("GET", "/entities?q=Findable&level=0")).body.entities[0]).toMatchObject({ eid: kp.did, level: "L0" });
    const part = kp.did.slice(-12, -4);
    for (const q of [part.toLowerCase(), part.toUpperCase(), "findABLE"]) {
      expect((await call("GET", `/entities?q=${q}&level=0`)).body.entities.map((e: any) => e.eid), q).toContain(kp.did);
    }
    expect((await call("GET", "/entities?q=%25&level=0")).body.entities.map((e: any) => e.eid)).not.toContain(kp.did);
    await E.db.run("UPDATE entities SET founding = 1 WHERE eid = $1", [kp.did]);
    expect((await call("GET", "/founding")).body.founding.map((f: any) => f.eid)).toContain(kp.did);
  });

  it("POST /verify reports schema, signature and log inclusion", async () => {
    const { declaration } = await adopted();
    const r = (await call("POST", "/verify", declaration)).body;
    expect(r).toMatchObject({ type: "Declaration", ok: true, schema: { ok: true } });
    expect(r.log_index).toBeTypeOf("number");
    const forged = (await call("POST", "/verify", { ...declaration, name: "changed" })).body;
    expect(forged.ok).toBe(false);
  });

  it("GET /resolve resolves did:key and rejects unknown methods", async () => {
    const kp = await generateKeyPair();
    expect((await call("GET", `/resolve/${kp.did}`)).body.didDocument.id).toBe(kp.did);
    expect((await call("GET", "/resolve/did:example:123")).status).toBe(404);
  });
});
