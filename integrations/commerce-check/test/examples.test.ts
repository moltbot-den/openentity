// Each example app, driven by a signed agent request, with the hosted check running in-process on a real registry:
// allow (mandate covers the cart), step_up (over step_up_over), deny (no mandate, or an unsigned request).
import type { AddressInfo } from "node:net";
import { createServer } from "node:http";
import { describe, expect, it } from "vitest";
import { agentHeaders, generateKeyPair, hosted, mandateFor } from "./fixture.ts";
import { signRequest } from "@openentity/sdk";

const load = (p: string) => import(p);
const options = { fetch: hosted };

type Send = (path: string, headers: (url: string) => Promise<Record<string, string>>) => Promise<{ status: number; body: any }>;
async function scenarios(send: Send) {
  const kp = await generateKeyPair(), m = mandateFor(kp.did);
  const as = (mandate?: object) => (url: string) => agentHeaders(kp, url, mandate);
  const allow = await send("/buy?total=1000", as(m));
  expect(allow).toMatchObject({ status: 200, body: { bought: true, agent: kp.did } });
  const up = await send("/buy?total=4000", as(m));
  expect(up).toMatchObject({ status: 428, body: { decision: "step_up", reasons: ["step_up_over"], cart: { total: 4000 } } });
  expect(up.body.cart_digest).toMatch(/^[0-9a-f]{64}$/);
  const deny = await send("/buy?total=1000", as());
  expect(deny).toMatchObject({ status: 403, body: { decision: "deny", reasons: ["mandate_required", "owner_unknown"] } });
  expect((await send("/buy?total=1000", async () => ({}))).body.reasons).toEqual(["request_unverified"]);
  for (const r of [allow, up, deny]) expect(r.body.evidence_id).toMatch(/^ev_[a-z2-7]{26}$/);
  // The evidence a merchant keeps is retrievable and intact.
  const ev = await (await hosted(`https://openentity.org/v1/commerce/evidence/${allow.body.evidence_id}`)).json();
  expect(ev).toMatchObject({ decision: "allow", intact: true });
}

describe("example apps", () => {
  it("Express", async () => {
    // The agent signs the public URL; the server sits behind a proxy on localhost, so publicOrigin says what agents signed.
    const server = createServer((await load("../examples/express.mjs")).app({ ...options, publicOrigin: "https://shop.example" })).listen(0);
    try {
      const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
      await scenarios(async (path, headers) => {
        const r = await fetch(base + path, { method: "POST", headers: await headers("https://shop.example" + path) });
        return { status: r.status, body: await r.json() };
      });
      // Without publicOrigin the signed host (shop.example) is not the host this server saw (127.0.0.1): refused, not trusted from the Host header.
      const bare = createServer((await load("../examples/express.mjs")).app(options)).listen(0);
      try {
        const u = `http://127.0.0.1:${(bare.address() as AddressInfo).port}/buy?total=1000`;
        const r = await fetch(u, { method: "POST", headers: await agentHeaders(await generateKeyPair(), u) });
        expect((await r.json()).reasons).toEqual(["request_wrong_audience"]);
      } finally { bare.close(); }
    } finally { server.close(); }
  });

  it("Hono (and Workers)", async () => {
    const a = (await load("../examples/hono.mjs")).app(options);
    await scenarios(async (path, headers) => {
      const url = `https://shop.example${path}`;
      const r = await a.request(url, { method: "POST", headers: await headers(url) });
      return { status: r.status, body: await r.json() };
    });
  });

  it("Next.js route handler", async () => {
    const POST = (await load("../examples/next-route.mjs")).route(options);
    await scenarios(async (path, headers) => {
      const url = `https://shop.example${path}`;
      const r = await POST(new Request(url, { method: "POST", headers: await headers(url) }));
      return { status: r.status, body: await r.json() };
    });
  });

  it("observe mode never blocks, and a check that cannot run fails closed (503) only when enforcing", async () => {
    const kp = await generateKeyPair(), url = "https://shop.example/buy?total=1000";
    const watch = (await load("../examples/hono.mjs")).app({ ...options, enforce: false });
    const r = await watch.request(url, { method: "POST", headers: await agentHeaders(kp, url) });
    expect(r.status).toBe(200); // deny decision logged, purchase not blocked
    const down = { fetch: (async () => new Response("no", { status: 502 })) as typeof fetch };
    const closed = await (await load("../examples/hono.mjs")).app(down).request(url, { method: "POST", headers: await agentHeaders(kp, url) });
    expect(closed.status).toBe(503);
    const open = await (await load("../examples/hono.mjs")).app({ ...down, enforce: false }).request(url, { method: "POST", headers: await agentHeaders(kp, url) });
    expect(open.status).toBe(200);
  });

  it("a signed binary (non-UTF-8) body passes the signature check in every adapter", async () => {
    const kp = await generateKeyPair(), m = mandateFor(kp.did), url = "https://shop.example/buy?total=1000";
    const body = Uint8Array.from([0xff, 0xfe, 0x00, 0x80, 0xc3, 0x28]); // not valid UTF-8
    const signed = { ...(await signRequest({ method: "POST", url, privateKey: kp, did: kp.did, body })), "OE-Mandate": (await agentHeaders(kp, url, m))["OE-Mandate"], "content-type": "application/octet-stream" };
    const hono = (await load("../examples/hono.mjs")).app(options);
    expect((await hono.request(url, { method: "POST", headers: signed, body })).status).toBe(200);
    const kp2 = await generateKeyPair(), m2 = mandateFor(kp2.did);
    const signed2 = { ...(await signRequest({ method: "POST", url, privateKey: kp2, did: kp2.did, body })), "OE-Mandate": (await agentHeaders(kp2, url, m2))["OE-Mandate"], "content-type": "application/octet-stream" };
    const POST = (await load("../examples/next-route.mjs")).route(options);
    expect((await POST(new Request(url, { method: "POST", headers: signed2, body }))).status).toBe(200);
  });
});
