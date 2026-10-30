import { afterEach, describe, expect, it, vi } from "vitest";
import { app, scheduled } from "../src/index.ts";
import { generateKeyPair, signObject } from "../src/sdk.ts";
import { E, adopted, call, mockFetch, nowSeconds, write } from "./helpers.ts";

afterEach(() => vi.unstubAllGlobals());

describe("stale levels", () => {
  it("the scheduled run re-levels an entity that has attestations but no verified alias", async () => {
    const { kp } = await adopted("Expired");
    await E.db.run("INSERT INTO attestations (sha256, issuer, subject, claim_type, json, created, expires) VALUES ('exp1', 'did:key:i', $1, 'identity', '{}', '2020-01-01T00:00:00Z', '2020-02-01T00:00:00Z')", [kp.did]);
    await E.db.run("UPDATE entities SET level = 2, level_label = 'L2' WHERE eid = $1", [kp.did]);
    await scheduled(E);
    expect((await call("GET", `/entities/${kp.did}`)).body.level).toBe("L0");
  });
});

describe("subscribe failure modes", () => {
  const env = { ...E, TURNSTILE_SECRET: "t", CIO_SITE_ID: "s", CIO_API_KEY: "k" };
  const post = (body: string, ct: string) => app.request("/v1/subscribe", { method: "POST", headers: { "content-type": ct }, body }, env);
  it("a null body, a bad content type and a bad form answer 4xx, not 500", async () => {
    expect((await post("null", "application/json")).status).toBe(400);
    expect((await post("hello", "text/plain")).headers.get("location")).toContain("signup=bad_json");
    expect((await post("x", "multipart/form-data")).headers.get("location")).toContain("signup=bad_json");
  });
  it("Turnstile or Customer.io down answers 502 subscribe_failed, and the browser path redirects", async () => {
    mockFetch({ "challenges.cloudflare.com": () => { throw new Error("down"); } });
    const down = await call("POST", "/subscribe", { email: "a@b.example", turnstile_token: "good" }, {}, env);
    expect([down.status, down.body.error]).toEqual([502, "subscribe_failed"]);
    mockFetch({ "challenges.cloudflare.com": () => ({ success: true }), "track.customer.io": () => { throw new Error("down"); } });
    const cio = await call("POST", "/subscribe", { email: "b@b.example", turnstile_token: "good" }, {}, env);
    expect([cio.status, cio.body.error]).toEqual([502, "subscribe_failed"]);
    const form = await app.request("/v1/subscribe", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ email: "c@b.example", "cf-turnstile-response": "good" }) }, env);
    expect([form.status, form.headers.get("location")]).toEqual([303, "https://openentity.org/adopt?signup=subscribe_failed#updates"]);
  });
});

describe("GET /entities bounds", () => {
  it("caps q and page", async () => {
    expect((await call("GET", `/entities?q=${"a".repeat(101)}`)).body.error).toBe("bad_query");
    expect((await call("GET", "/entities?page=2001")).body.error).toBe("bad_offset");
    expect((await call("GET", "/entities?page=2000")).status).toBe(200);
  });
});

describe("attestation without expires", () => {
  it("is refused, never defaulted", async () => {
    const { kp } = await adopted();
    const obs = await generateKeyPair();
    const a = await signObject({ spec: "openentity/1.0", type: "Attestation", issuer: obs.did, subject: kp.did, claim_type: "capability", claim: { capability: "x", evidence_ref: "y" }, created: nowSeconds() } as any, obs);
    const r = await write("POST", "/attestations", obs.did, a);
    expect(r.status).toBeGreaterThanOrEqual(400);
    expect(await E.db.all("SELECT 1 FROM attestations WHERE subject = $1", [kp.did])).toHaveLength(0);
  });
});
