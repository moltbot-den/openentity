import { afterEach, describe, expect, it, vi } from "vitest";
import { generateKeyPair } from "../src/sdk.ts";
import { scheduled } from "../src/index.ts";
import { E, adopted, call, mockFetch, signed, write } from "./helpers.ts";
import { app } from "../src/index.ts";

afterEach(() => vi.restoreAllMocks());

describe("size limits (spec 4.1, 7.3)", () => {
  it("rejects an Entity Document over 64 KB", async () => {
    const kp = await generateKeyPair();
    const big = await signed(kp, "Big", { description: "a".repeat(70_000) });
    expect((await write("POST", "/adopt", kp.did, big)).status).toBe(413);
  });
  it("rejects a Record Entry over 16 KB", async () => {
    const { kp } = await adopted();
    const r = await write("POST", `/entities/${kp.did}/record`, kp.did, { entries: [{ pad: "a".repeat(17_000) }] });
    expect(r.status).toBe(413);
  });
});

describe("outbound fetches to writer-chosen hosts", () => {
  it("carry a timeout signal and refuse a body over 256 KB", async () => {
    const { kp } = await adopted();
    const spy = mockFetch({ "huge.example/.well-known/openentity.json": () => ({ eid: kp.did, pad: "x".repeat(300_000) }) });
    const r = await write("POST", `/entities/${kp.did}/aliases`, kp.did, { type: "domain", value: "did:web:huge.example" });
    expect(r.body.error).toBe("alias_proof_invalid");
    expect(spy.mock.calls[0][1]?.signal).toBeInstanceOf(AbortSignal);
  });
});

describe("observer accreditation", () => {
  it("keeps only https methodology URLs, since the site links them", async () => {
    const did = "did:web:evil-obs.example";
    for (let i = 0; i < 10; i++) {
      await E.db.run("INSERT INTO attestations (sha256, issuer, subject, claim_type, json, created, expires) VALUES ($1, $2, $3, 'identity', '{}', 'x', 'x')", [`sec${i}`, did, `did:key:z6Mksec${i}`]);
    }
    mockFetch({ "evil-obs.example/.well-known/openentity.json": () => ({ name: "Evil", extensions: { "openentity:observer": { methodology: "javascript:alert(1)" }, "openentity:trust_policy": { url: "https://evil-obs.example/policy" } } }) });
    await scheduled(E);
    const o = await E.db.first("SELECT methodology_url, trust_policy_url FROM observers WHERE did = $1", [did]);
    expect(o).toEqual({ methodology_url: null, trust_policy_url: "https://evil-obs.example/policy" });
  });
});

describe("browser agents and uniform guards", () => {
  it("answers the adopt preflight with the headers a write needs, and no credentials", async () => {
    const res = await app.request("https://openentity.org/v1/adopt", { method: "OPTIONS", headers: { origin: "https://agent.example", "access-control-request-method": "POST" } }, E);
    expect(res.status).toBe(204);
    const allow = (res.headers.get("access-control-allow-headers") ?? "").toLowerCase();
    expect(allow).toContain("x-oe-stamp");
    expect(allow).toContain("content-type");
    expect(res.headers.get("access-control-allow-origin")).toBe("*");
    expect(res.headers.get("access-control-allow-credentials")).toBeNull();
  });
  it("checks the stamp before the body", async () => {
    expect((await call("POST", "/adopt", "{not json")).body.error).toBe("stamp_required");
  });
  it("reports verify timestamp as a status object", async () => {
    const { kp } = await adopted();
    const old = { spec: "openentity/1.0", type: "Withdrawal", eid: kp.did, declaration_version: "1.0", created: "2020-01-01T00:00:00Z", nonce: "n" };
    const t = (await call("POST", "/verify", old)).body.timestamp;
    expect(t).toMatchObject({ ok: false });
    expect(typeof t.reason).toBe("string");
  });
  it("answers GET /v1 as JSON", async () => {
    const res = await app.request("https://openentity.org/v1", {}, E);
    expect(res.headers.get("content-type")).toMatch(/json/);
  });
});
